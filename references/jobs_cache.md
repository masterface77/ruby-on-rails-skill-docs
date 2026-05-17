# Background Jobs, Cache e Action Cable

## TABELA DE CONTEÚDO
1. [Sidekiq com Segurança](#sidekiq)
2. [Redis Cache Patterns](#cache)
3. [Action Cable (WebSocket)](#cable)

---

## 1. Sidekiq com Segurança {#sidekiq}

```ruby
# config/initializers/sidekiq.rb
Sidekiq.configure_server do |config|
  config.redis = {
    url:      ENV.fetch("REDIS_URL"),
    ssl_params: { verify_mode: OpenSSL::SSL::VERIFY_PEER },  # TLS obrigatório
    password: ENV.fetch("REDIS_PASSWORD", nil),
    db:       1  # DB separado do cache (facilita flush seletivo)
  }

  # SEGURANÇA: Middlewares do servidor
  config.server_middleware do |chain|
    chain.add SidekiqMiddleware::SecurityContext  # Injeta contexto de segurança
    chain.add SidekiqMiddleware::RateLimit        # Rate limit por job type
  end
end

Sidekiq.configure_client do |config|
  config.redis = { url: ENV.fetch("REDIS_URL") }
end

# config/sidekiq.yml
# Filas com prioridade — crítico > padrão > baixo
:queues:
  - [critical, 10]  # Pagamentos, segurança
  - [default,  5]   # Jobs normais
  - [mailers,  3]   # Emails
  - [low,      1]   # Relatórios, exports

:concurrency: 10
:max_retries: 3
:dead_max_jobs: 1000


# app/jobs/application_job.rb
class ApplicationJob < ActiveJob::Base
  # SEGURANÇA: Idempotência obrigatória em todos os jobs
  # Jobs podem ser executados mais de uma vez (retry, at-least-once delivery)

  queue_as :default

  # Retry com backoff exponencial (não sobrecarrega serviços em falha)
  retry_on StandardError, wait: :polynomially_longer, attempts: 3

  # Descarta job após 3 falhas (evita acúmulo infinito)
  discard_on ActiveJob::DeserializationError

  before_perform :log_start
  after_perform  :log_end
  rescue_from(Exception, with: :handle_exception)

  private

  def log_start
    Rails.logger.info("[JOB] #{self.class.name} started | jid=#{job_id}")
  end

  def log_end
    Rails.logger.info("[JOB] #{self.class.name} completed | jid=#{job_id}")
  end

  def handle_exception(error)
    Rails.logger.error("[JOB] #{self.class.name} failed: #{error.message} | jid=#{job_id}")
    Sentry.capture_exception(error, tags: { job: self.class.name }) if defined?(Sentry)
    raise  # Re-raise para que o retry funcione
  end
end

# app/jobs/send_email_job.rb
class SendEmailJob < ApplicationJob
  queue_as :mailers

  # SEGURANÇA: Nunca serializa objetos ActiveRecord no payload do job
  # Objetos podem mudar ou ser deletados antes do job executar
  # Passe apenas IDs — busque o objeto dentro do job
  def perform(user_id:, email_type:, payload: {})
    # Busca objeto fresco do banco — não confia em objetos serializados
    user = User.active.find_by(id: user_id)

    # SEGURANÇA: Verifica se recurso ainda existe e está válido
    unless user
      Rails.logger.warn("[SendEmailJob] User #{user_id} não encontrado — descartando")
      return  # Descarta silenciosamente — não é erro
    end

    unless user.email_verified?
      Rails.logger.warn("[SendEmailJob] User #{user_id} sem e-mail verificado — descartando")
      return
    end

    # Idempotência: verifica se e-mail já foi enviado (evita duplicatas em retry)
    cache_key = "email_sent:#{user_id}:#{email_type}:#{payload[:idempotency_key]}"
    if Rails.cache.exist?(cache_key)
      Rails.logger.info("[SendEmailJob] E-mail já enviado para #{user_id} — skip")
      return
    end

    case email_type
    when "welcome"        then UserMailer.welcome(user).deliver_now
    when "password_reset" then UserMailer.password_reset(user, payload[:token]).deliver_now
    when "notification"   then UserMailer.notification(user, payload).deliver_now
    else
      raise ArgumentError, "Tipo de e-mail desconhecido: #{email_type}"
    end

    # Marca como enviado com TTL de 24h
    Rails.cache.write(cache_key, true, expires_in: 24.hours)
  end
end
```

---

## 2. Cache Patterns Seguros {#cache}

```ruby
# app/services/cache_service.rb

# ============================================================
# ESTRATÉGIA DE CACHE — Russian Doll Caching + Fragment Cache
# ============================================================

# config/environments/production.rb
config.cache_store = :redis_cache_store, {
  url:            ENV.fetch("REDIS_CACHE_URL"),
  password:       ENV.fetch("REDIS_PASSWORD", nil),
  ssl_params:     { verify_mode: OpenSSL::SSL::VERIFY_PEER },
  expires_in:     1.hour,          # TTL padrão
  namespace:      "#{Rails.env}",  # Separação por ambiente
  compress:       true,            # Comprime valores grandes
  pool_size:      10,
  pool_timeout:   5,
  error_handler:  ->(method:, returning:, exception:) {
    # Cache miss em falha de Redis — não quebra a aplicação
    Sentry.capture_exception(exception, tags: { cache_method: method })
    Rails.logger.error("Redis cache error: #{exception.message}")
  }
}

module CacheService
  # Cache com invalidação automática por versão do objeto
  def self.fetch_for(record, key_suffix: "", expires_in: 1.hour, &block)
    # Cache key inclui updated_at — invalida automaticamente quando objeto muda
    cache_key = "#{record.class.name.underscore}:#{record.id}:#{record.updated_at.to_i}:#{key_suffix}"

    Rails.cache.fetch(cache_key, expires_in: expires_in, &block)
  end

  # Cache de query frequente — evita consultas repetitivas
  def self.cached_query(key:, expires_in: 5.minutes, &block)
    Rails.cache.fetch("query:#{key}", expires_in: expires_in, &block)
  end

  # SEGURANÇA: Invalidação em cascata quando relacionamento muda
  def self.invalidate_user_cache(user_id)
    # Padrão de chaves do usuário
    Rails.cache.delete_matched("user:#{user_id}:*")
    Rails.cache.delete_matched("user_posts:#{user_id}:*")
  end

  # Counter atômico — thread-safe para métricas em tempo real
  def self.increment_counter(key:, expires_in: 1.day)
    full_key = "counter:#{key}"
    Rails.cache.increment(full_key, 1, expires_in: expires_in) || 1
  end
end

# Uso em controller:
def show
  @post = CacheService.fetch_for(@post, key_suffix: "show", expires_in: 30.minutes) do
    PostSerializer.new(@post).serializable_hash
  end

  render json: @post
end
```

---

## 3. Action Cable (WebSocket Seguro) {#cable}

```ruby
# app/channels/application_cable/connection.rb
module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :current_user

    def connect
      # SEGURANÇA: Autentica conexão WebSocket via token
      # Token passado como query param ou cookie
      self.current_user = find_verified_user
    end

    def disconnect
      # Log de desconexão para auditoria
      Rails.logger.info("[Cable] User #{current_user&.id} disconnected")
    end

    private

    def find_verified_user
      # Opção 1: Token no query string
      token = request.params[:token]

      # Opção 2: Cookie HttpOnly (mais seguro)
      token ||= request.cookie_jar.signed["auth_token"]

      return reject_unauthorized_connection unless token

      payload = JwtService.decode(token)
      return reject_unauthorized_connection unless payload

      user = User.active.find_by(id: payload["user_id"])
      return reject_unauthorized_connection unless user

      user
    rescue => e
      Rails.logger.warn("[Cable] Connection rejected: #{e.message}")
      reject_unauthorized_connection
    end
  end
end

# app/channels/notification_channel.rb
class NotificationChannel < ApplicationCable::Channel
  def subscribed
    # SEGURANÇA: Cada usuário só assina seu próprio stream
    # Nunca: stream_from "notifications_#{params[:user_id]}"  (qualquer user_id!)
    # Sempre: usa current_user (autenticado na conexão)
    stream_for current_user

    Rails.logger.info("[Cable] User #{current_user.id} subscribed to notifications")
  end

  def unsubscribed
    stop_all_streams
  end

  # Ação que o cliente pode invocar
  def mark_as_read(data)
    # SEGURANÇA: Valida e autoriza cada ação recebida
    notification_id = data["notification_id"]

    notification = current_user.notifications.find_by(id: notification_id)
    return unless notification  # Silenciosamente ignora se não pertence ao usuário

    notification.update!(read_at: Time.current)

    # Confirma para o cliente
    transmit({ type: "marked_read", id: notification_id })
  end
end

# Enviar notificação para usuário específico (de qualquer lugar da app):
NotificationChannel.broadcast_to(
  user,
  {
    type:    "new_notification",
    id:      notification.id,
    title:   notification.title,
    body:    notification.body,
    created_at: notification.created_at.iso8601
  }
)
```
