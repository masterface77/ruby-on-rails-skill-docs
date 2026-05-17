# Algoritmos e Design Patterns em Ruby on Rails

## TABELA DE CONTEÚDO
1. [Service Objects](#service_objects)
2. [Interactor Pattern](#interactors)
3. [Decorator Pattern](#decorators)
4. [Strategy Pattern](#strategy)
5. [Observer / Hooks](#observers)
6. [Algoritmos Úteis](#algorithms)

---

## 1. Service Objects {#service_objects}

```ruby
# app/services/application_service.rb
# Base class para todos os Service Objects

class ApplicationService
  # Interface pública padrão: sempre .call
  # Isso garante consistência e testabilidade
  def self.call(...)
    new(...).call
  end

  # Resultado tipado — sempre retorna Success ou Failure
  # Evita nil checks espalhados pelo código
  Result = Struct.new(:success, :value, :errors, keyword_init: true) do
    def success? = success
    def failure? = !success
    def error    = errors&.first
  end

  private

  def success(value = nil)
    Result.new(success: true, value: value, errors: [])
  end

  def failure(*errors)
    Result.new(success: false, value: nil, errors: errors.flatten)
  end
end

# app/services/users/register_service.rb
module Users
  class RegisterService < ApplicationService
    def initialize(params:, ip_address:)
      @params     = params
      @ip_address = ip_address
    end

    def call
      # Validação de negócio (além das validações do modelo)
      return failure("Domínio de e-mail bloqueado") if blocked_email_domain?
      return failure("Limite de contas por IP atingido") if ip_limit_reached?

      user = nil

      # Transação garante atomicidade de todo o processo de registro
      ActiveRecord::Base.transaction do
        user = User.create!(@params.slice(:email, :username, :password, :password_confirmation))

        # Gera token de verificação de e-mail
        verification_token = user.generate_email_verification_token!

        # Envia e-mail de verificação (fora da transação para não bloquear)
        UserMailer.verification_email(user, verification_token).deliver_later
      end

      # Log de auditoria
      AuditLog.log(action: "user.registered",
                   metadata: { email_domain: user.email.split("@").last })

      success(user)

    rescue ActiveRecord::RecordInvalid => e
      failure(e.record.errors.full_messages)
    rescue => e
      Rails.logger.error("RegisterService error: #{e.message}")
      Sentry.capture_exception(e) if defined?(Sentry)
      failure("Erro ao criar conta. Tente novamente.")
    end

    private

    def blocked_email_domain?
      domain = @params[:email]&.split("@")&.last&.downcase
      BlockedEmailDomain.exists?(domain: domain)
    end

    def ip_limit_reached?
      # Máximo 3 contas por IP nas últimas 24h (previne cadastros em massa)
      User.where(registration_ip: @ip_address)
          .where(created_at: 24.hours.ago..)
          .count >= 3
    end
  end
end

# Uso no controller — limpo e testável
class RegistrationsController < ApplicationController
  skip_before_action :authenticate_user!

  def create
    result = Users::RegisterService.call(
      params:     registration_params,
      ip_address: request.remote_ip
    )

    if result.success?
      render json: { message: "Conta criada! Verifique seu e-mail." },
             status: :created
    else
      render json: { errors: result.errors }, status: :unprocessable_entity
    end
  end
end
```

---

## 2. Interactor Pattern {#interactors}

```ruby
# Interactors = Service Objects com contexto compartilhado e rollback automático
# Gem: interactor-rails

# app/interactors/place_order.rb
class PlaceOrder
  include Interactor::Organizer

  # Pipeline: cada passo pode falhar e o anterior será revertido
  organize ValidateCart,
           ReserveStock,
           ProcessPayment,
           CreateOrder,
           SendConfirmationEmail
end

# app/interactors/validate_cart.rb
class ValidateCart
  include Interactor

  def call
    cart = context.cart

    if cart.items.empty?
      # context.fail! interrompe o pipeline e chama rollback de todos anteriores
      context.fail!(error: "Carrinho vazio")
    end

    if cart.items.any? { |item| !item.product.available? }
      context.fail!(error: "Produto indisponível")
    end

    # Passa dados para o próximo interactor via context
    context.total = cart.calculate_total
  end
end

# app/interactors/process_payment.rb
class ProcessPayment
  include Interactor

  def call
    payment = PaymentGateway.charge(
      amount: context.total,
      token:  context.payment_token,
      user:   context.user
    )

    if payment.declined?
      context.fail!(error: "Pagamento recusado: #{payment.decline_reason}")
    end

    context.payment = payment
  end

  # Rollback automático se passo posterior falhar
  def rollback
    context.payment&.refund!
    Rails.logger.info("Payment rolled back: #{context.payment&.id}")
  end
end

# Uso:
result = PlaceOrder.call(
  cart:          current_user.cart,
  payment_token: params[:payment_token],
  user:          current_user
)

if result.success?
  render json: { order_id: result.order.id }
else
  render json: { error: result.error }, status: :unprocessable_entity
end
```

---

## 3. Decorator Pattern {#decorators}

```ruby
# app/decorators/user_decorator.rb
# Draper gem ou SimpleDelegator puro

class UserDecorator < SimpleDelegator
  # Formata dados para apresentação SEM poluir o modelo
  # O modelo tem apenas lógica de negócio — o decorator tem lógica de display

  def full_name
    "#{first_name} #{last_name}".strip.presence || email
  end

  def avatar_url
    if avatar.attached?
      avatar.variant(resize_to_limit: [200, 200]).processed.url
    else
      # Avatar gerado por inicial — sem dependência externa
      "https://ui-avatars.com/api/?name=#{CGI.escape(full_name)}&size=200&background=random"
    end
  end

  def role_badge
    {
      guest:     { label: "Visitante",    color: "gray"   },
      user:      { label: "Usuário",      color: "blue"   },
      moderator: { label: "Moderador",    color: "yellow" },
      admin:     { label: "Admin",        color: "red"    },
      superuser: { label: "Super Admin",  color: "purple" }
    }[role.to_sym]
  end

  def member_since
    created_at.strftime("%B de %Y")  # "Janeiro de 2024"
  end

  def masked_email
    # LGPD: mascara e-mail em logs e interfaces — "jo***@gmail.com"
    parts = email.split("@")
    "#{parts[0][0..1]}***@#{parts[1]}"
  end

  # Serialização segura — define explicitamente o que é público
  def public_json
    {
      id:          id.to_s,  # UUID como string
      username:    username,
      avatar_url:  avatar_url,
      member_since: member_since,
      role:        role_badge
      # email NÃO incluído — privado por padrão
    }
  end
end

# Uso:
user = UserDecorator.new(current_user)
render json: user.public_json
```

---

## 4. Strategy Pattern {#strategy}

```ruby
# Algoritmo de notificação — diferentes canais, mesma interface

# app/strategies/notifications/base_strategy.rb
module Notifications
  class BaseStrategy
    def initialize(user:, payload:)
      @user    = user
      @payload = payload
    end

    # Toda estratégia deve implementar #deliver!
    def deliver!
      raise NotImplementedError, "#{self.class}#deliver! não implementado"
    end

    def available?
      raise NotImplementedError
    end
  end
end

# app/strategies/notifications/email_strategy.rb
module Notifications
  class EmailStrategy < BaseStrategy
    def available?
      @user.email_verified? && @user.notification_email?
    end

    def deliver!
      NotificationMailer
        .with(user: @user, payload: @payload)
        .notification_email
        .deliver_later(queue: "notifications")
    end
  end
end

# app/strategies/notifications/push_strategy.rb
module Notifications
  class PushStrategy < BaseStrategy
    def available?
      @user.push_tokens.active.any? && @user.notification_push?
    end

    def deliver!
      @user.push_tokens.active.each do |token|
        PushNotificationJob.perform_later(
          token:   token.value,
          title:   @payload[:title],
          body:    @payload[:body],
          data:    @payload[:data]
        )
      end
    end
  end
end

# app/services/notification_service.rb — orquestra as estratégias
class NotificationService < ApplicationService
  STRATEGIES = [
    Notifications::PushStrategy,
    Notifications::EmailStrategy,
    Notifications::SmsStrategy
  ].freeze

  def initialize(user:, event:, payload:)
    @user    = user
    @event   = event
    @payload = payload
  end

  def call
    delivered = []

    STRATEGIES.each do |strategy_class|
      strategy = strategy_class.new(user: @user, payload: @payload)
      next unless strategy.available?

      strategy.deliver!
      delivered << strategy_class.name
    rescue => e
      # Falha em um canal não impede os outros
      Rails.logger.error("Notification strategy #{strategy_class} failed: #{e.message}")
    end

    success(delivered)
  end
end
```

---

## 5. Algoritmos Úteis {#algorithms}

```ruby
# ============================================================
# PAGINAÇÃO COM CURSOR (mais eficiente que OFFSET para grandes tabelas)
# ============================================================

class CursorPaginator
  DEFAULT_LIMIT = 25
  MAX_LIMIT     = 100

  def initialize(scope, limit: DEFAULT_LIMIT, cursor: nil, direction: :after)
    @scope     = scope
    @limit     = [[limit.to_i, 1].max, MAX_LIMIT].min
    @cursor    = cursor
    @direction = direction
  end

  def results
    @results ||= begin
      query = @scope
      query = apply_cursor(query) if @cursor.present?
      query.limit(@limit + 1)  # Busca 1 a mais para saber se há próxima página
    end
  end

  def has_next_page?
    results.size > @limit
  end

  def records
    results.first(@limit)
  end

  def next_cursor
    return nil unless has_next_page?
    # Cursor baseado em campo único e ordenado (created_at + id para desempate)
    last = records.last
    Base64.urlsafe_encode64("#{last.created_at.to_f}:#{last.id}", padding: false)
  end

  private

  def apply_cursor(query)
    decoded    = Base64.urlsafe_decode64(@cursor)
    ts, id     = decoded.split(":")
    timestamp  = Time.at(ts.to_f)

    query.where(
      "(created_at, id) < (?, ?)",  # Tupla comparison — eficiente com índice composto
      timestamp, id
    )
  end
end

# Uso:
paginator = CursorPaginator.new(
  Post.published.order(created_at: :desc, id: :desc),
  limit: params[:limit],
  cursor: params[:cursor]
)

render json: {
  data:        PostSerializer.new(paginator.records),
  next_cursor: paginator.next_cursor,
  has_more:    paginator.has_next_page?
}

# ============================================================
# SLUG ÚNICO E SEGURO
# ============================================================

module Sluggable
  extend ActiveSupport::Concern

  included do
    before_validation :generate_slug, on: :create
    validates :slug, uniqueness: true, format: { with: /\A[a-z0-9\-]+\z/ }
  end

  private

  def generate_slug
    return if slug.present?

    base_slug  = slugify(sluggable_field)
    self.slug  = unique_slug(base_slug)
  end

  def slugify(str)
    str.to_s
       .unicode_normalize(:nfkd)       # Decompõe caracteres acentuados
       .encode("ASCII", replace: "")   # Remove caracteres não-ASCII
       .downcase
       .gsub(/[^a-z0-9\s]/, "")        # Remove pontuação
       .gsub(/\s+/, "-")               # Espaço → hífen
       .squeeze("-")                   # Múltiplos hífens → um
       .first(100)                     # Limita tamanho
       .chomp("-")                     # Remove hífen no final
  end

  def unique_slug(base)
    candidate = base
    counter   = 1

    # Verifica unicidade e adiciona sufixo se necessário
    while self.class.exists?(slug: candidate)
      candidate = "#{base}-#{counter}"
      counter  += 1
      raise "Não foi possível gerar slug único" if counter > 100
    end

    candidate
  end
end
```
