---
name: ruby-on-rails
description: >
  Skill especializada em Ruby on Rails com segurança avançada linha a linha, lógica de programação
  completa, algoritmos, padrões de arquitetura, API REST/GraphQL, autenticação, autorização, criptografia,
  prevenção de ataques (SQLi, XSS, CSRF, IDOR, Mass Assignment, RCE), testes automatizados, performance,
  background jobs e deploy seguro. Use SEMPRE que o usuário mencionar Rails, Ruby, ActiveRecord, Devise,
  API Rails, backend Ruby, MVC Ruby, RSpec, Sidekiq, Action Cable, Hotwire ou qualquer tarefa relacionada
  a desenvolvimento backend com Ruby on Rails — mesmo que não mencione a palavra "skill".
compatibility:
  ruby: ">=3.2"
  rails: ">=7.1"
  tools: [bash, ruby, bundler, postgres, redis]
---

# Ruby on Rails — Skill Completa de Segurança e Programação

## ÍNDICE DE REFERÊNCIAS

> Para tarefas específicas, leia o arquivo de referência correspondente:

| Tópico | Arquivo | Quando ler |
|--------|---------|-----------|
| Segurança avançada (OWASP Top 10) | `references/security.md` | Autenticação, autorização, criptografia, ataques |
| ActiveRecord & SQL seguro | `references/activerecord.md` | Queries, migrations, validações, N+1 |
| API REST & GraphQL | `references/api.md` | Endpoints, serialização, rate limiting, versionamento |
| Algoritmos & Design Patterns | `references/algorithms.md` | Service Objects, Interactors, Decorators, Strategy |
| Background Jobs & Cache | `references/jobs_cache.md` | Sidekiq, Redis, Action Cable, caching |
| Testes (RSpec, FactoryBot) | `references/testing.md` | Unit, integration, request specs |
| Deploy & Infraestrutura | `references/deploy.md` | Docker, CI/CD, secrets, SSL/TLS |

---

## PRINCÍPIOS FUNDAMENTAIS DE SEGURANÇA RAILS

### 1. Configuração Base Segura (config/application.rb)

```ruby
# config/application.rb
module MyApp
  class Application < Rails::Application
    # SEGURANÇA: Força encoding UTF-8 em toda a aplicação
    # Previne ataques de encoding (UTF-7, Latin-1 injection)
    config.encoding = "utf-8"

    # SEGURANÇA: Filtra parâmetros sensíveis dos logs
    # Nunca loga senhas, tokens, cartões de crédito
    config.filter_parameters += [
      :password, :password_confirmation,
      :secret, :token, :api_key, :credit_card,
      :cvv, :ssn, :otp, :pin
    ]

    # SEGURANÇA: Habilita proteção CSRF (Cross-Site Request Forgery)
    # Gera e valida token único por sessão
    config.action_controller.default_protect_from_forgery = true

    # SEGURANÇA: Cookie SameSite=Strict previne CSRF em browsers modernos
    config.action_dispatch.cookies_same_site_protection = :strict

    # SEGURANÇA: Força HTTPS em produção via HSTS
    # max-age=31536000 = 1 ano; includeSubDomains protege subdomínios
    config.force_ssl = Rails.env.production?

    # SEGURANÇA: Chaves secretas via variáveis de ambiente, NUNCA no código
    config.secret_key_base = ENV.fetch("SECRET_KEY_BASE") {
      raise "SECRET_KEY_BASE não definida! Defina a variável de ambiente."
    }

    # SEGURANÇA: Timezone explícito evita vulnerabilidades de comparação de tempo
    config.time_zone = "UTC"
    config.active_record.default_timezone = :utc

    # SEGURANÇA: Desativa exposição de informações de versão
    config.middleware.delete ActionDispatch::DebugExceptions if Rails.env.production?
  end
end
```

---

### 2. Cabeçalhos HTTP de Segurança

```ruby
# config/initializers/security_headers.rb
# SEGURANÇA: Content Security Policy (CSP) previne XSS e injeção de scripts
Rails.application.configure do
  config.content_security_policy do |policy|
    # Bloqueia tudo por padrão — princípio do menor privilégio
    policy.default_src :self

    # Scripts: apenas do próprio domínio + CDN explícito
    # 'unsafe-inline' NUNCA deve ser usado em produção
    policy.script_src  :self, "https://cdn.trusted.com"

    # Estilos inline proibidos — força CSS externo controlado
    policy.style_src   :self, :https

    # Imagens: permite data: para ícones inline pequenos
    policy.img_src     :self, :data, :https

    # Fonts do próprio servidor
    policy.font_src    :self

    # Conexões AJAX/WebSocket: apenas HTTPS
    policy.connect_src :self, :https

    # Frames: bloqueia clickjacking
    policy.frame_ancestors :none

    # Reporta violações (não bloqueia ainda — para monitoramento)
    policy.report_uri  "/csp_reports"
  end

  # SEGURANÇA: Nonce único por request para scripts inline legítimos
  config.content_security_policy_nonce_generator = ->(request) {
    SecureRandom.base64(16)
  }
  config.content_security_policy_nonce_directives = %w[script-src]
end

# config/initializers/secure_headers.rb
module SecurityHeaders
  def self.apply(response)
    headers = response.headers

    # Impede MIME sniffing (ataques de type confusion)
    headers["X-Content-Type-Options"] = "nosniff"

    # Proteção básica XSS para browsers antigos
    headers["X-XSS-Protection"] = "1; mode=block"

    # Clickjacking: impede embedding em iframes externos
    headers["X-Frame-Options"] = "DENY"

    # HSTS: força HTTPS por 1 ano incluindo subdomínios
    if Rails.env.production?
      headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    end

    # Referrer Policy: não vaza URLs internas para sites externos
    headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Permissions Policy: desativa APIs sensíveis do browser
    headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
  end
end
```

---

### 3. Modelo com Validações e Segurança Completa

```ruby
# app/models/user.rb
class User < ApplicationRecord
  # SEGURANÇA: has_secure_password usa bcrypt com salt automático
  # Custo padrão 12 (2^12 iterações) — resistente a brute force
  # Nunca armazene senha em texto plano JAMAIS
  has_secure_password

  # ASSOCIAÇÕES com dependent: :destroy para evitar dados órfãos
  # SEGURANÇA: dados de sessão destruídos quando usuário é deletado
  has_many :sessions,          dependent: :destroy
  has_many :access_tokens,     dependent: :destroy
  has_many :audit_logs,        dependent: :nullify  # preserva auditoria

  # SEGURANÇA: Normalização antes de salvar
  # Evita duplicatas por case ("Admin" vs "admin") e espaços
  before_save :normalize_email
  before_save :normalize_username

  # VALIDAÇÕES — cada regra tem propósito de segurança
  validates :email,
            presence:   true,                    # Campo obrigatório
            uniqueness: { case_sensitive: false }, # Sem duplicatas
            format:     {
              with: URI::MailTo::EMAIL_REGEXP,    # RFC 5322 — evita injeção
              message: "deve ser um e-mail válido"
            },
            length: { maximum: 254 }             # RFC 5321 limite de e-mail

  validates :username,
            presence:   true,
            uniqueness: { case_sensitive: false },
            format:     {
              with: /\A[a-zA-Z0-9_\-]{3,30}\z/,  # Apenas chars seguros
              message: "apenas letras, números, _ e -"
            },
            length: { in: 3..30 }

  validates :password,
            length: { minimum: 12, maximum: 128 }, # Mínimo forte, máximo evita DoS
            format: {
              with: /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/,
              message: "precisa de maiúscula, minúscula, número e caractere especial"
            },
            if: :password_required?

  # SEGURANÇA: Enumeração segura — armazena inteiro no DB, expõe string na app
  # Evita envio de valores arbitrários pelo usuário
  enum :role, {
    guest:     0,
    user:      1,
    moderator: 2,
    admin:     3,
    superuser: 4
  }, prefix: true  # user.role_admin? user.role_user!

  # SEGURANÇA: Soft delete — não apaga dados de auditoria imediatamente
  scope :active,   -> { where(deleted_at: nil) }
  scope :deleted,  -> { where.not(deleted_at: nil) }
  scope :verified, -> { where.not(email_verified_at: nil) }

  # SEGURANÇA: Geração de token criptograficamente seguro
  # SecureRandom.urlsafe_base64 usa /dev/urandom (CSPRNG)
  def generate_reset_token!
    # Token de 32 bytes = 256 bits de entropia — resistente a brute force
    raw_token   = SecureRandom.urlsafe_base64(32)

    # Armazena apenas o HASH do token no banco
    # Se o banco vazar, tokens não são utilizáveis
    self.password_reset_token    = BCrypt::Password.create(raw_token, cost: 10)
    self.password_reset_sent_at  = Time.current

    save!(validate: false)  # Evita re-validar senha ao salvar token

    raw_token  # Retorna o token RAW apenas uma vez, para enviar por email
  end

  # SEGURANÇA: Comparação em tempo constante — previne timing attacks
  # Um atacante não pode descobrir se o token está "quase certo" medindo tempo
  def valid_reset_token?(token)
    return false if password_reset_token.blank?
    return false if password_reset_sent_at < 2.hours.ago  # Token expirado

    # ActiveSupport::SecurityUtils.secure_compare é O(n) constante
    BCrypt::Password.new(password_reset_token) == token
  rescue BCrypt::Errors::InvalidHash
    false  # Token malformado — nega acesso silenciosamente
  end

  private

  def normalize_email
    self.email = email.downcase.strip
  end

  def normalize_username
    self.username = username.strip
  end

  def password_required?
    # Só valida senha se está sendo definida/alterada
    new_record? || password.present?
  end
end
```

---

### 4. Controller Base Seguro

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::API
  # SEGURANÇA: Inclui proteção CSRF mesmo em API mode
  include ActionController::RequestForgeryProtection
  protect_from_forgery with: :exception

  # SEGURANÇA: Aplica cabeçalhos de segurança em toda resposta
  before_action :set_security_headers
  before_action :authenticate_user!
  before_action :check_account_not_locked!

  # SEGURANÇA: Captura erros de autorização e retorna 403 (não 500)
  rescue_from Pundit::NotAuthorizedError,    with: :handle_unauthorized
  rescue_from ActiveRecord::RecordNotFound,  with: :handle_not_found
  rescue_from ActionController::ParameterMissing, with: :handle_bad_request

  private

  # SEGURANÇA: Autenticação JWT com validação completa
  def authenticate_user!
    token = extract_token_from_header

    # SEGURANÇA: Falha explícita sem vazar informação do motivo
    return render_unauthorized unless token

    payload = JwtService.decode(token)
    return render_unauthorized unless payload

    @current_user = User.active.find_by(id: payload["user_id"])
    return render_unauthorized unless @current_user
    return render_unauthorized if @current_user.session_invalidated_at.present? &&
                                   payload["iat"] < @current_user.session_invalidated_at.to_i

    # Registra acesso para auditoria
    log_access_attempt(success: true)
  rescue JWT::ExpiredSignature
    render_unauthorized("Token expirado")
  rescue JWT::DecodeError
    render_unauthorized("Token inválido")
  end

  def extract_token_from_header
    header = request.headers["Authorization"]
    return nil unless header&.start_with?("Bearer ")

    # Remove "Bearer " do início com precisão
    header.split(" ", 2).last&.strip
  end

  def check_account_not_locked!
    return unless @current_user

    if @current_user.locked_at.present?
      render json: { error: "Conta bloqueada. Contate o suporte." }, status: :forbidden
    end
  end

  # SEGURANÇA: Respostas de erro genéricas — não vaza stack trace em produção
  def handle_unauthorized(message = "Não autorizado")
    log_access_attempt(success: false)
    render json: { error: message }, status: :unauthorized
  end

  def handle_not_found
    # Retorna 404 genérico — não confirma se recurso existe (evita IDOR)
    render json: { error: "Recurso não encontrado" }, status: :not_found
  end

  def handle_bad_request(exception)
    render json: { error: "Parâmetro obrigatório ausente: #{exception.param}" },
           status: :bad_request
  end

  def set_security_headers
    SecurityHeaders.apply(response)
  end

  def log_access_attempt(success:)
    AuditLog.create!(
      user_id:    @current_user&.id,
      action:     "api_access",
      success:    success,
      ip_address: anonymize_ip(request.remote_ip),  # LGPD: anonimiza IP
      user_agent: request.user_agent,
      path:       request.path,
      method:     request.method
    )
  end

  # LGPD/GDPR: Mascara último octeto do IP para privacidade
  def anonymize_ip(ip)
    addr = IPAddr.new(ip)
    addr.ipv4? ? "#{ip.split('.')[0..2].join('.')}.0" : addr.mask(48).to_s
  rescue IPAddr::InvalidAddressError
    "invalid"
  end
end
```

---

### 5. Strong Parameters — Barreira contra Mass Assignment

```ruby
# app/controllers/users_controller.rb
class UsersController < ApplicationController
  # SEGURANÇA: Strong Parameters = whitelist explícita
  # Impede Mass Assignment Attack: usuário não pode definir :role, :admin, :id

  def create
    # Parâmetros passam pela "peneira" ANTES de chegar ao model
    @user = User.new(user_create_params)

    if @user.save
      render json: UserSerializer.new(@user), status: :created
    else
      # SEGURANÇA: Retorna erros de validação mas não estrutura interna
      render json: { errors: @user.errors.full_messages }, status: :unprocessable_entity
    end
  end

  def update
    authorize @user  # Pundit verifica se @current_user pode editar @user

    if @user.update(user_update_params)
      render json: UserSerializer.new(@user)
    else
      render json: { errors: @user.errors.full_messages }, status: :unprocessable_entity
    end
  end

  private

  # Criação: aceita campos do cadastro inicial
  def user_create_params
    params.require(:user).permit(
      :email,
      :username,
      :password,
      :password_confirmation
      # :role NÃO permitido — atribuição por regra de negócio, não pelo usuário
      # :admin NÃO permitido
      # :id NÃO permitido
    )
  end

  # Atualização: campos diferentes (sem senha aqui — endpoint separado)
  def user_update_params
    params.require(:user).permit(
      :username,
      :avatar,
      profile_attributes: [:bio, :website, :location]
    )
  end
end
```

---

### 6. Service JWT Completo e Seguro

```ruby
# app/services/jwt_service.rb
class JwtService
  # SEGURANÇA: Algoritmo assimétrico RS256 em produção
  # RS256 = RSA SHA-256: chave privada assina, chave pública verifica
  # Melhor que HS256 (simétrico) pois serviços externos podem verificar sem acesso à chave privada
  ALGORITHM = Rails.env.production? ? "RS256" : "HS256"

  # Tempo de vida curto para access token — limita janela de comprometimento
  ACCESS_TOKEN_TTL  = 15.minutes
  REFRESH_TOKEN_TTL = 7.days

  class << self
    def encode(payload, ttl: ACCESS_TOKEN_TTL)
      now = Time.current.to_i

      claims = payload.merge(
        iat: now,                          # Issued At: quando foi emitido
        nbf: now,                          # Not Before: não válido antes de agora
        exp: (Time.current + ttl).to_i,   # Expiration: expiração
        jti: SecureRandom.uuid,            # JWT ID: único por token (previne replay)
        iss: Rails.application.credentials.jwt_issuer  # Issuer: quem emitiu
      )

      JWT.encode(claims, private_key, ALGORITHM)
    end

    def decode(token)
      options = {
        algorithm: ALGORITHM,
        verify_expiration: true,           # Valida exp
        verify_not_before: true,           # Valida nbf
        verify_iat: true,                  # Valida iat
        iss: Rails.application.credentials.jwt_issuer,
        verify_iss: true,                  # Verifica issuer
        verify_jti: ->(jti) {             # Verifica que token não está na blacklist
          !TokenBlacklist.revoked?(jti)
        }
      }

      decoded = JWT.decode(token, public_key, true, options)
      decoded.first  # Retorna payload (sem header)
    rescue JWT::ExpiredSignature, JWT::DecodeError => e
      Rails.logger.warn("JWT decode failed: #{e.class}")
      nil
    end

    # Revoga token (logout): adiciona JTI na blacklist com TTL igual ao exp
    def revoke!(token)
      payload = JWT.decode(token, public_key, false).first
      ttl     = payload["exp"] - Time.current.to_i
      TokenBlacklist.add(payload["jti"], ttl: ttl) if ttl.positive?
    rescue JWT::DecodeError
      nil  # Token já inválido — sem problema
    end

    private

    def private_key
      if ALGORITHM == "RS256"
        OpenSSL::PKey::RSA.new(ENV.fetch("JWT_PRIVATE_KEY").gsub("\\n", "\n"))
      else
        ENV.fetch("SECRET_KEY_BASE")
      end
    end

    def public_key
      if ALGORITHM == "RS256"
        OpenSSL::PKey::RSA.new(ENV.fetch("JWT_PUBLIC_KEY").gsub("\\n", "\n")).public_key
      else
        ENV.fetch("SECRET_KEY_BASE")
      end
    end
  end
end
```

---

### 7. Rate Limiting e Proteção contra Brute Force

```ruby
# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:create]

  # SEGURANÇA: Rate limiting por IP para login
  # Máximo 5 tentativas a cada 15 minutos por IP
  before_action :check_login_rate_limit!, only: [:create]

  def create
    # SEGURANÇA: Busca por email case-insensitive, normalizado
    user = User.active.verified.find_by(email: params[:email]&.downcase&.strip)

    # SEGURANÇA: Tempo constante mesmo quando usuário não existe
    # Sem isso, atacante descobre e-mails cadastrados medindo tempo de resposta
    if user&.authenticate(params[:password])
      on_successful_login(user)
    else
      on_failed_login(user)
    end
  end

  def destroy
    # Revoga token JWT atual
    JwtService.revoke!(extract_token_from_header)
    render json: { message: "Logout realizado com sucesso" }
  end

  private

  def check_login_rate_limit!
    key   = "login_attempts:#{request.remote_ip}"
    count = Rails.cache.increment(key, 1, expires_in: 15.minutes)

    if count > 5
      # LGPD: loga tentativa suspeita para análise de segurança
      Rails.logger.warn("[SECURITY] Brute force detectado: IP=#{request.remote_ip}")
      render json: { error: "Muitas tentativas. Tente novamente em 15 minutos." },
             status: :too_many_requests
    end
  end

  def on_successful_login(user)
    # Reseta contador de tentativas falhas
    Rails.cache.delete("login_attempts:#{request.remote_ip}")

    # Reseta lock se estava bloqueado
    user.update_columns(
      failed_attempts: 0,
      locked_at:       nil
    )

    access_token  = JwtService.encode({ user_id: user.id })
    refresh_token = JwtService.encode({ user_id: user.id, type: "refresh" },
                                       ttl: JwtService::REFRESH_TOKEN_TTL)

    # Refresh token em cookie HttpOnly — não acessível via JavaScript
    response.set_cookie("refresh_token", {
      value:     refresh_token,
      httponly:  true,               # Protege contra XSS roubando o token
      secure:    Rails.env.production?, # Apenas HTTPS
      same_site: :strict,            # Protege contra CSRF
      expires:   7.days.from_now
    })

    render json: { access_token: access_token }, status: :created
  end

  def on_failed_login(user)
    if user
      # Incrementa falhas e bloqueia após 10 tentativas
      user.increment!(:failed_attempts)
      user.update_column(:locked_at, Time.current) if user.failed_attempts >= 10
    end

    # SEGURANÇA: Mesma mensagem para usuário inválido E senha errada
    # Evita user enumeration (descobrir e-mails cadastrados)
    render json: { error: "E-mail ou senha inválidos" }, status: :unauthorized
  end
end
```

---

### 8. Policy de Autorização (Pundit)

```ruby
# app/policies/application_policy.rb
class ApplicationPolicy
  attr_reader :user, :record

  def initialize(user, record)
    # SEGURANÇA: Lança exceção se não há usuário autenticado
    # Garante que nunca haja autorização sem autenticação
    raise Pundit::NotAuthorizedError, "Usuário não autenticado" unless user

    @user   = user
    @record = record
  end

  # Por padrão: negar tudo — princípio do menor privilégio
  # Sobrescreva explicitamente o que é permitido
  def index?   = false
  def show?    = false
  def create?  = false
  def update?  = false
  def destroy? = false
  def edit?    = update?
  def new?     = create?
end

# app/policies/post_policy.rb
class PostPolicy < ApplicationPolicy
  def index?
    true  # Qualquer autenticado pode listar
  end

  def show?
    # Pode ver se: publicado, OU é o autor, OU é admin
    record.published? || owner? || user.role_admin?
  end

  def create?
    # Pode criar se: email verificado e não está banido
    user.email_verified? && !user.banned?
  end

  def update?
    # Só autor ou moderador/admin podem editar
    owner? || user.role_moderator? || user.role_admin?
  end

  def destroy?
    # Só admin pode deletar (soft delete preserva histórico)
    owner? || user.role_admin?
  end

  # SEGURANÇA: Scope — filtra registros que o usuário pode ver
  # Impede IDOR (Insecure Direct Object Reference) em listagens
  class Scope < ApplicationPolicy::Scope
    def resolve
      if user.role_admin? || user.role_moderator?
        scope.all                            # Admin vê tudo
      else
        scope.published.or(scope.where(author: user))  # User vê públicos + os seus
      end
    end
  end

  private

  def owner?
    record.user_id == user.id
  end
end
```

---

## REGRAS DE OURO DE SEGURANÇA RAILS

### Checklist Obrigatório em Todo Código

```
✅ NUNCA interpoler parâmetros em SQL: User.where("id = #{params[:id]}")  ← PROIBIDO
✅ SEMPRE usar placeholders: User.where(id: params[:id])  ← CORRETO
✅ NUNCA usar eval(), send() ou constantize() com input do usuário
✅ NUNCA armazenar senhas, tokens ou chaves no código-fonte
✅ SEMPRE validar tipo, formato e tamanho de todo input
✅ SEMPRE usar authorize no início de cada action (Pundit)
✅ NUNCA expor ID sequencial — usar UUID ou hashid
✅ SEMPRE sanitizar HTML com Sanitize antes de renderizar
✅ NUNCA confiar em Content-Type do request sem verificar
✅ SEMPRE aplicar HTTPS e HSTS em produção
✅ NUNCA logar dados sensíveis (senhas, tokens, PIX, CPF)
✅ SEMPRE usar prepared statements via ActiveRecord
✅ NUNCA usar Marshal.load com dados externos (RCE vulnerability)
✅ SEMPRE limitar upload de arquivo: tipo, tamanho e nome
✅ NUNCA usar redirect_to com URL fornecida pelo usuário sem whitelist
```

---

## QUANDO LER OS ARQUIVOS DE REFERÊNCIA

- **Precisa fazer query complexa?** → `references/activerecord.md`
- **Precisa criar endpoint de API?** → `references/api.md`
- **Precisa de autenticação OAuth/2FA?** → `references/security.md`
- **Precisa de job em background?** → `references/jobs_cache.md`
- **Precisa escrever testes?** → `references/testing.md`
- **Precisa fazer deploy seguro?** → `references/deploy.md`
- **Precisa implementar algoritmo complexo?** → `references/algorithms.md`
