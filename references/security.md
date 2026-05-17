# Segurança Avançada Ruby on Rails

## TABELA DE CONTEÚDO
1. [OWASP Top 10 em Rails](#owasp)
2. [Criptografia e Hashing](#crypto)
3. [Autenticação OAuth 2.0](#oauth)
4. [Two-Factor Authentication (2FA)](#2fa)
5. [Proteção contra Injeção](#injection)
6. [Upload Seguro de Arquivos](#upload)
7. [Redirecionamentos Seguros](#redirect)
8. [Auditoria e Logging](#audit)

---

## 1. OWASP Top 10 em Rails {#owasp}

### A01 - Broken Access Control

```ruby
# VULNERÁVEL: acessa qualquer post pelo ID
def show
  @post = Post.find(params[:id])  # ← qualquer usuário acessa qualquer post!
end

# SEGURO: scoped ao usuário atual + Pundit
def show
  # policy_scope filtra apenas posts que o user pode ver
  @post = policy_scope(Post).find(params[:id])
  authorize @post  # verifica permissão específica

rescue ActiveRecord::RecordNotFound
  # Retorna 404 genérico — não confirma existência do recurso
  render json: { error: "Não encontrado" }, status: :not_found
end
```

### A02 - Cryptographic Failures

```ruby
# VULNERÁVEL: MD5/SHA1 são quebrados para senhas
user.password_digest = Digest::MD5.hexdigest(password)  # ← NUNCA FAÇA

# SEGURO: BCrypt com custo alto + salt automático
# has_secure_password usa BCrypt com custo 12 por padrão
class User < ApplicationRecord
  has_secure_password validations: true

  # Aumenta custo em produção para maior resistência
  BCrypt::Engine.cost = Rails.env.production? ? 13 : BCrypt::Engine::MIN_COST
end
```

### A03 - Injection

```ruby
# VULNERÁVEL: SQL Injection
User.where("name = '#{params[:name]}'")           # ← PROIBIDO
User.where("role = #{params[:role]}")             # ← PROIBIDO

# SEGURO: Parameterized queries
User.where(name: params[:name])                   # Hash syntax — sempre seguro
User.where("created_at > ?", 1.week.ago)          # Placeholder — seguro
User.where("name LIKE ?", "%#{User.sanitize_sql_like(params[:q])}%")  # LIKE seguro

# VULNERÁVEL: Command Injection
system("convert #{params[:filename]}")            # ← PROIBIDO
`ffmpeg -i #{file_path}`                          # ← PROIBIDO

# SEGURO: Array form isola argumentos do shell
system("convert", params[:filename])              # Array form — args separados
Open3.capture2("ffmpeg", "-i", validated_path)   # Open3 com validação prévia
```

### A07 - Identification and Authentication Failures

```ruby
# Verificação de e-mail obrigatória antes de acesso completo
class EmailVerificationMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    request = ActionDispatch::Request.new(env)
    user    = extract_user(request)

    # Rotas permitidas sem verificação
    allowed = %w[/auth/verify_email /auth/resend_verification /auth/login]

    if user && !user.email_verified? && allowed.none? { |path| request.path.start_with?(path) }
      return [403, { "Content-Type" => "application/json" },
              [{ error: "E-mail não verificado" }.to_json]]
    end

    @app.call(env)
  end
end
```

---

## 2. Criptografia e Hashing {#crypto}

```ruby
# config/initializers/encryption.rb

# SEGURANÇA: Criptografia AES-256-GCM autenticada
# GCM (Galois/Counter Mode) = confidencialidade + integridade
class EncryptionService
  ALGORITHM = "aes-256-gcm"  # Melhor que CBC para APIs (autenticado)

  def self.encrypt(plaintext)
    cipher = OpenSSL::Cipher.new(ALGORITHM)
    cipher.encrypt

    # IV aleatório para cada operação — NUNCA reutilize IV com GCM
    iv  = cipher.random_iv
    key = active_key

    cipher.key = key
    cipher.iv  = iv

    # Additional Authenticated Data — verifica integridade do contexto
    cipher.auth_data = "rails-encryption-v1"

    encrypted = cipher.update(plaintext.to_s) + cipher.final
    auth_tag  = cipher.auth_tag  # Tag de autenticação de 16 bytes

    # Concatena versão + iv + auth_tag + ciphertext em base64
    # Versão permite rotação de chaves sem quebrar dados antigos
    [
      "v1",
      Base64.strict_encode64(iv),
      Base64.strict_encode64(auth_tag),
      Base64.strict_encode64(encrypted)
    ].join(".")
  end

  def self.decrypt(ciphertext_with_iv)
    version, iv_b64, tag_b64, ct_b64 = ciphertext_with_iv.split(".")

    raise "Versão de criptografia inválida" unless version == "v1"

    cipher = OpenSSL::Cipher.new(ALGORITHM)
    cipher.decrypt

    cipher.key      = active_key
    cipher.iv       = Base64.strict_decode64(iv_b64)
    cipher.auth_tag = Base64.strict_decode64(tag_b64)
    cipher.auth_data = "rails-encryption-v1"

    cipher.update(Base64.strict_decode64(ct_b64)) + cipher.final

  rescue OpenSSL::Cipher::CipherError
    # Falha na autenticação: dados adulterados ou chave errada
    raise "Dados corrompidos ou chave inválida"
  end

  # SEGURANÇA: Deriva chave de tamanho correto da secret_key_base
  # HKDF (HMAC-based Key Derivation Function) — RFC 5869
  def self.active_key
    ikm    = Rails.application.credentials.secret_key_base
    salt   = Rails.application.credentials.encryption_salt || "rails-encryption-salt"
    info   = "data-encryption-key-v1"

    OpenSSL::KDF.hkdf(ikm, salt: salt, info: info, length: 32, hash: "SHA256")
  end
end

# Uso em model para campos sensíveis (CPF, cartão, etc.)
class PaymentMethod < ApplicationRecord
  # Criptografa dados sensíveis antes de persistir
  before_save :encrypt_card_number
  after_find  :decrypt_card_number

  private

  def encrypt_card_number
    return if card_number_raw.blank?
    self.card_number_encrypted = EncryptionService.encrypt(card_number_raw)
    self.card_number_raw       = nil  # Não persiste em plaintext
  end

  def decrypt_card_number
    return if card_number_encrypted.blank?
    @card_number = EncryptionService.decrypt(card_number_encrypted)
  end
end
```

---

## 3. OAuth 2.0 Seguro {#oauth}

```ruby
# app/services/oauth_service.rb
class OauthService
  PROVIDERS = {
    google: {
      auth_url:    "https://accounts.google.com/o/oauth2/v2/auth",
      token_url:   "https://oauth2.googleapis.com/token",
      userinfo_url: "https://www.googleapis.com/oauth2/v3/userinfo",
      scopes:      "openid email profile"
    }
  }.freeze

  # SEGURANÇA: Gera state token para prevenir CSRF no OAuth flow
  # State vinculado à sessão do usuário — não pode ser reutilizado
  def self.authorization_url(provider:, redirect_uri:, session:)
    config = PROVIDERS.fetch(provider)

    # State aleatório criptográfico — 256 bits de entropia
    state = SecureRandom.urlsafe_base64(32)

    # PKCE: code_verifier e code_challenge (RFC 7636)
    # Protege contra interceptação do authorization code
    code_verifier  = SecureRandom.urlsafe_base64(43)  # 43 chars = 256 bits
    code_challenge = Base64.urlsafe_encode64(
      OpenSSL::Digest::SHA256.digest(code_verifier),
      padding: false
    )

    # Armazena na sessão — expira em 10 minutos
    session[:oauth_state]         = state
    session[:oauth_code_verifier] = code_verifier
    session[:oauth_state_exp]     = 10.minutes.from_now.to_i

    params = {
      client_id:             ENV.fetch("GOOGLE_CLIENT_ID"),
      redirect_uri:          redirect_uri,
      response_type:         "code",
      scope:                 config[:scopes],
      state:                 state,
      code_challenge:        code_challenge,
      code_challenge_method: "S256",
      access_type:           "offline",  # Para refresh token
      prompt:                "select_account"
    }

    "#{config[:auth_url]}?#{params.to_query}"
  end

  # SEGURANÇA: Troca code por token com todas as verificações
  def self.exchange_code(provider:, code:, state:, session:, redirect_uri:)
    # 1. Verifica state para prevenir CSRF
    raise OauthError, "State inválido"   unless session[:oauth_state] == state
    raise OauthError, "State expirado"   if Time.current.to_i > session[:oauth_state_exp].to_i

    # 2. Limpa state da sessão imediatamente (one-time use)
    code_verifier = session.delete(:oauth_code_verifier)
    session.delete(:oauth_state)
    session.delete(:oauth_state_exp)

    config = PROVIDERS.fetch(provider)

    # 3. Troca code por access_token
    response = Faraday.post(config[:token_url]) do |req|
      req.headers["Content-Type"] = "application/x-www-form-urlencoded"
      req.body = {
        client_id:     ENV.fetch("GOOGLE_CLIENT_ID"),
        client_secret: ENV.fetch("GOOGLE_CLIENT_SECRET"),  # Nunca no código!
        code:          code,
        code_verifier: code_verifier,  # PKCE
        redirect_uri:  redirect_uri,
        grant_type:    "authorization_code"
      }
    end

    raise OauthError, "Falha ao obter token" unless response.success?

    token_data  = JSON.parse(response.body)
    id_token    = token_data["id_token"]

    # 4. Valida ID token JWT (Google assina com chave pública conhecida)
    user_info = validate_and_decode_id_token(id_token, provider:)

    # 5. Retorna dados do usuário verificados
    {
      provider_id: user_info["sub"],
      email:       user_info["email"],
      name:        user_info["name"],
      avatar_url:  user_info["picture"],
      verified:    user_info["email_verified"]
    }
  end

  private

  def self.validate_and_decode_id_token(id_token, provider:)
    # Busca chaves públicas do provedor (com cache de 1 hora)
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
    jwks     = Rails.cache.fetch("oauth:jwks:google", expires_in: 1.hour) do
      JSON.parse(Faraday.get(jwks_uri).body)
    end

    # Decodifica e verifica assinatura
    decoded = JWT.decode(
      id_token,
      nil,  # Chave resolvida dinamicamente pelo JWKS
      true,
      {
        algorithms: ["RS256"],
        jwks:       jwks,
        iss:        "https://accounts.google.com",
        verify_iss: true,
        aud:        ENV.fetch("GOOGLE_CLIENT_ID"),
        verify_aud: true
      }
    )

    decoded.first
  rescue JWT::DecodeError => e
    raise OauthError, "ID Token inválido: #{e.message}"
  end
end
```

---

## 4. Two-Factor Authentication (2FA) {#2fa}

```ruby
# app/models/two_factor_auth.rb

# TOTP (Time-based One-Time Password) — RFC 6238
# Compatível com Google Authenticator, Authy, 1Password
class TwoFactorAuth
  ISSUER     = "MeuApp"
  DIGITS     = 6
  DRIFT      = 1  # Aceita 1 período anterior/posterior (30s de tolerância)

  # Gera secret e QR code para configuração
  def self.setup(user)
    # 32 bytes = 256 bits de entropia — resistente a brute force
    secret = ROTP::Base32.random(32)

    # Criptografa secret antes de salvar no banco
    encrypted_secret = EncryptionService.encrypt(secret)

    totp    = ROTP::TOTP.new(secret, issuer: ISSUER, digits: DIGITS)
    otp_uri = totp.provisioning_uri(user.email)

    # QR code como SVG inline (não depende de serviço externo)
    qr_svg = RQRCode::QRCode.new(otp_uri).as_svg(
      color:        "000",
      shape_rendering: "crispEdges",
      module_size:  4
    )

    {
      secret:           secret,  # Exibe UMA VEZ para o usuário copiar
      encrypted_secret: encrypted_secret,
      qr_svg:           qr_svg,
      backup_codes:     generate_backup_codes
    }
  end

  # Verifica código TOTP com drift para tolerância de clock skew
  def self.verify(user, code)
    return false unless user.totp_secret_encrypted.present?

    secret = EncryptionService.decrypt(user.totp_secret_encrypted)
    totp   = ROTP::TOTP.new(secret, issuer: ISSUER, digits: DIGITS)

    # SEGURANÇA: drift de 1 = aceita código do período anterior/próximo
    # Necessário pois relógios de usuário podem ter pequena diferença
    last_otp_at = totp.verify(
      code.to_s.gsub(/\s/, ""),  # Remove espaços acidentais
      drift_behind: 30,
      drift_ahead:  30,
      after: user.last_otp_at    # Previne reuso do mesmo código
    )

    if last_otp_at
      # Registra timestamp para prevenir replay do mesmo código
      user.update_column(:last_otp_at, last_otp_at)
      true
    else
      false
    end
  end

  # Códigos de backup criptografados — usados quando perder o dispositivo
  def self.generate_backup_codes
    codes = Array.new(10) { SecureRandom.hex(5).upcase.scan(/.{5}/).join("-") }
    # ["A3F2B-9C4D1", "E7K3M-2P5Q8", ...]
    codes
  end
end
```

---

## 5. Upload Seguro de Arquivos {#upload}

```ruby
# app/uploaders/secure_uploader.rb

# SEGURANÇA: Validação rigorosa de uploads — vetor de ataque comum
class SecureUploader < CarrierWave::Uploader::Base
  # Tipos MIME explicitamente permitidos (whitelist)
  ALLOWED_CONTENT_TYPES = %w[
    image/jpeg image/png image/gif image/webp
    application/pdf
  ].freeze

  # Extensões permitidas (defesa em profundidade)
  ALLOWED_EXTENSIONS = %w[jpg jpeg png gif webp pdf].freeze

  # Tamanho máximo: 10MB para imagens, 50MB para PDFs
  MAX_SIZES = {
    "image" => 10.megabytes,
    "application" => 50.megabytes
  }.freeze

  # SEGURANÇA: Renomeia arquivo com UUID para prevenir path traversal
  # e evitar adivinhação de URLs
  def filename
    return unless original_filename
    "#{SecureRandom.uuid}#{File.extname(original_filename).downcase}"
  end

  # SEGURANÇA: Verifica magic bytes do arquivo (não confia na extensão)
  def content_type_allowlist
    ALLOWED_CONTENT_TYPES
  end

  def extension_allowlist
    ALLOWED_EXTENSIONS
  end

  def size_range
    1.byte..50.megabytes
  end

  # SEGURANÇA: Verifica magic bytes reais do arquivo
  # Um arquivo .jpg com conteúdo PHP pode ser renomeado para bypass
  def verify_content_type!
    content_type_from_bytes = Marcel::MimeType.for(
      File.open(file.path),
      name: file.original_filename
    )

    unless ALLOWED_CONTENT_TYPES.include?(content_type_from_bytes)
      raise CarrierWave::IntegrityError,
            "Tipo de arquivo não permitido (detectado: #{content_type_from_bytes})"
    end
  end

  # SEGURANÇA: Strip de metadados EXIF (localização GPS, dados pessoais)
  process :strip_exif

  def strip_exif
    return unless image?

    # Reprocessa imagem para remover metadados
    # Exiftool ou ImageMagick -strip
    manipulate! do |img|
      img.strip!  # Remove todos os perfis e comentários
      img
    end
  end

  private

  def image?
    file.content_type.start_with?("image/")
  end
end
```

---

## 6. Auditoria e Logging Seguro {#audit}

```ruby
# app/models/audit_log.rb
class AuditLog < ApplicationRecord
  belongs_to :user, optional: true  # Permite logs de ações sem autenticação

  # Campos obrigatórios para rastreabilidade
  validates :action,     presence: true
  validates :ip_address, presence: true

  # SEGURANÇA: Logs imutáveis — após criar não pode editar/deletar
  before_update { raise ActiveRecord::ReadOnlyRecord }
  before_destroy { raise ActiveRecord::ReadOnlyRecord }

  # Tipos de ação monitorados
  ACTIONS = {
    login_success:   "login.success",
    login_failure:   "login.failure",
    logout:          "auth.logout",
    password_change: "user.password_change",
    role_change:     "admin.role_change",
    data_export:     "user.data_export",
    api_access:      "api.access",
    rate_limit_hit:  "security.rate_limit",
    suspicious:      "security.suspicious"
  }.freeze

  scope :suspicious, -> { where(action: ACTIONS[:suspicious]) }
  scope :by_ip,      ->(ip) { where(ip_address: ip) }
  scope :recent,     -> { order(created_at: :desc).limit(100) }

  def self.log(action:, user: nil, request: nil, metadata: {})
    # SEGURANÇA: Não falha silenciosamente — usa create! mas captura exceção
    create!(
      user_id:    user&.id,
      action:     action,
      ip_address: request ? anonymize_ip(request.remote_ip) : "system",
      user_agent: request&.user_agent&.first(500),  # Limita tamanho
      path:       request&.path,
      method:     request&.request_method,
      metadata:   sanitize_metadata(metadata)  # Remove dados sensíveis dos metadados
    )
  rescue => e
    # Log para sistema de monitoramento mas não quebra a aplicação
    Rails.logger.error("[AuditLog] Falha ao criar log: #{e.message}")
    Sentry.capture_exception(e) if defined?(Sentry)
  end

  private

  def self.sanitize_metadata(metadata)
    # Remove campos sensíveis dos metadados antes de logar
    sensitive_keys = %w[password token secret api_key credit_card]
    metadata.deep_transform_keys(&:to_s)
            .reject { |k, _| sensitive_keys.any? { |s| k.include?(s) } }
  end

  def self.anonymize_ip(ip)
    addr = IPAddr.new(ip)
    addr.ipv4? ? "#{ip.split(".")[0..2].join(".")}.0" : addr.mask(48).to_s
  rescue IPAddr::InvalidAddressError
    "invalid"
  end
end
```
