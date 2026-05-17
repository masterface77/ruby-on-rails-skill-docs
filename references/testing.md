# Testes Rails — RSpec, FactoryBot e Segurança

## TABELA DE CONTEÚDO
1. [Configuração RSpec](#rspec_config)
2. [Factories Seguras](#factories)
3. [Model Specs](#model_specs)
4. [Request Specs (API)](#request_specs)
5. [Testes de Segurança](#security_tests)

---

## 1. Configuração RSpec {#rspec_config}

```ruby
# spec/rails_helper.rb
require "spec_helper"
require "rails/all"
require "rspec/rails"
require "database_cleaner/active_record"
require "shoulda/matchers"
require "factory_bot_rails"

RSpec.configure do |config|
  config.include FactoryBot::Syntax::Methods
  config.include RequestSpecHelper  # helpers de autenticação para tests

  # Database cleaner — banco limpo entre testes
  config.before(:suite)   { DatabaseCleaner.strategy = :transaction }
  config.before(:each)    { DatabaseCleaner.start }
  config.after(:each)     { DatabaseCleaner.clean }
  config.before(:each, :js) do
    DatabaseCleaner.strategy = :truncation
  end

  # Shared contexts reutilizáveis
  config.shared_context_metadata_behavior = :apply_to_host_groups
end

Shoulda::Matchers.configure do |config|
  config.integrate { |with|
    with.test_framework :rspec
    with.library       :rails
  }
end

# spec/support/request_spec_helper.rb
module RequestSpecHelper
  # Helper para autenticar nas request specs
  def auth_headers(user)
    token = JwtService.encode({ user_id: user.id })
    { "Authorization" => "Bearer #{token}", "Content-Type" => "application/json" }
  end

  def json_response
    JSON.parse(response.body, symbolize_names: true)
  end
end
```

---

## 2. Factories Seguras {#factories}

```ruby
# spec/factories/users.rb
FactoryBot.define do
  factory :user do
    # SEGURANÇA: Sequências garantem unicidade entre testes
    sequence(:email)    { |n| "user#{n}@example.com" }
    sequence(:username) { |n| "user_#{n}" }

    password              { "SecurePass123!" }
    password_confirmation { "SecurePass123!" }
    role                  { :user }
    email_verified_at     { Time.current }  # Verificado por padrão

    # Traits para diferentes estados
    trait :admin do
      role              { :admin }
      sequence(:email)  { |n| "admin#{n}@example.com" }
    end

    trait :unverified do
      email_verified_at { nil }
    end

    trait :locked do
      locked_at       { Time.current }
      failed_attempts { 10 }
    end

    trait :with_posts do
      after(:create) { |user| create_list(:post, 3, author: user) }
    end

    trait :with_2fa do
      totp_secret_encrypted { EncryptionService.encrypt(ROTP::Base32.random(32)) }
    end
  end
end

# spec/factories/posts.rb
FactoryBot.define do
  factory :post do
    association :author, factory: :user

    sequence(:title)    { |n| "Post #{n}" }
    content             { Faker::Lorem.paragraphs(number: 3).join("\n\n") }
    published           { false }

    trait :published do
      published    { true }
      published_at { 1.day.ago }
    end

    trait :with_comments do
      after(:create) { |post| create_list(:comment, 5, post: post) }
    end
  end
end
```

---

## 3. Model Specs {#model_specs}

```ruby
# spec/models/user_spec.rb
RSpec.describe User, type: :model do
  # Shoulda Matchers para validações rápidas
  describe "validations" do
    subject { build(:user) }

    it { is_expected.to validate_presence_of(:email) }
    it { is_expected.to validate_uniqueness_of(:email).case_insensitive }
    it { is_expected.to validate_length_of(:password).is_at_least(12) }
    it { is_expected.to validate_length_of(:password).is_at_most(128) }
  end

  describe "associations" do
    it { is_expected.to have_many(:posts).dependent(:destroy) }
    it { is_expected.to have_many(:sessions).dependent(:destroy) }
  end

  describe "#generate_reset_token!" do
    let(:user) { create(:user) }

    it "retorna um token raw seguro" do
      token = user.generate_reset_token!
      expect(token).to be_present
      expect(token.length).to be >= 32  # Pelo menos 32 chars (base64 de 24 bytes)
    end

    it "salva hash do token no banco (não o token raw)" do
      token = user.generate_reset_token!
      user.reload
      expect(user.password_reset_token).not_to eq(token)  # Não armazena raw
      expect(BCrypt::Password.new(user.password_reset_token) == token).to be true
    end

    it "define expiração de 2 horas" do
      user.generate_reset_token!
      expect(user.password_reset_sent_at).to be_within(5.seconds).of(Time.current)
    end
  end

  describe "#valid_reset_token?" do
    let(:user)  { create(:user) }
    let(:token) { user.generate_reset_token! }

    it "retorna true com token válido" do
      expect(user.valid_reset_token?(token)).to be true
    end

    it "retorna false com token inválido" do
      expect(user.valid_reset_token?("invalid_token")).to be false
    end

    it "retorna false com token expirado" do
      travel_to 3.hours.from_now do
        expect(user.valid_reset_token?(token)).to be false
      end
    end

    it "toma tempo constante (previne timing attack)" do
      valid_times   = Array.new(10) { Benchmark.realtime { user.valid_reset_token?(token) } }
      invalid_times = Array.new(10) { Benchmark.realtime { user.valid_reset_token?("wrong") } }

      valid_avg   = valid_times.sum   / valid_times.size
      invalid_avg = invalid_times.sum / invalid_times.size

      # Diferença de tempo deve ser pequena (< 50ms) — tempo constante
      expect((valid_avg - invalid_avg).abs).to be < 0.05
    end
  end
end
```

---

## 4. Request Specs (API) {#request_specs}

```ruby
# spec/requests/api/v1/sessions_spec.rb
RSpec.describe "POST /api/v1/auth/login", type: :request do
  let(:user) { create(:user, password: "SecurePass123!") }

  describe "login bem-sucedido" do
    it "retorna access_token e status 201" do
      post "/api/v1/auth/login", params: {
        email:    user.email,
        password: "SecurePass123!"
      }.to_json, headers: { "Content-Type" => "application/json" }

      expect(response).to have_http_status(:created)
      expect(json_response[:access_token]).to be_present
    end

    it "define cookie refresh_token HttpOnly" do
      post "/api/v1/auth/login", params: { email: user.email, password: "SecurePass123!" }.to_json,
           headers: { "Content-Type" => "application/json" }

      cookie = response.cookies["refresh_token"]
      expect(cookie).to be_present
    end
  end

  describe "segurança" do
    it "retorna mensagem genérica para e-mail inválido" do
      post "/api/v1/auth/login", params: { email: "nonexistent@test.com", password: "any" }.to_json,
           headers: { "Content-Type" => "application/json" }

      expect(response).to have_http_status(:unauthorized)
      expect(json_response[:error]).to eq("E-mail ou senha inválidos")
      # NÃO deve dizer "e-mail não encontrado" ou "senha incorreta"
    end

    it "retorna mensagem genérica para senha errada (mesmo texto)" do
      post "/api/v1/auth/login", params: { email: user.email, password: "wrong_password" }.to_json,
           headers: { "Content-Type" => "application/json" }

      expect(response).to have_http_status(:unauthorized)
      expect(json_response[:error]).to eq("E-mail ou senha inválidos")
    end

    it "bloqueia após 5 tentativas (rate limit)" do
      6.times do
        post "/api/v1/auth/login", params: { email: user.email, password: "wrong" }.to_json,
             headers: { "Content-Type" => "application/json" }
      end

      expect(response).to have_http_status(:too_many_requests)
    end
  end
end

# spec/requests/api/v1/posts_spec.rb
RSpec.describe "Posts API", type: :request do
  let(:user)  { create(:user) }
  let(:other) { create(:user) }
  let(:post_record) { create(:post, author: user) }

  describe "autorização" do
    it "impede acesso não autenticado" do
      get "/api/v1/posts/#{post_record.id}"
      expect(response).to have_http_status(:unauthorized)
    end

    it "impede que outro usuário edite post alheio (IDOR)" do
      patch "/api/v1/posts/#{post_record.id}",
            params: { post: { title: "Hacked!" } }.to_json,
            headers: auth_headers(other)  # outro usuário

      expect(response).to have_http_status(:forbidden)
      expect(post_record.reload.title).not_to eq("Hacked!")
    end

    it "retorna 404 (não 403) para post inexistente — evita IDOR" do
      get "/api/v1/posts/00000000-0000-0000-0000-000000000000",
          headers: auth_headers(other)

      expect(response).to have_http_status(:not_found)
    end
  end
end
```

---

## 5. Testes de Segurança Específicos {#security_tests}

```ruby
# spec/security/sql_injection_spec.rb
RSpec.describe "Proteção contra SQL Injection", type: :request do
  let(:user) { create(:user) }

  SQL_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1 UNION SELECT * FROM users",
    "' OR 1=1--",
    "admin'--",
    "' OR 'x'='x"
  ].freeze

  SQL_PAYLOADS.each do |payload|
    it "não executa: #{payload.truncate(30)}" do
      expect {
        get "/api/v1/posts", params: { search: payload },
            headers: auth_headers(user)
      }.not_to raise_error

      expect(response).not_to have_http_status(:internal_server_error)
      expect(User.count).to be >= 1  # Tabela não foi dropada
    end
  end
end

# spec/security/xss_spec.rb
RSpec.describe "Proteção contra XSS", type: :request do
  let(:user) { create(:user) }

  XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>"
  ].freeze

  XSS_PAYLOADS.each do |payload|
    it "sanitiza: #{payload.truncate(30)}" do
      post "/api/v1/posts",
           params: { post: { title: payload, content: "test" } }.to_json,
           headers: auth_headers(user)

      if response.successful?
        post_id = json_response.dig(:data, :id)
        post_record = Post.find_by(id: post_id)

        if post_record
          # O título não deve conter tags HTML executáveis
          expect(post_record.title).not_to match(/<script/i)
          expect(post_record.title).not_to match(/onerror/i)
          expect(post_record.title).not_to match(/javascript:/i)
        end
      end
    end
  end
end
```
