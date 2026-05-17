# API REST & GraphQL Segura em Rails

## TABELA DE CONTEÚDO
1. [Estrutura de API REST](#rest)
2. [Serialização Segura](#serialization)
3. [Rate Limiting](#rate_limit)
4. [Versionamento](#versioning)
5. [GraphQL Seguro](#graphql)

---

## 1. API REST Segura {#rest}

```ruby
# config/routes.rb
Rails.application.routes.draw do
  # Versioning via namespace — não quebra clientes existentes
  namespace :api do
    namespace :v1 do
      # Autenticação
      post   "auth/register",       to: "registrations#create"
      post   "auth/login",          to: "sessions#create"
      delete "auth/logout",         to: "sessions#destroy"
      post   "auth/refresh",        to: "tokens#refresh"
      post   "auth/verify_email",   to: "email_verifications#create"
      post   "auth/forgot_password", to: "password_resets#create"
      patch  "auth/reset_password",  to: "password_resets#update"

      # Recursos autenticados
      resources :users, only: [:show, :update, :destroy]
      resources :posts do
        resources :comments, shallow: true
        member do
          post :publish
          post :unpublish
        end
      end

      # Health check — sem autenticação (para load balancer)
      get "health", to: "health#show"
    end
  end

  # SEGURANÇA: Catch-all retorna 404 (não 422 ou 500 que vaza info)
  match "*unmatched", to: "application#not_found", via: :all
end
```

---

## 2. Serialização Segura {#serialization}

```ruby
# app/serializers/user_serializer.rb
# jsonapi-serializer ou blueprinter

class UserSerializer
  include JSONAPI::Serializer

  # SEGURANÇA: Whitelist de atributos — nunca serializa tudo
  # password_digest, totp_secret, tokens JAMAIS aparecem na resposta
  attributes :id, :username, :email, :role, :created_at

  # Atributo computado — formato consistente de data
  attribute :member_since do |user|
    user.created_at.iso8601  # RFC 3339 — formato universal
  end

  attribute :avatar_url do |user|
    UserDecorator.new(user).avatar_url
  end

  # Relações — apenas dados necessários, evita N+1 com includes
  has_many :posts, serializer: PostSummarySerializer

  # SEGURANÇA: Atributos condicionais por permissão
  attribute :email do |user, params|
    # Email só aparece se: é o próprio usuário OU admin
    current_user = params[:current_user]
    if current_user&.id == user.id || current_user&.role_admin?
      user.email
    else
      UserDecorator.new(user).masked_email
    end
  end
end

# SEGURANÇA: Resposta de erro padronizada (RFC 7807 - Problem Details)
module ErrorSerializer
  def self.serialize(errors, status:)
    {
      type:    "https://docs.meuapp.com/errors",
      title:   Rack::Utils::HTTP_STATUS_CODES[status],
      status:  status,
      errors:  Array(errors).map { |e| { detail: e } }
    }
  end
end
```

---

## 3. Rate Limiting Avançado {#rate_limit}

```ruby
# config/initializers/rack_attack.rb
class Rack::Attack
  # SEGURANÇA: Throttle por IP para rotas públicas
  throttle("api/ip", limit: 300, period: 5.minutes) do |req|
    req.ip if req.path.start_with?("/api/")
  end

  # Throttle mais restrito para login (anti brute force)
  throttle("logins/ip", limit: 5, period: 20.minutes) do |req|
    req.ip if req.path == "/api/v1/auth/login" && req.post?
  end

  # Throttle por usuário autenticado (mais permissivo que por IP)
  throttle("api/user", limit: 1000, period: 1.hour) do |req|
    # Extrai user_id do token JWT sem validar assinatura (apenas para throttle)
    if (token = req.get_header("HTTP_AUTHORIZATION")&.split(" ")&.last)
      begin
        JWT.decode(token, nil, false).first["user_id"]
      rescue JWT::DecodeError
        nil
      end
    end
  end

  # Throttle especial para endpoints custosos
  throttle("api/search", limit: 30, period: 1.minute) do |req|
    req.ip if req.path.start_with?("/api/v1/search")
  end

  # SEGURANÇA: Bloqueia IPs com comportamento suspeito
  blocklist("block-bad-actors") do |req|
    BlockedIp.exists?(ip: req.ip)
  end

  # Resposta customizada para rate limit
  self.throttled_responder = ->(env) {
    retry_after = (env["rack.attack.match_data"] || {})[:period]
    [
      429,
      {
        "Content-Type" => "application/json",
        "Retry-After"  => retry_after.to_s
      },
      [{ error: "Muitas requisições. Tente novamente em #{retry_after} segundos." }.to_json]
    ]
  }
end
```

---

## 4. GraphQL Seguro {#graphql}

```ruby
# app/graphql/my_app_schema.rb
class MyAppSchema < GraphQL::Schema
  mutation(Types::MutationType)
  query(Types::QueryType)

  # SEGURANÇA: Limita profundidade de queries (previne DOS via queries aninhadas)
  # query { user { posts { comments { author { posts { ... } } } } } }
  max_depth 10

  # SEGURANÇA: Limita complexidade total (cada campo tem um custo)
  max_complexity 200

  # SEGURANÇA: Timeout por query
  use GraphQL::Schema::Timeout, max_seconds: 10

  # SEGURANÇA: Desativa introspection em produção
  # Introspection revela toda a estrutura do schema para atacantes
  if Rails.env.production?
    use GraphQL::Schema::DisableIntrospection
  end

  # SEGURANÇA: Paginação obrigatória em conexões
  default_max_page_size 50

  # Contexto disponível em todos os resolvers
  def self.context_class
    GraphqlContext
  end
end

# app/graphql/types/query_type.rb
module Types
  class QueryType < Types::BaseObject
    # SEGURANÇA: Autorização por resolver

    field :me, Types::UserType, null: true,
          description: "Usuário autenticado atual"

    def me
      context[:current_user]  # nil se não autenticado
    end

    field :post, Types::PostType, null: true do
      argument :id, ID, required: true
    end

    def post(id:)
      # SEGURANÇA: Busca via policy_scope (autorização automática)
      post = Post.find_by(id: id)

      # Verifica permissão via Pundit
      context[:pundit].authorize(post, :show?) if post
      post

    rescue Pundit::NotAuthorizedError
      nil  # Retorna nil em vez de erro (evita IDOR via enumeration)
    end
  end
end

# SEGURANÇA: Prevenção de N+1 em GraphQL com dataloader
# app/graphql/loaders/association_loader.rb
class AssociationLoader < GraphQL::Batch::Loader
  def initialize(model, association_name)
    super()
    @model            = model
    @association_name = association_name
  end

  def perform(records)
    # Carrega associação para TODOS os records de uma vez (batch)
    ::ActiveRecord::Associations::Preloader
      .new(records: records, associations: [@association_name])
      .call

    records.each do |record|
      fulfill(record, record.public_send(@association_name))
    end
  end
end

# Uso no resolver:
field :author, Types::UserType, null: false

def author
  # Ao invés de object.author (N+1), usa dataloader
  AssociationLoader.for(Post, :author).load(object)
end
```
