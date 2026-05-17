# ActiveRecord — Queries Seguras e Otimizadas

## TABELA DE CONTEÚDO
1. [Queries Seguras](#queries)
2. [Migrations com Segurança](#migrations)
3. [Validações Avançadas](#validations)
4. [Prevenção N+1](#n_plus_1)
5. [Transações e Concorrência](#transactions)
6. [Índices e Performance](#indexes)

---

## 1. Queries Seguras {#queries}

```ruby
# ============================================================
# GUIA COMPLETO DE QUERIES ACTIVERECORD SEGURAS
# ============================================================

# NUNCA: Interpolação direta (SQL Injection)
User.where("email = '#{params[:email]}'")          # ← VULNERÁVEL

# SEMPRE: Uma dessas formas seguras:

# 1. Hash syntax (mais legível, sempre seguro)
User.where(email: params[:email])

# 2. Placeholder com ? (para operadores especiais)
User.where("created_at > ?", 1.week.ago)

# 3. Named placeholders (mais legível com múltiplos parâmetros)
User.where("role = :role AND active = :active",
           role: "admin", active: true)

# 4. LIKE seguro — escapa metacaracteres do SQL
query = "%#{User.sanitize_sql_like(params[:search])}%"
User.where("name LIKE ?", query)

# 5. IN clause segura
User.where(id: [1, 2, 3])  # Rails escapa automaticamente

# 6. Ranges
User.where(created_at: 1.week.ago..Time.current)

# ============================================================
# SCOPES SEGUROS E REUTILIZÁVEIS
# ============================================================

class Post < ApplicationRecord
  # Scopes encapsulam lógica de query — reutilizáveis e testáveis
  scope :published,    -> { where(published: true) }
  scope :draft,        -> { where(published: false) }
  scope :recent,       -> { order(created_at: :desc) }
  scope :by_author,    ->(user_id) { where(author_id: user_id) }
  scope :with_content, -> { where.not(content: [nil, ""]) }

  # Scope com parâmetro seguro — sanitização antes de usar em query
  scope :search, ->(query) {
    return none if query.blank?
    sanitized = "%#{sanitize_sql_like(query.to_s.strip[0..100])}%"  # Limita tamanho
    where("title ILIKE ? OR content ILIKE ?", sanitized, sanitized)
  }

  # Scope de paginação segura — evita page=-1 ou limit=999999
  scope :paginate, ->(page:, per: 25) {
    safe_page = [page.to_i, 1].max           # Mínimo página 1
    safe_per  = [[per.to_i, 1].max, 100].min  # Entre 1 e 100 por página
    offset((safe_page - 1) * safe_per).limit(safe_per)
  }
end
```

---

## 2. Migrations com Segurança {#migrations}

```ruby
# db/migrate/20240101000001_create_users.rb
class CreateUsers < ActiveRecord::Migration[7.1]
  def change
    create_table :users, id: :uuid do |t|  # UUID em vez de ID sequencial
      # UUID como PK: evita enumeração e adivinhação de IDs (IDOR prevention)

      # Dados de autenticação
      t.string  :email,                     null: false
      t.string  :username,                  null: false
      t.string  :password_digest,           null: false  # BCrypt hash

      # Tokens e verificação
      t.string  :email_verification_token
      t.datetime :email_verified_at
      t.string  :password_reset_token       # Armazena HASH do token
      t.datetime :password_reset_sent_at

      # Controle de acesso
      t.integer :role,                      null: false, default: 1
      t.integer :failed_attempts,           null: false, default: 0
      t.datetime :locked_at
      t.datetime :session_invalidated_at   # Para logout global

      # 2FA
      t.string  :totp_secret_encrypted      # Criptografado em AES-256
      t.datetime :last_otp_at
      t.text    :backup_codes_encrypted     # Array de códigos criptografados

      # Soft delete (preserva histórico para auditoria)
      t.datetime :deleted_at
      t.datetime :banned_at
      t.string  :ban_reason

      # Metadata
      t.string  :last_sign_in_ip
      t.datetime :last_sign_in_at
      t.string  :current_sign_in_ip
      t.datetime :current_sign_in_at
      t.integer :sign_in_count, default: 0

      t.timestamps
    end

    # ÍNDICES para queries frequentes e unicidade
    add_index :users, :email,    unique: true  # Unicidade + performance
    add_index :users, :username, unique: true
    add_index :users, :deleted_at              # Para scope :active
    add_index :users, :role                    # Para filtros por role
    add_index :users, :email_verification_token, unique: true, where: "email_verification_token IS NOT NULL"
    add_index :users, :password_reset_token,    unique: true, where: "password_reset_token IS NOT NULL"
  end
end

# Adição de coluna com zero downtime (produção)
class AddPhoneToUsers < ActiveRecord::Migration[7.1]
  # SEGURANÇA: safe_column_add evita lock de tabela em produção
  # Sempre: disable_ddl_transaction! + algoritmo :concurrent para índices
  disable_ddl_transaction!

  def change
    # Adiciona coluna com default null (não faz UPDATE em toda tabela)
    add_column :users, :phone_encrypted, :string

    # Índice concorrente — não bloqueia tabela em produção
    add_index :users, :phone_encrypted,
              algorithm: :concurrently,
              where: "phone_encrypted IS NOT NULL"
  end
end
```

---

## 3. Prevenção N+1 Queries {#n_plus_1}

```ruby
# ============================================================
# PROBLEMA N+1 — Um dos maiores problemas de performance Rails
# ============================================================

# VULNERÁVEL: Gera 1 + N queries (1 para posts, N para cada autor)
posts = Post.published.recent.limit(20)
posts.each { |p| puts p.author.name }  # ← N queries extras!

# SEGURO: includes carrega autor em 1 query (ou 2 com JOIN)
posts = Post.includes(:author)
            .published
            .recent
            .limit(20)
posts.each { |p| puts p.author.name }  # ← 0 queries extras

# Associações aninhadas
posts = Post.includes(
  author: :profile,           # Autor + perfil do autor
  comments: [:author, :likes] # Comentários + autor + likes de cada comentário
).published

# QUANDO usar includes vs joins:
# includes = usa para ACESSAR dados da associação em Ruby
# joins    = usa para FILTRAR por dados da associação (SELECT mais eficiente)
# eager_load = force LEFT OUTER JOIN (necessário para .where na associação)

# Filtrar posts de autores verificados:
Post.eager_load(:author).where(users: { email_verified_at: !nil })

# Selecionar apenas colunas necessárias (evita OOM com tabelas grandes)
User.select(:id, :email, :role)    # Não carrega password_digest, tokens, etc.
    .where(role: :admin)

# Counter cache — evita COUNT(*) frequente
# Na migration:
add_column :posts, :comments_count, :integer, default: 0, null: false
# No model:
class Comment < ApplicationRecord
  belongs_to :post, counter_cache: true  # Mantém posts.comments_count atualizado
end
# Uso:
post.comments_count  # Lê do banco — sem query adicional

# ============================================================
# BULLET GEM — Detecta N+1 automaticamente em desenvolvimento
# ============================================================
# config/environments/development.rb
config.after_initialize do
  Bullet.enable        = true
  Bullet.alert         = true
  Bullet.rails_logger  = true
  Bullet.add_footer    = true
end
```

---

## 4. Transações e Concorrência {#transactions}

```ruby
# ============================================================
# TRANSAÇÕES — Garante atomicidade de operações críticas
# ============================================================

class TransferService
  def self.transfer!(from_account:, to_account:, amount:)
    raise ArgumentError, "Valor deve ser positivo" unless amount.positive?

    ActiveRecord::Base.transaction do
      # SEGURANÇA: lock! previne race condition (double-spend attack)
      # SELECT ... FOR UPDATE — bloqueia linhas até fim da transação
      from = Account.lock.find(from_account.id)
      to   = Account.lock.find(to_account.id)

      raise InsufficientFundsError if from.balance < amount

      from.decrement!(:balance, amount)
      to.increment!(:balance, amount)

      # Registra transação para auditoria e reconciliação
      Transaction.create!(
        from_account: from,
        to_account:   to,
        amount:       amount,
        idempotency_key: SecureRandom.uuid  # Previne duplicatas
      )
    end
    # Se qualquer operação falhar, TODO é revertido (rollback automático)

  rescue ActiveRecord::RecordInvalid => e
    raise TransferError, "Transferência inválida: #{e.message}"
  rescue ActiveRecord::Deadlocked
    # Retry com backoff exponencial em caso de deadlock
    retry_count ||= 0
    raise if retry_count >= 3
    retry_count += 1
    sleep(0.1 * (2 ** retry_count))  # 0.2s, 0.4s, 0.8s
    retry
  end
end

# ============================================================
# IDEMPOTÊNCIA — Previne operações duplicadas
# ============================================================

class PaymentController < ApplicationController
  def create
    # SEGURANÇA: Idempotency key do cliente previne cobranças duplas
    # (retry de rede, duplo clique, etc.)
    idempotency_key = request.headers["Idempotency-Key"]
    raise BadRequest, "Idempotency-Key obrigatório" if idempotency_key.blank?

    # Verifica se já foi processado (cache por 24h)
    cached = Rails.cache.read("payment:#{idempotency_key}")
    return render json: cached if cached

    # Processa pagamento
    payment = PaymentService.charge!(
      user:   current_user,
      amount: payment_params[:amount],
      token:  payment_params[:card_token]
    )

    result = PaymentSerializer.new(payment).as_json

    # Cacheia resultado
    Rails.cache.write("payment:#{idempotency_key}", result, expires_in: 24.hours)

    render json: result, status: :created
  end
end
```

---

## 5. Índices e Performance {#indexes}

```ruby
# ============================================================
# EXPLAIN ANALYZE — Diagnostica queries lentas
# ============================================================

# No Rails console ou migration:
puts Post.published.by_author(user.id).to_sql
# SELECT "posts".* FROM "posts" WHERE "posts"."published" = TRUE AND "posts"."author_id" = $1

ActiveRecord::Base.connection.execute(
  "EXPLAIN ANALYZE #{Post.published.by_author(user.id).to_sql}"
).each { |row| puts row["QUERY PLAN"] }

# Índice composto para queries frequentes
add_index :posts, [:author_id, :published, :created_at]
# Cobre: WHERE author_id = X AND published = TRUE ORDER BY created_at

# Índice parcial — menor e mais rápido para subset dos dados
add_index :users, :email,
          unique: true,
          where: "deleted_at IS NULL"  # Apenas usuários ativos

# Índice para full-text search (PostgreSQL)
# Na migration:
execute <<~SQL
  ALTER TABLE posts ADD COLUMN search_vector tsvector;

  CREATE INDEX posts_search_idx ON posts USING gin(search_vector);

  CREATE OR REPLACE FUNCTION posts_search_vector_update() RETURNS trigger AS $$
  BEGIN
    NEW.search_vector :=
      setweight(to_tsvector('portuguese', coalesce(NEW.title, '')), 'A') ||
      setweight(to_tsvector('portuguese', coalesce(NEW.content, '')), 'B');
    RETURN NEW;
  END
  $$ LANGUAGE plpgsql;

  CREATE TRIGGER posts_search_vector_update
    BEFORE INSERT OR UPDATE ON posts
    FOR EACH ROW EXECUTE FUNCTION posts_search_vector_update();
SQL

# No model:
scope :full_text_search, ->(query) {
  return none if query.blank?
  sanitized = Post.connection.quote(query.to_s.strip)
  where("search_vector @@ plainto_tsquery('portuguese', #{sanitized})")
    .order(Arel.sql("ts_rank(search_vector, plainto_tsquery('portuguese', #{sanitized})) DESC"))
}
```
