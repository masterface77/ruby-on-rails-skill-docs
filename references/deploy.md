# Deploy Seguro — Docker, CI/CD, Secrets, SSL

## TABELA DE CONTEÚDO
1. [Dockerfile Seguro](#docker)
2. [CI/CD Pipeline](#cicd)
3. [Gestão de Secrets](#secrets)
4. [Checklist de Produção](#checklist)

---

## 1. Dockerfile Seguro {#docker}

```dockerfile
# Dockerfile
# SEGURANÇA: Multi-stage build — imagem final não tem ferramentas de build
# Reduz superfície de ataque e tamanho da imagem

# === STAGE 1: Builder ===
FROM ruby:3.3-slim AS builder

# SEGURANÇA: Não roda como root no build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev git \
    && rm -rf /var/lib/apt/lists/*  # Remove cache apt

WORKDIR /app

# Copia Gemfile primeiro — aproveita cache de layers do Docker
COPY Gemfile Gemfile.lock ./

# SEGURANÇA: --without development test — não instala gems de dev em prod
# --deployment mode usa versões exatas do Gemfile.lock
RUN bundle config set --local without "development test" && \
    bundle config set --local deployment true && \
    bundle install --jobs 4

COPY . .

# Precompila assets (sem segredos — usa SECRET_KEY_BASE_DUMMY)
RUN SECRET_KEY_BASE_DUMMY=1 bundle exec rails assets:precompile

# === STAGE 2: Runtime ===
FROM ruby:3.3-slim AS runtime

# SEGURANÇA: Cria usuário não-root dedicado
RUN groupadd --gid 1001 rails && \
    useradd --uid 1001 --gid 1001 --no-create-home --shell /bin/bash rails

# Apenas dependências de runtime (não de build)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia apenas artefatos necessários do builder
COPY --from=builder --chown=rails:rails /usr/local/bundle /usr/local/bundle
COPY --from=builder --chown=rails:rails /app /app

# SEGURANÇA: Remove arquivos desnecessários e sensíveis
RUN rm -rf \
    .git \
    spec \
    test \
    .env* \
    config/credentials.yml.enc  # Credentials via env vars, não arquivo

# SEGURANÇA: Roda como usuário não-root
USER rails

# Health check para orquestração
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3000/api/v1/health || exit 1

EXPOSE 3000

CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
```

```yaml
# docker-compose.yml (desenvolvimento)
version: "3.9"

services:
  app:
    build: .
    ports: ["3000:3000"]
    environment:
      DATABASE_URL: "postgresql://postgres:${DB_PASSWORD}@db:5432/myapp_dev"
      REDIS_URL: "redis://:${REDIS_PASSWORD}@redis:6379/0"
      SECRET_KEY_BASE: "${SECRET_KEY_BASE}"
    depends_on:
      db:    { condition: service_healthy }
      redis: { condition: service_healthy }
    # SEGURANÇA: Read-only filesystem com tmpfs para escrita temporária
    read_only: true
    tmpfs:
      - /tmp
      - /app/tmp

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: "${DB_PASSWORD}"
      POSTGRES_USER:     "postgres"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test:     ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
    # SEGURANÇA: Não expõe porta do banco externamente
    # expose: ["5432"]  ← apenas internamente

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass "${REDIS_PASSWORD}" --maxmemory 256mb --maxmemory-policy allkeys-lru
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]

volumes:
  postgres_data:
```

---

## 2. CI/CD Pipeline Seguro {#cicd}

```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  RUBY_VERSION: "3.3"
  RAILS_ENV:    test

jobs:
  security-scan:
    name: "🔒 Security Scan"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Brakeman: analisa código Rails em busca de vulnerabilidades
      - name: Run Brakeman
        uses: presidentbeef/brakeman-action@main
        with:
          options: "--format json --confidence-level 2"

      # Bundle Audit: verifica CVEs nas gems
      - name: Bundle Audit
        run: |
          gem install bundler-audit
          bundle audit check --update
          bundle audit --format json > bundle-audit.json

      # Semgrep: SAST (Static Application Security Testing)
      - name: Semgrep Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: "p/ruby p/rails p/owasp-top-ten"

  test:
    name: "🧪 Tests"
    runs-on: ubuntu-latest
    needs: security-scan

    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_PASSWORD: test_password
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"

    steps:
      - uses: actions/checkout@v4
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: ${{ env.RUBY_VERSION }}
          bundler-cache: true

      - name: Setup Database
        env:
          DATABASE_URL: postgresql://postgres:test_password@localhost/test
        run: bundle exec rails db:create db:schema:load

      - name: Run Tests with Coverage
        env:
          DATABASE_URL: postgresql://postgres:test_password@localhost/test
          REDIS_URL:    redis://localhost:6379/0
          SECRET_KEY_BASE: ${{ secrets.TEST_SECRET_KEY_BASE }}
        run: |
          bundle exec rspec --format progress \
                            --format RspecJunitFormatter \
                            --out tmp/rspec.xml

      - name: Check Coverage (mínimo 90%)
        run: |
          coverage=$(cat coverage/.last_run.json | jq '.result.covered_percent')
          if (( $(echo "$coverage < 90" | bc -l) )); then
            echo "Coverage $coverage% abaixo do mínimo de 90%"
            exit 1
          fi

  deploy:
    name: "🚀 Deploy"
    runs-on: ubuntu-latest
    needs: [security-scan, test]
    if: github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v4

      # SEGURANÇA: Secrets apenas em GitHub Secrets — NUNCA no código
      - name: Deploy to Production
        env:
          DEPLOY_KEY:    ${{ secrets.DEPLOY_SSH_KEY }}
          REGISTRY:      ${{ secrets.CONTAINER_REGISTRY }}
        run: |
          # Build e push da imagem com digest
          docker build -t $REGISTRY/myapp:$GITHUB_SHA .
          docker push $REGISTRY/myapp:$GITHUB_SHA

          # Deploy com zero-downtime (rolling update)
          kubectl set image deployment/myapp app=$REGISTRY/myapp:$GITHUB_SHA
          kubectl rollout status deployment/myapp --timeout=5m
```

---

## 3. Gestão de Secrets {#secrets}

```ruby
# REGRA DE OURO: NUNCA commite secrets no repositório

# .env.example (commitar — sem valores reais)
# DATABASE_URL=postgresql://user:password@localhost/myapp_production
# REDIS_URL=redis://:password@localhost:6379/0
# SECRET_KEY_BASE=
# JWT_PRIVATE_KEY=
# JWT_PUBLIC_KEY=
# GOOGLE_CLIENT_ID=
# GOOGLE_CLIENT_SECRET=
# ENCRYPTION_SALT=

# .gitignore — SEMPRE incluir
# .env
# .env.production
# .env.local
# config/master.key
# config/credentials/*.key

# Geração segura de secrets
# rails secret                      # Para SECRET_KEY_BASE
# openssl genrsa -out private.pem 4096  # Chave RSA para JWT
# openssl rsa -in private.pem -pubout -out public.pem

# config/initializers/validate_env.rb
# Falha no boot se variável obrigatória não está definida
module RequiredEnv
  REQUIRED_VARS = %w[
    DATABASE_URL
    REDIS_URL
    SECRET_KEY_BASE
    JWT_PRIVATE_KEY
    JWT_PUBLIC_KEY
    ENCRYPTION_SALT
  ].freeze

  def self.validate!
    missing = REQUIRED_VARS.reject { |var| ENV[var].present? }
    raise "Variáveis de ambiente obrigatórias ausentes: #{missing.join(', ')}" if missing.any?
  end
end

RequiredEnv.validate! if Rails.env.production?
```

---

## 4. Checklist de Produção {#checklist}

```
🔒 SEGURANÇA
✅ config.force_ssl = true
✅ HSTS habilitado (max-age=31536000)
✅ Content Security Policy configurada
✅ SECRET_KEY_BASE aleatória e rotacionada (rails secret)
✅ DB: apenas app user com permissões mínimas (sem SUPERUSER)
✅ Redis com senha e TLS
✅ Brakeman sem warnings de alta severity
✅ bundle audit sem CVEs conhecidas

🚀 PERFORMANCE
✅ Eager loading configurado (Bullet sem N+1)
✅ Índices no banco (EXPLAIN ANALYZE nas queries principais)
✅ Cache configurado (Redis)
✅ CDN para assets estáticos
✅ Gzip habilitado no servidor

📊 OBSERVABILIDADE
✅ Sentry para error tracking
✅ Logs estruturados (JSON) com request_id
✅ Health check endpoint /api/v1/health
✅ Métricas de request (p95, p99 latency)
✅ Alertas para taxa de erro > 1%

🗄️ BANCO DE DADOS
✅ Backups automáticos diários com retenção de 30 dias
✅ Conexão pool configurada (puma threads = DB pool size)
✅ Statement timeout configurado (previne queries longas)
✅ pg_stat_statements para identificar queries lentas
```
