# 🛡️ Ruby on Rails — Skill Completa de Segurança e Programação

Uma **skill para IA (Antigravity / Windsurf)** especializada em Ruby on Rails com foco em segurança avançada, algoritmos, padrões de arquitetura e boas práticas de desenvolvimento backend.

## 📦 Como instalar esta Skill

> As skills são arquivos de conhecimento que o AI assistant lê automaticamente quando você menciona tópicos relacionados ao Ruby on Rails. Elas **não são plugins** — são documentos de referência que o assistente consulta para dar respostas mais precisas.

### Método 1 — Via URL (recomendado)

No Windsurf ou Antigravity, adicione a URL raw do `SKILL.md` como fonte de conhecimento:

```
https://raw.githubusercontent.com/levireis/ruby-on-rails-skill-docs/main/SKILL.md
```

### Método 2 — Clone local

```bash
git clone https://github.com/levireis/ruby-on-rails-skill-docs.git
```

Copie a pasta para o diretório de skills do seu editor/assistente.

---

## 📚 Conteúdo da Skill

| Tópico | Arquivo | Descrição |
|--------|---------|-----------|
| **Skill Principal** | `SKILL.md` | Núcleo com configuração segura, modelos, controllers e JWT |
| **Segurança Avançada** | `references/security.md` | OWASP Top 10, autenticação, criptografia, prevenção de ataques |
| **ActiveRecord & SQL** | `references/activerecord.md` | Queries seguras, migrations, validações, N+1 |
| **API REST & GraphQL** | `references/api.md` | Endpoints, serialização, rate limiting, versionamento |
| **Algoritmos & Padrões** | `references/algorithms.md` | Service Objects, Interactors, Decorators, Strategy |
| **Background Jobs & Cache** | `references/jobs_cache.md` | Sidekiq, Redis, Action Cable, caching |
| **Testes** | `references/testing.md` | RSpec, FactoryBot, specs de unidade e integração |
| **Deploy & Infra** | `references/deploy.md` | Docker, CI/CD, secrets, SSL/TLS |

---

## 🎯 Quando a Skill é ativada

O assistente usa esta skill automaticamente quando você menciona:

- `Rails`, `Ruby on Rails`, `Ruby`
- `ActiveRecord`, `Devise`, `Pundit`
- `API Rails`, `backend Ruby`, `MVC Ruby`
- `RSpec`, `Sidekiq`, `Action Cable`, `Hotwire`
- Qualquer tarefa relacionada a desenvolvimento backend com Ruby

---

## 🔧 Compatibilidade

```yaml
ruby: ">=3.2"
rails: ">=7.1"
tools: [bash, ruby, bundler, postgres, redis]
```

---

## 📋 Tópicos Cobertos

### Segurança
- Configuração base segura (CSP, HSTS, CORS)
- Cabeçalhos HTTP de segurança
- Strong Parameters — proteção contra Mass Assignment
- JWT com RS256, blacklist e refresh token seguro
- Rate limiting e proteção contra brute force
- Autorização com Pundit (princípio do menor privilégio)
- Prevenção de SQLi, XSS, CSRF, IDOR, RCE

### Arquitetura
- Service Objects e Command Pattern
- Interactors com rollback transacional
- Decorators (Draper)
- Strategy Pattern para regras de negócio
- Repository Pattern para abstração de dados

### Qualidade
- RSpec com FactoryBot e Faker
- Request specs para APIs
- Testes de segurança automatizados
- CI/CD com GitHub Actions

---

## 👤 Autor

**Levi Reis** — Criado como material de referência para desenvolvimento Rails seguro e profissional.

---

## 📄 Licença

MIT License — Livre para uso, modificação e distribuição.
