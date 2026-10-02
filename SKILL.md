---
name: security-check
description: Faz review de segurança das mudanças pendentes na branch atual aplicando checklist anti-vibe-coding + OWASP Top 10:2025 + OWASP LLM/Agentic Top 10. Antes de auditar o código, sincroniza com a NVD (nvd.nist.gov), o catálogo KEV da CISA e o GitHub Advisory Database pra processar CVEs novos do stack identificado no projeto (framework, auth, ORM, banco de dados, runtime, automação, servidores MCP...). Use quando quiser auditar brechas antes de fazer deploy, após implementar feature sensível (auth, upload, query, fetch externo, operação financeira, webhook, LLM/agente), ou quando quiser saber se saiu CVE novo relevante pro stack.
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash, Write, Edit
---

# Security Check — Review de Brechas

Você audita as mudanças pendentes na branch atual buscando vulnerabilidades comuns. Combina o foco do `/security-review` (auditar diff da branch) com:
1. **Sincronização com NVD, CISA KEV e GitHub Advisory** (Fase 0) — o stack do projeto é identificado e os CVEs novos dele são processados antes de olhar o código
2. Checklist consolidado de padrões recorrentes de exploração em aplicações web modernas (especialmente "vibe coded")
3. Práticas validadas do **OWASP Top 10:2025**, **OWASP Cheat Sheets**, **OWASP Secure Headers Project**, **OWASP Top 10 for LLM Applications (2025)** e **OWASP Top 10 for Agentic Applications (2026)**

Arquivos da skill (todos relativos a esta pasta):

| Arquivo | Papel |
|---|---|
| `SKILL.md` | este workflow + checklist |
| `scripts/nvd_check.py` | consulta a NVD API 2.0 por termo da watchlist desde a última verificação (KEV + componentes que não são pacote: runtime, banco de dados, cache, serviços self-hosted); imprime digest; `--commit` grava estado |
| `scripts/gh_advisories.py` | consulta o GitHub Advisory Database por **dependência direta** do projeto (`package.json`/lockfile/`requirements.txt`) com range semver exato e diz o que afeta a versão instalada + versão mínima segura (precisa de `gh auth`) |
| `nvd-watchlist.json` | termos consultados (um por componente do stack) — vem com uma lista inicial genérica e é **ajustado ao stack identificado** no passo 0 da Fase 0 |
| `nvd-state.json` | estado máquina: `last_check`, `last_cve_processed`, `processed{id: lastModified}` — só o script escreve |
| `cve-watch.md` | registro humano: última verificação, último CVE processado, tabela de CVEs relevantes por componente com versão mínima segura e o que grepar no código |

## Quando usar

- ANTES de qualquer deploy de feature nova
- Após mexer em: auth, sessão, cookies, upload, query SQL/NoSQL, fetch externo, CORS, operações financeiras/aprovações, webhooks, integração com LLM/agente/MCP
- Quando o usuário pedir "review de segurança", "checa brechas", "audita esse código", "saiu CVE novo?"

## ⛔ Regra inegociável: ZERO mudanças automáticas no projeto auditado

Esta skill **NUNCA** modifica código, configuração, infra, env vars ou dependências **do projeto auditado**. O escopo é **só auditar + reportar**. A skill entrega um **relatório rico** (findings + risco de regressão + ordem sugerida + dependências + modulação) que serve como **insumo para o planejamento nativo do agente** (Claude Code / Codex / outro harness) — a skill não constrói plano de execução próprio, pois isso conflita com o planner do harness.

**Única exceção de escrita:** os arquivos de estado **dentro da pasta desta skill** (`nvd-state.json` via `--commit`, `cve-watch.md`, `nvd-watchlist.json`). Nada fora dela.

Fluxo:

1. **Sincronizar NVD/KEV/GitHub Advisory** (Fase 0) — identificar o stack, processar CVEs novos, registrar o último processado
2. **Auditar** o diff (apenas leitura: `Read`, `Grep`, `Glob`, `Bash` de inspeção)
3. **Entregar o relatório** estruturado (Fase 4)
4. **Aguardar decisão do usuário** sobre quais findings endereçar (todos / só CRÍTICO / fatiar em PRs)
5. A execução em si fica fora da skill — o agente usa o planejamento normal dele com o relatório como contexto

Se o usuário disser "corrige" no meio do relatório, confirmar uma vez: "Quer endereçar todos os CRÍTICOS de uma vez, ou prefere fatiar (ex: auth primeiro, depois input validation)?" — nunca presumir escopo.

## Workflow (5 fases)

### Fase 0 — Identificar o stack e sincronizar NVD + KEV + GitHub Advisory (sempre, antes de olhar o código)

A NVD (https://nvd.nist.gov) é o repositório global de CVEs; o KEV (CISA Known Exploited Vulnerabilities) marca os que já têm exploração ativa. Toda execução da skill começa conferindo se saiu coisa nova desde a última vez.

0. **Identificar o stack do projeto** (varrer antes de consultar): ler os manifestos (`package.json` + lockfile, `requirements.txt`/`pyproject.toml`, `go.mod`, `composer.json`, `Gemfile`), `Dockerfile`/`docker-compose.yml`, `.env.example` e configs de deploy pra listar framework, lib de auth, ORM, banco de dados, cache, fila, runtime, serviços self-hosted e integrações com LLM/MCP. Cruzar com `nvd-watchlist.json` e **adicionar** o que faltar (regras em "Manutenção da watchlist" abaixo). A lista que vem com a skill é só um ponto de partida genérico.
1. **Rodar o script** apontando pro(s) projeto(s) sendo auditado(s) (usa `last_check` de `nvd-state.json`; na primeira vez usa 30 dias):
   ```bash
   SKILL=~/.claude/skills/security-check
   python3 $SKILL/scripts/nvd_check.py --project . --md /tmp/nvd_digest.md
   ```
   - Sem API key: 5 req/30 s → ~6,5 s por termo (~35 termos ≈ 4 min por janela de 119 dias). Com key em `~/.nvd.key` ou `$NVD_API_KEY` é 10x mais rápido (pedir em https://nvd.nist.gov/developers/request-an-api-key — grátis, chega por e-mail).
   - Se a janela desde `last_check` for > 119 dias o script fatia automaticamente (a API limita a 120 dias por consulta).
   - `--since 2026-01-01` força janela; `--terms "Next.js,Supabase"` restringe; `--all` reexibe já processados; `--min-score 7` esconde MEDIUM.
   - O script marca `⚠️ AFETADO` quando o range CPE do CVE bate com a versão declarada/instalada no `package.json`/lockfile. Quando o CVE ainda não tem CPE (status `Received`/`Awaiting Analysis` — comum nas primeiras semanas), ele avisa "match por nome, sem range CPE" → **ler a descrição** e comparar versões manualmente.
   - **1b. Dependências diretas com range exato** (GitHub Advisory Database — cobre o que a NVD ainda não analisou; é a fonte mais confiável pra pacote npm/pip):
     ```bash
     python3 $SKILL/scripts/gh_advisories.py --project . --since <last_check>   # --all mostra também o que não afeta
     ```
     Saída: só advisories cujo range bate com a versão instalada (lockfile) ou declarada, + "mínimo seguro sugerido" por pacote na mesma major, + aviso quando só há patch em outra major. Transitivas ficam com `npm audit`/`pip-audit` (Fase 1). Papel de cada fonte: **GH Advisory** = pacotes do projeto; **NVD** = KEV + componentes de infra (runtime, banco de dados, cache, serviços self-hosted) + padrões novos; **KEV** = prioridade absoluta.
2. **Triar o digest**. Pra cada CVE novo/alterado, decidir uma de três:
   - **Relevante pro stack** → adicionar linha em `cve-watch.md` (tabela do componente) com: CVE, CVSS, versões afetadas, versão corrigida, pré-condição (ex.: "só App Router", "só dev server exposto", "só Windows"), KEV sim/não e **o que grepar no código** pra saber se o projeto está exposto. Se o CVE ensina um **padrão** (ex.: "middleware não é boundary de auth", "`!!session` falha aberto"), adicionar também o item de checklist correspondente na Fase 2.
   - **Relevante mas fora do stack atual** (ex.: React Native) → ignorar; não poluir o registro.
   - **Ruído** (termo ambíguo — "React", "Redis", "Vite" pegam descrições de outros produtos) → ignorar.
3. **Cruzar com o KEV**: o script já marca `KEV` quando a NVD informa `cisaExploitAdd`. Qualquer CVE do stack em KEV com versão afetada no projeto vira finding 🔴 automático no relatório final, independente de estar no diff.
4. **Gravar o estado**: `python3 $SKILL/scripts/nvd_check.py --commit --quiet >/dev/null` (mesmos `--since/--terms` usados na consulta, se usou). Atualizar o cabeçalho de `cve-watch.md` ("Última verificação" / "Último CVE processado" = `last_cve_processed` do estado).
5. **Reportar no início do relatório final** (seção `📡 NVD/KEV`): data da verificação, quantos CVEs novos, quais são relevantes, quais afetam o projeto auditado.

Se a NVD estiver fora do ar (HTTP 503 recorrente), dizer isso explicitamente, **não gravar estado** e seguir pra Fase 1 usando o `cve-watch.md` existente.

**Manutenção da watchlist:** ao auditar um projeto cujo stack traz componente ausente de `nvd-watchlist.json` (framework, ORM, lib de auth, parser de upload, cliente de fila, runtime, banco de dados, serviço self-hosted), adicionar o termo com `note` explicando o motivo técnico. Preferir `cpe` quando a palavra for ambígua em inglês (ex.: express, ai). Pacote npm/pip comum fica com `gh_advisories.py`; a watchlist é pra infra, frameworks com histórico de KEV e termos que revelam padrões novos. Termo que só traz ruído sai da lista.

### Fase 1 — Reconhecimento

Antes de checar qualquer coisa, mapeie o terreno:
- **Stack**: linguagem, framework, ORM, lib de auth, DB, fila, storage, provedor de LLM
- **Trust boundaries**: o que vem do usuário? o que vem de serviços internos? o que vem de webhooks? o que vem de **conteúdo que o LLM lê** (e-mails, páginas, tickets, resultados de tools)?
- **Superfícies críticas**: endpoints de auth, fluxos de pagamento, uploads, rotas admin, chamadas a APIs externas, Server Actions, Route Handlers, webhooks de entrada, integração com LLM/MCP
- **Escopo do diff**:
  ```bash
  git status
  git diff --stat
  git diff main...HEAD --stat 2>/dev/null || git diff origin/main...HEAD --stat 2>/dev/null
  ```
- **Auditoria de dependências** (rodar o que existir; só reportar, nunca `--fix`):
  ```bash
  [ -f package-lock.json ] && npm audit --omit=dev --audit-level=high 2>&1 | tail -40
  [ -f pnpm-lock.yaml ]    && pnpm audit --prod --audit-level=high 2>&1 | tail -40
  [ -f requirements.txt ]  && command -v pip-audit >/dev/null && pip-audit -r requirements.txt 2>&1 | tail -40
  command -v osv-scanner >/dev/null && osv-scanner --lockfile=package-lock.json 2>&1 | tail -40
  command -v gitleaks    >/dev/null && gitleaks detect --no-banner --redact 2>&1 | tail -20
  ```
  A saída de `gh_advisories.py` (Fase 0, 1b) já diz quais dependências diretas estão em range vulnerável e a versão mínima; cruzar com a coluna "versão mínima segura" de `cve-watch.md` (que também cobre infra: runtime, banco de dados, cache, serviços self-hosted). Versão abaixo do mínimo = finding (🔴 se KEV ou CVSS ≥ 9, senão 🟠).

Se houver mudanças staged/unstaged + commits na branch, audite **tudo junto**. Se a branch tem muitos arquivos, priorize por sensibilidade: auth/session > input handling > fetches externos > resto.

### Fase 2 — Auditar contra o checklist

Para cada arquivo modificado, busque os padrões abaixo. Use `grep` e `Read` — não delegue para subagent (queremos verificação direta no diff). As tags `[A0x:2025]` referem-se ao OWASP Top 10:2025.

#### 🔴 Access Control (IDOR + Authz) [A01:2025]
- [ ] Em CADA operação de read/edit/delete: o backend verifica que o usuário autenticado é dono ou tem permissão sobre o resource específico (não confia em ID do request)
- [ ] **IDOR test**: mentalmente trocar o ID do request por outro user — o backend rejeita?
- [ ] **Privilege escalation vertical**: usuário comum não consegue chegar em rota admin
- [ ] **Privilege escalation horizontal**: user A não consegue agir como user B
- [ ] **Path traversal**: endpoints de file/diretório bloqueiam `../` e absolute paths
- [ ] Tokens/sessões invalidados **no servidor** no logout (não só no cliente)
- [ ] **Multi-tenant**: toda query em tabela compartilhada carrega `WHERE tenant_id = ...` derivado da sessão, nunca do body/query string
- [ ] **Open redirect**: `callbackUrl`, `redirect`, `next`, `returnTo` validados contra allowlist de paths relativos (ou mesma origem) — `grep -rn "redirect(\|callbackUrl\|returnTo" <arquivos>`
- [ ] **Host header**: links de reset/magic link/verificação montados a partir de `APP_URL` fixo, nunca de `Host`/`X-Forwarded-Host` (poisoned reset link); frameworks que confiam no `Host` precisam de allowlist (Starlette < 1.0.1, CVE-2026-48710, entrou no KEV em 2026-09-02 → `TrustedHostMiddleware`; Fastify `trustProxy` por IP)

#### 🔴 Business Logic / Insecure Design [A06:2025]
Toda regra de negócio com dinheiro, permissão ou acesso a conteúdo **precisa de validação server-side explícita** — nunca depender só de o frontend esconder um botão. Para CADA feature nova, perguntar: "o que um usuário mal-intencionado tentaria explorar aqui?"
- [ ] **Saldo/estoque nunca negativo**: `UPDATE ... SET saldo = saldo - $1 WHERE user_id = $2 AND saldo >= $1` retornando rows affected
- [ ] **Cupom/código uso único por usuário**: `UNIQUE(user_id, coupon_id)` + check antes de aplicar
- [ ] **Reembolso** dentro do prazo + uma única vez por compra (status enum + janela temporal validada)
- [ ] **Acesso a conteúdo pago**: verificar transação concluída no banco, não só `user.is_premium` cacheado
- [ ] **Ação só pelo dono**: `WHERE resource.owner_id = current_user.id` em toda mutation
- [ ] **Quota/limite por plano**: count atual + max do plano, com lock pra não exceder por race
- [ ] **Toggle de estado** (publicar/arquivar/banir) valida estado anterior (não pode "republicar" o que já está publicado)
- [ ] **Workflow de aprovação**: cada transição checa que o ator tem papel certo E o objeto está no estado anterior esperado
- [ ] **Gate de pagamento por webhook** (Stripe, Mercado Pago, Hotmart, Paddle etc.): status de acesso só muda por evento **assinado e verificado**; a liberação lê o status gravado no banco (fail-closed se o evento não chegou), nunca "libera enquanto o webhook não confirma"

#### 🔴 Auth & Secrets [A07:2025 · A04:2025]
- [ ] `grep -rn "process.env.*||" <arquivos>` — `JWT_SECRET || 'default'` é brecha crítica, deve crashar se não configurado
- [ ] Middleware de auth valida o token de verdade (JWT verify com signature + expiration + audience + issuer), não só checa existência do cookie
- [ ] **Existência ≠ autenticado**: check de sessão testa um campo concreto (`session?.user?.id`), nunca `if (session)` / `!!auth` — libs devolvem objeto de erro truthy quando a config quebra (Auth.js CVE-2026-73421, ver `cve-watch.md`)
- [ ] Cookies: `httpOnly: true`, `secure: true` em prod, `sameSite: 'strict'` ou `lax`; prefixo `__Host-` quando possível
- [ ] **CSRF** em toda rota state-changing autenticada por cookie que não seja Server Action (Route Handlers, Express/Fastify): token sincronizado ou double-submit + checagem de `Origin`/`Sec-Fetch-Site`
- [ ] **Password hashing**: Argon2id (m=19MiB, t=2, p=1) ou bcrypt 10+ rounds — sinalizar qualquer MD5/SHA-1/SHA-256 puro [OWASP]
- [ ] **Anti-enumeração**: mensagens genéricas em login ("credenciais inválidas"), registro ("se este email não está registrado, você receberá um link") e recuperação de senha ("se este email está registrado, enviaremos instruções")
- [ ] **Normalização de e-mail antes da validação**: NFKC + lowercase **antes** de validar formato e de comparar com o banco; rejeitar não-ASCII se i18n não for requisito (homoglyph de `@` → account takeover via magic link, Auth.js CVE-2026-73420)
- [ ] **Rate limiting** em login com lockout progressivo (por IP **e** por conta)
- [ ] **Access tokens curtos**: 15-30 min (sensíveis: 5-15 min) [OWASP]
- [ ] **Refresh token rotation** implementado (single-use, novo refresh emitido a cada uso) [OWASP]
- [ ] **CSPRNG** para gerar tokens/session IDs/códigos (`crypto.randomBytes`, não `Math.random()`)
- [ ] **Constant-time comparison** para validar tokens (`crypto.timingSafeEqual`, não `===`) — anti timing attack
- [ ] **Session ID regenerado** após login ou mudança de privilégio (anti session fixation)
- [ ] **Resposta timing-safe** em login/registro/recuperação de senha — mesma duração para usuário existente vs inexistente (usar processamento assíncrono ou delay artificial). Diferente de constant-time compare: aqui é tempo total da rota, anti-enumeração via side channel
- [ ] **Magic link / OTP em conta ainda não verificada**: ao provar posse do e-mail, **apagar senha e sessões criadas antes da verificação** e só então marcar verificada (pre-account hijacking: atacante cadastra o e-mail da vítima com senha, vítima entra por magic link, senha do atacante continua valendo — Better Auth GHSA-qq9h-g4jm-xgf3); OAuth auto-link só com e-mail verificado no provider
- [ ] **OAuth**: `state` + `nonce` + PKCE obrigatórios e **vinculados ao provider** que os emitiu; `redirect_uri` exato (sem wildcard); lib de auth na versão mínima de `cve-watch.md`
- [ ] **MFA** disponível para ações sensíveis (acesso admin, mudança de senha/email, operações financeiras) — TOTP/WebAuthn quando viável; sinalizar como 🟡 quando ausente
- [ ] Nunca logar passwords, tokens, keys, dados de cartão
- [ ] **Segredos não vazam pro bundle**: `grep -rn "NEXT_PUBLIC_\|VITE_\|PUBLIC_" .env* src/` — qualquer key/secret/token com esse prefixo vai pro navegador. `service_role`, `*_SECRET`, `*_PRIVATE_KEY` nunca podem ter prefixo público

#### 🔴 Input Validation & Injection [A05:2025]
- [ ] `grep -rn "sql.raw\|sql\`\|\$queryRawUnsafe\|\$executeRawUnsafe\|sql.raw(" <arquivos>` — qualquer interpolação de input em raw SQL é red flag (Prisma `$queryRaw` com tagged template OK; `Unsafe` com string concatenada não)
- [ ] **Identificadores SQL dinâmicos** (`ORDER BY`, nome de coluna/tabela/alias vindo do request): allowlist mapeando input → nome conhecido; nunca `sql.identifier(input)` / `.as(input)` (Drizzle CVE-2026-39356 escapava mal o delimitador) nem interpolar em raw
- [ ] **NoSQL injection**: validar que input não tem operadores como `$where`, `$regex`, `$ne` (MongoDB)
- [ ] Queries LIKE escapam `%`, `_`, `\` antes de usar
- [ ] **Mass assignment**: nunca `data: { ...body }` / `Object.assign(entity, req.body)` — schema `zod` com campos explícitos (`.strict()`), e campos como `role`, `is_admin`, `owner_id`, `price`, `status` nunca vêm do cliente
- [ ] **Prototype pollution**: `lodash.merge`/`deepmerge`/`Object.assign` recursivo com JSON de usuário → bloquear chaves `__proto__`, `constructor`, `prototype` (ou usar `structuredClone` + schema)
- [ ] **XSS**: `grep -rn "innerHTML\|dangerouslySetInnerHTML\|v-html" <arquivos>` — qualquer um desses com dado de usuário é red flag
- [ ] **Command injection**: nenhum `exec()`, `eval()`, `shell_exec()`, `child_process` com input do usuário; se inevitável, `execFile` com array de args
- [ ] **ReDoS**: regex aplicada em input de usuário sem limite de tamanho e com quantificadores aninhados (`(a+)+`, `(.*)*`) — preferir `zod` com `.max()` antes do `.regex()`
- [ ] Uploads validam **Magic Bytes** do arquivo, não só MIME type do header
- [ ] Server tem `bodyLimit` definido (default 1MB para JSON) e limite de profundidade/array em parsers
- [ ] **Validação de body não é só o schema do framework**: Fastify < 5.8.5 pulava validação com `Content-Type` com espaço/tab à esquerda, < 5.12.1 entregava valor não coagido em schema primitivo na raiz, e `trustProxy: <número>` aceitava `X-Forwarded-*` forjado → revalidar tipo no handler, schema sempre objeto na raiz, `trustProxy` por IP/CIDR
- [ ] Validação de comprimento de URLs (max 2048 chars) e campos de texto (max length explícito)
- [ ] **Pagination com max page_size** — nunca permitir requisitar 999999 records
- [ ] Rate limiting granular em rotas sensíveis (login, upload, financeiro, endpoints que chamam LLM)

#### 🔴 SSRF Protection (qualquer fetch que use URL de input) [A01:2025]
- [ ] Bloqueia RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- [ ] Bloqueia loopback: `127.0.0.0/8`, `::1`, `localhost`
- [ ] Bloqueia link-local `169.254.0.0/16` (metadata AWS/GCP) e CGNAT `100.64.0.0/10`
- [ ] Timeout curto (10s) em fetches externos
- [ ] Verifica IP **após** DNS resolution (anti DNS rebinding)
- [ ] URLs validadas em protocolo (`https://` only, nunca `file://` ou `gopher://`) e domínio (allowlist quando possível)
- [ ] **URLs de imagem fornecidas pelo usuário** (avatar externo, embed, link preview, OG image) servidas via **proxy próprio de imagem** (Camo, go-camo ou equivalente) que: (a) anonimiza IP do usuário final, (b) faz validação SSRF no fetch, (c) limita número de redirects, (d) força HTTPS, (e) define tamanho máximo. Nunca embedar URL externa diretamente no `<img src>`.
- [ ] **Next.js `images.remotePatterns`** sem `hostname: '**'` — o otimizador `/_next/image` vira proxy SSRF/DoS aberto
- [ ] **Envio de e-mail** (nodemailer): transporter com `disableFileAccess: true` + `disableUrlAccess: true`; `raw`, `path`, `href` de anexo/corpo **nunca** vindos do usuário (CVE-2026-82659: `raw` ignorava as flags → leitura de arquivo + SSRF); nodemailer ≥ 9.1.1

#### 🔴 Race Conditions
- [ ] `grep -rn "findOne\|findFirst\|SELECT" <arquivos>` seguido de update — read-then-write em dados concorrentes precisa ser atômico
- [ ] **Atomic UPDATE com WHERE**: `UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1` (em vez de SELECT depois UPDATE)
- [ ] **SELECT FOR UPDATE** dentro de transaction quando precisar ler antes de escrever
- [ ] **UNIQUE CONSTRAINT** no DB como camada extra para coupons single-use, likes, slugs únicos
- [ ] **Idempotency keys** em endpoints de pagamento (cliente envia UUID, servidor cacheia resultado por 24h)
- [ ] **Optimistic locking** com coluna `version` para resources não-financeiros (documentos, configs)
- [ ] Postgres: usar `jsonb || jsonb` para merge atômico de metadata, não ler→modificar→escrever

**Cenários que DEVEM ter proteção contra check-then-act** (não só financeiro):
- Compras, pagamentos, transferências, saques
- Cupons/descontos/promoções de uso único
- Reembolsos e estornos
- **Curtidas, votos, follows, toggles** (like/unlike, follow/unfollow) — sem UNIQUE pode duplicar
- **Criação de recursos únicos** (username, slug, email, handle) — `UNIQUE CONSTRAINT` obrigatório no DB
- **Upgrades/downgrades de plano** (prorate + ativação atômica)
- **Links de convite, tokens de reset, magic links** de uso único (marcar consumido na mesma TX que aceita)
- **Reservas/agendamentos** que dependem de slot disponível
- **Webhooks reentregues** (mesmo `event_id` chegando 2x) — processar uma vez só

#### 🔴 Secrets & Configuration [A02:2025]
- [ ] Nenhum API key, token ou password em código-fonte ou commit history (`git grep -i "password\|secret\|token\|api_key"`; `git log -p --all -S "sk-" -- . | head` para chaves em commits antigos)
- [ ] `.env` e `.env.local` em `.gitignore`, `.env.example` com valores fictícios
- [ ] Sem credenciais default em qualquer environment
- [ ] Sem stack traces em error responses de prod
- [ ] Endpoints de debug (`/debug`, `/__status`) desabilitados em prod
- [ ] **Directory listing desabilitado** no webserver (Apache `Options -Indexes`; nginx é default-off — confirmar reverse proxy / static server / S3 bucket)
- [ ] **Ambientes não-prod (dev/staging/preview) não acessíveis publicamente**: auth básica, IP allowlist, VPN, ou domínio sem indexação. **Dev server (Vite/Next) nunca com `--host`/`0.0.0.0` em máquina exposta** (Vite CVE-2025-31125 em KEV é só dev server, mas está em KEV; Vite 7/8 tiveram mais 3 bypasses de `server.fs.deny` em 2026), nem `vitest --ui`/`--api` escutando na rede (CVE-2026-47429, 9.8: lê e executa arquivo arbitrário)
- [ ] DB roles com mínimo privilégio por serviço (read-only quando não precisa escrever)
- [ ] Container não roda como root
- [ ] **Redis/Postgres/filas só na rede privada** (rede privada do provedor, sem porta pública) e com senha; BullMQ/Bull Board e painéis de admin atrás de auth

#### 🔴 Next.js / React Server Components (quando o projeto usa Next.js)
- [ ] **Middleware não é boundary de auth** (CVE-2025-29927 e mais **5 bypasses só em 2026**: i18n, segment-prefetch, injeção de parâmetro de rota dinâmica, Turbopack — CVE-2026-44573/44574/44575/45109/64642): toda page/layout/Route Handler/Server Action reverifica sessão numa Data Access Layer (`server-only` + função `verifySession()`), o middleware é só redirecionamento de UX
- [ ] **Server Actions são endpoints HTTP públicos**: cada action revalida auth + authz + input (`zod`) como se fosse uma API; nada de confiar em "só é chamada pelo botão X". Arquivos `'use server'` exportam **apenas** as actions (helper exportado por engano vira endpoint)
- [ ] **Props server→client não vazam segredo**: objeto inteiro do usuário/tenant passado como prop pra Client Component vai serializado pro HTML; passar só os campos necessários (ou usar `experimental_taintObjectReference`/`taintUniqueValue`)
- [ ] **`server-only`** importado em módulos de acesso a dados/segredos (falha o build se cair no bundle do cliente)
- [ ] **React Flight/RSC na versão corrigida** (React2Shell CVE-2025-55182, CVSS 10, RCE não autenticado no App Router): `react-server-dom-*` ≥ 19.0.1/19.1.2/19.2.1 e `next` na versão mínima de `cve-watch.md`
- [ ] **Otimizador de imagem** (`/_next/image`) decodifica arquivo não confiável com sharp/libvips/libheif — RCE não autenticado via AVIF (GHSA-2xp9-vwfh-vxw4, CVSS 9.5, corrigido em 15.5.24/16.3.3) e DoS via SVG/remotePatterns: `images.remotePatterns` fechado (host + pathname), `dangerouslyAllowSVG: false`; sem poder atualizar → `images.formats: ['image/webp']` (sem `image/avif`) ou `images.unoptimized: true`
- [ ] **Revalidação on-demand** (`revalidateTag`/`revalidatePath` em Route Handler) exige secret comparado com `timingSafeEqual`
- [ ] **Draft/Preview Mode** só ativável com secret; `draftMode().disable()` no logout
- [ ] **Cache**: respostas autenticadas nunca em cache compartilhado (`dynamic = 'force-dynamic'` ou `noStore()`; `Cache-Control: private`), e nenhum header de request controla a chave de cache sem `Vary`
- [ ] **`headers()` em `next.config`** (ou middleware) entrega os headers da seção 🟠 abaixo; `poweredByHeader: false`
- [ ] Proxy/CDN à frente **remove** `x-middleware-subrequest` e demais `x-middleware-*` de entrada (defesa em profundidade)

#### 🔴 Supabase (quando o projeto usa `@supabase/*`)
- [ ] **RLS habilitado em TODA tabela** do schema `public` (`select relname from pg_class join pg_namespace ... where relrowsecurity = false`) — tabela sem RLS é leitura/escrita pública via anon key
- [ ] Policies usam `auth.uid()`/`auth.jwt()`; nada de `USING (true)` em tabela com dado de usuário
- [ ] **`service_role` key só no servidor** (nunca em `NEXT_PUBLIC_`, nunca em client component, nunca em Edge Function chamada pelo browser sem verificar JWT)
- [ ] Storage: buckets privados por default; policies por pasta/usuário; URLs assinadas com expiração curta
- [ ] `@supabase/ssr` com cookies `httpOnly` configurados; sessão validada com `getUser()` (bate no servidor), não só `getSession()` (lê o cookie sem verificar)
- [ ] Views/functions `SECURITY DEFINER` revisadas (bypassam RLS)

#### 🟠 Security Headers (todos no response, validar com helmet ou equivalente) [A02:2025]
Lista validada [OWASP Secure Headers Project]:
- [ ] **Content-Security-Policy** — restritivo: `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` (Next.js: nonce por request via middleware)
- [ ] **Strict-Transport-Security**: `max-age=63072000; includeSubDomains; preload` (2 anos)
- [ ] **X-Frame-Options**: `DENY` (ou usar `frame-ancestors` no CSP)
- [ ] **X-Content-Type-Options**: `nosniff`
- [ ] **Referrer-Policy**: `strict-origin-when-cross-origin`
- [ ] **Permissions-Policy**: `geolocation=(), camera=(), microphone=(), payment=(), usb=()`
- [ ] CORS com origin explícita, nunca `*` com credentials, **nunca refletir o `Origin` recebido** (equivale a `*`), sem localhost em prod
- [ ] SSE/EventSource com `withCredentials: true` + `Access-Control-Allow-Credentials: true`
- [ ] TLS 1.2+ only (TLS 1.0/1.1 desabilitados)

#### 🟠 File Upload
- [ ] MIME type validado por **magic bytes**, não só header (lib `file-type` na versão mínima de `cve-watch.md`)
- [ ] Tamanho máximo enforced (também na policy do presigned URL S3/R2: `content-length-range` + `Content-Type` fixo)
- [ ] **Allowlist** de tipos permitidos (não blocklist); **SVG é código** (XSS) — ou proibir, ou servir com `Content-Security-Policy: sandbox` e `Content-Disposition: attachment`
- [ ] Imagens **re-encodadas** no servidor (sharp/ImageMagick com policy) — mata polyglots e metadata (GPS/EXIF)
- [ ] Filename original descartado, substituído por UUID; key no bucket prefixada por tenant/usuário
- [ ] Armazenado fora do webroot (S3, GCS, etc.), bucket privado, download via URL assinada
- [ ] Webserver não pode executar arquivos do upload directory
- [ ] Parsers de documento (PDF.js/`pdfjs-dist`, mammoth, xlsx/exceljs, papaparse, file-type) rodam com limite de tamanho/tempo, em worker/processo isolado, e na versão mínima de `cve-watch.md`; PDF.js com `isEvalSupported: false` (CVE-2026-16633: JS arbitrário ao abrir PDF malicioso); mammoth ≥ 1.11.0 (directory traversal)

#### 🟠 Webhooks & Supply Chain [A03:2025 · A08:2025]
- [ ] **Webhooks validam signature/origin** (HMAC, header `X-Hub-Signature-256` Meta/GitHub, `hottok` Hotmart, `Stripe-Signature`) com `timingSafeEqual` sobre o **raw body** (antes de parsear JSON)
- [ ] **Anti-replay**: timestamp na assinatura com tolerância (5 min) + dedupe por `event_id` (UNIQUE)
- [ ] Webhook de entrada no n8n com **autenticação** (Header Auth/HMAC) ou path aleatório longo; nunca "Respond with all execution data"
- [ ] Lockfile commitado (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) e CI usando `npm ci`
- [ ] `npm audit` / `pip-audit` sem HIGH/CRITICAL (ver Fase 1)
- [ ] **Scripts de install desabilitados** em CI/prod (`npm ci --ignore-scripts` / `.npmrc ignore-scripts=true`) e **cooldown de versão nova** (ex.: `minimumReleaseAge` no pnpm) — worms npm 2025 (Shai-Hulud, s1ngularity) se espalharam por postinstall de versão recém-publicada
- [ ] **SRI hashes** em scripts carregados de CDN (`<script integrity="sha384-...">`)
- [ ] Sem deserialização de dados não-confiáveis sem validação estrita
- [ ] **CI/CD tratado como código privilegiado**: workflows em `.github/workflows/*` (ou equivalente) passam por code review como qualquer outro código; **actions de terceiros pinadas por SHA**, não por tag (tj-actions/changed-files 2025)
- [ ] **Secrets no pipeline em store dedicado** (GitHub Secrets, Vault, KMS) — nunca em variável de pipeline editável por contribuidores
- [ ] **Segregação de permissões** entre estágios de build/test/deploy (build não pode fazer deploy; PR de fork não tem secrets; `permissions:` mínimo no workflow)
- [ ] **Artefatos assinados** quando viável (cosign/sigstore, SLSA L2+) — anti SolarWinds-style supply chain attack
- [ ] **SBOM gerado** no build (CycloneDX/SPDX) para rastreabilidade de dependências

#### 🟠 Exception Handling & Fail Closed [A10:2025]
- [ ] **Global exception handler** ativo — toda exceção não capturada vira `5xx` genérico, **nunca expõe** stack trace, SQL query, path de arquivo ou nome de tabela
- [ ] **Fail closed em auth/authz**: exceção dentro de check de permissão → negar acesso, nunca conceder por default. Verificar todos `try/catch` em rotas autenticadas
- [ ] **Erro de configuração = deploy quebrado**, não "app sobe sem auth": secret faltando, provider mal configurado ou DB indisponível derruba o boot (health check falha), em vez de a lib devolver objeto de erro que passa em `if (session)`
- [ ] Header malformado (`Authorization: Bearer` sem token, JWT truncado) devolve 401, não 500 (uncaught exception vira DoS barato — Auth.js CVE-2026-73418)
- [ ] Sem `catch (_) {}` / `except: pass` engolindo exceções silenciosamente em rotas de produção
- [ ] Mensagens de erro pro cliente são genéricas (`"Erro ao processar"`); detalhes vão pro log estruturado, não pro response
- [ ] Comportamento testado com: payload malformado, body vazio, encoding inválido, serviço dependente fora do ar, timeout de DB, payload acima do limit
- [ ] Erros em batch/job background não silenciam falhas — alertam ou marcam item como `failed`, nunca como `success`

#### 🟠 n8n (instância self-hosted — quando o diff toca workflow, webhook ou credencial)
- [ ] **Versão ≥ 1.122.0** (CVE-2025-68613 em KEV: expression injection → RCE por usuário autenticado; ver `cve-watch.md` para os posteriores). A versão não aparece em `/rest/settings` público — conferir em Settings → About ou na tag da imagem do container
- [ ] **Expressões nunca montadas a partir de input externo** (webhook body/query dentro de `{{ }}` ou Code node via `eval`) — tratar payload de webhook como string opaca
- [ ] `N8N_BLOCK_ENV_ACCESS_IN_NODE=true`, `N8N_RUNNERS_ENABLED=true` (Code node isolado em task runner), `NODES_EXCLUDE` com `n8n-nodes-base.executeCommand` e `n8n-nodes-base.readWriteFile` se não forem necessários
- [ ] **Community nodes**: instalar só o que é indispensável e de autor conhecido (conferir se `communityNodesEnabled` está ligado) — é supply chain com acesso total às credenciais
- [ ] Owner com 2FA; API key da Public API com rotação e escopo; uma key por integração, com registro de quem usa
- [ ] Webhooks de entrada com auth (Header Auth/HMAC) e resposta mínima; credenciais sensíveis (banco de dados, gateway de pagamento, CRM) com `allowedHttpRequestDomains` restrito
- [ ] Workflows que gravam em banco: cada aplicação no seu próprio banco de dados e usuário de banco, com privilégio mínimo

#### 🟠 AI / LLM / Agentes (OWASP LLM Top 10:2025 · Agentic Top 10:2026)
- [ ] **Prompt injection direta e indireta** [LLM01/ASI01]: input do usuário **e tudo que o modelo lê** (e-mail, página, ticket, resultado de tool, arquivo) entram como **dado delimitado**, nunca concatenados na instrução; instruções encontradas no conteúdo são ignoradas por design (e testadas)
- [ ] **Mínimo privilégio nas tools** [LLM06/ASI02/ASI03]: tool que lê não escreve; credencial da tool é da aplicação com escopo mínimo, nunca a do usuário-admin; ações irreversíveis (pagar, deletar, enviar e-mail/WhatsApp, deploy) exigem **confirmação humana** ou vão pra fila com aprovação
- [ ] Nenhum `bypassPermissions`, `--approval-mode yolo`, `--dangerously-skip-permissions`, `sandbox: false` em produção [ASI05]
- [ ] **Output do LLM é input não-confiável** [LLM05]: sanitizado antes de renderizar (markdown → `rehype-sanitize`/DOMPurify, sem HTML cru, protocolos de link allowlist), antes de executar (nunca `eval`/shell/SQL gerado sem parametrização) e antes de virar chamada de tool (schema `zod` estrito)
- [ ] **Segredos fora do system prompt** [LLM07]: o prompt é considerado público; segredos/regra de negócio crítica ficam no código
- [ ] **Limites de consumo** [LLM10]: max tokens, max turnos/iterações do agente, timeout, orçamento por usuário/dia, rate limit no endpoint de chat (custo é vetor de DoS)
- [ ] **Memória/RAG** [LLM08/ASI06]: escrita na memória do agente ou no índice vetorial só de fontes autenticadas; documentos com ACL filtrados **antes** do retrieval (não depois); conteúdo recuperado tratado como não-confiável
- [ ] **MCP servers** [ASI04/ASI07]: transporte HTTP com auth (OAuth 2.1/bearer) — nunca `0.0.0.0` sem auth; **uma instância de `McpServer` + transporte por requisição/sessão** (compartilhar entre clientes cruza respostas e notificações entre eles — CVE-2026-25536, SDK < 1.26.0); `enableDnsRebindingProtection: true` explícito (SDK < 1.24.0 não ligava por padrão) e validar `Host`/`Origin` em servidor local; tool descriptions/schemas **pinados por hash** (tool poisoning/rug pull); servidor de terceiro instalado só de fonte confiável e versão fixa; resultado de tool não é instrução
- [ ] **Fallback e isolamento entre provedores/agentes** [ASI08]: erro de um provider degrada com mensagem genérica, sem vazar prompt/ferramenta; agentes que se comunicam autenticam mensagens entre si
- [ ] Interações do LLM com dado de usuário logadas (prompt hash, tools chamadas, decisão) — sem PII crua no log

#### 🟡 Logging & Monitoring [A09:2025]
- [ ] **Formato estruturado JSON** com schema consistente — facilita SIEM/ingest, reduz log injection. Fields recomendados pelo OWASP Logging Vocabulary: `datetime`, `level`, `event`, `appid`, `userId`, `sourceIP`, `userAgent`, `action`, `resource`, `result`, `requestId`
- [ ] **Prefixos de evento consistentes**: `authn:login_success`, `authn:login_failure`, `authz:denied`, `input:validation_failed`, `excess:rate_limit_hit`, `txn:payment_attempt`
- [ ] **Sanitizar input antes de logar** (anti log injection): escapar `\n`, `\r`, control chars que poluem multilinhas
- [ ] Login failures logados com IP + user-agent + timestamp
- [ ] Operações financeiras logadas com `userId + action + amount + resourceId + result`
- [ ] Access denied events logados (tentativas de IDOR/escalação são sinal de ataque)
- [ ] Mudanças de permissão/papel logadas
- [ ] Nenhum password/token/PII sensível nos logs
- [ ] Logs em local tamper-resistant (append-only, WORM storage, ou SIEM com retenção)
- [ ] **Alerta** (não só log) para: pico de `authz:denied`, falha de assinatura de webhook, erro de config de auth, custo de LLM acima do orçamento

#### 🟡 Privacidade & Dados Pessoais (LGPD/GDPR — condicional)
Aplicar quando a aplicação coleta/processa dados pessoais (qualquer app com cadastro de usuário). Validar contra o stack atual:
- [ ] **Minimização de coleta**: cada campo armazenado tem uso explícito numa feature — se não, remover
- [ ] **Endpoint "ver meus dados"** (auth obrigatória, agrega de todas as tabelas que referenciam o user)
- [ ] **Endpoint correção** dos próprios dados
- [ ] **Endpoint exclusão/anonimização** com tratamento de dependências (FK orphans, cascade vs anonimize, manter dados agregados sem PII)
- [ ] **Endpoint exportação portável** em formato comum (JSON/CSV/XML) — GDPR Art. 20; prazo 1 mês (GDPR) / 15 dias (LGPD)
- [ ] **Endpoint revogar consentimento** (cookies, marketing, share com terceiros)
- [ ] **Logs e backups na política de retenção**: deletar do banco principal não basta — definir TTL em logs/backups que contêm PII
- [ ] **Dados sensíveis** (saúde, biometria, religião, orientação, dados financeiros, documento oficial/CPF) → criptografia em repouso adicional + acesso auditado; documento oficial usado como chave de busca armazenado com hash/índice cego quando só serve pra lookup
- [ ] **Dados pessoais enviados a LLM/terceiros** (provedor de modelo, transcrição, e-mail marketing) listados como operadores; PII minimizada/pseudonimizada no prompt
- [ ] **Notificação de incidente** documentada (quem, quando, autoridades; LGPD/ANPD e GDPR/DPA)

#### 🟢 Defesas Extras
- [ ] **Honey pots**: rotas falsas que logam acessos:
  ```
  /admin, /wp-admin, /phpmyadmin, /.env, /config, /api/v1/internal, /admin-panel
  ```
- [ ] Delay (2-3s) em honey pots para desperdiçar tempo do atacante
- [ ] Logging de IP, user-agent e headers em acessos suspeitos

#### CVEs específicos do stack
A lista viva está em **`cve-watch.md`** (mantida pela Fase 0). Os que viraram **padrão de checklist** (não basta atualizar a versão, o código pode repetir o erro):
- [ ] **Next.js middleware bypass** (CVE-2025-29927, corrigido em 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3; afeta self-hosted `next start`/standalone com middleware — Vercel/Netlify/export estático não): auth verificada além do middleware — ver bloco Next.js
- [ ] **React2Shell** (CVE-2025-55182, KEV, CVSS 10): `react-server-dom-*` e `next` acima do mínimo; qualquer App Router exposto é alvo sem auth
- [ ] **Auth.js fail-open** (CVE-2026-73421): `next-auth` ≥ 5.0.0-beta.32 **e** nenhum `if (session)`/`!!auth` sem campo concreto
- [ ] **Auth.js homoglyph e-mail** (CVE-2026-73420): `@auth/core` ≥ 0.41.3 / `next-auth` ≥ 4.24.15; normalizar antes de validar em qualquer fluxo de e-mail próprio
- [ ] **n8n expression injection** (CVE-2025-68613, KEV): instância ≥ 1.122.0; expressões nunca de input externo
- [ ] **Next.js image optimizer AVIF RCE** (GHSA-2xp9-vwfh-vxw4): `next` ≥ 15.5.24 / 16.3.3 em **todas** as plataformas (não é só Windows) — o mesmo bug de libheif atinge Astro (< 7.2.8) e qualquer app com `sharp` < 0.35.4 decodificando upload
- [ ] **MCP SDK compartilhado entre clientes** (CVE-2026-25536): SDK ≥ 1.26.0 **e** server/transporte por sessão
- [ ] **Drizzle identifiers** (CVE-2026-39356): ≥ 0.45.2 **e** allowlist em qualquer `sql.identifier`/`.as`
- [ ] **MCP servers**: validar integridade de tool schemas (tool poisoning, session hijacking); SDK na versão mínima de `cve-watch.md`

### Fase 3 — Self-check (16 perguntas, antes de fechar o report)

Para cada feature/endpoint mexido, mentalmente simule:

1. E se eu trocar o ID por outro de um user diferente?
2. E se eu mandar 100 requisições idênticas em paralelo?
3. E se eu mandar um campo com 1 milhão de caracteres?
4. E se eu colocar `<script>alert(1)</script>` em qualquer campo?
5. E se eu mandar `' OR 1=1 --` em qualquer campo?
6. E se eu acessar o endpoint sem estar logado?
7. E se eu forjar/manipular o token?
8. E se eu mandar uma URL externa onde se espera uma interna?
9. E se eu tentar a mesma operação financeira 2x ao mesmo tempo?
10. E se eu acessar/editar/deletar um resource que não é meu?
11. E se eu fizer upload de `.exe` renomeado pra `.jpg`?
12. E se eu inspecionar a response e achar dados de outros users?
13. E se eu chamar a Server Action / Route Handler direto com `curl`, sem passar pela UI?
14. E se o provedor de auth estiver mal configurado em prod (secret ausente) — o check falha **fechado** ou aberto?
15. E se eu reenviar o mesmo webhook (replay) ou mandar um com assinatura inválida?
16. E se o LLM ler uma instrução escondida no dado que ele processa (e-mail, página, resultado de tool)? Que tool ele consegue acionar com isso?

Se alguma pergunta não tem resposta clara no código, é um achado.

### Fase 4 — Reportar (insumo para o planner do agente)

**A skill encerra aqui.** O relatório precisa ser rico o suficiente para que o usuário decida o escopo e o agente use seu planejamento nativo (Claude Code / Codex) para executar — não duplicar o planner do harness.

Cada finding deve trazer **fix + risco de regressão + dependências + esforço + tarefas humanas associadas**:

```
[ID] [CATEGORIA] Severidade: 🔴 CRÍTICO | 🟠 ALTO | 🟡 MÉDIO | 🟢 INFO
Arquivo: <arquivo:linha>
Evidência: <snippet de código>
Por que importa: <impacto em 1 frase — o que o atacante consegue>
Cenário de ataque: <como o atacante explora>
Fix sugerido: <mudança concreta de código/config — ou "tarefa humana" se não for editável por agente>
Risco de regressão: <o que pode quebrar ao aplicar: contrato de API alterado, migration necessária, testes que vão exigir update, header novo que pode quebrar consumidor X, comportamento que clientes assumem>
Dependências: <IDs de findings que precisam vir antes, OU "nenhuma">
Esforço: S (≤1h) | M (≤4h) | L (>4h, exige refactor)
```

Estrutura do report final:

```
## Security Check — <branch>

### 📡 NVD/KEV
- Verificação: <data/hora> · janela desde <last_check anterior> · CVEs novos/alterados: N · relevantes pro stack: M (registrados em cve-watch.md)
- Afetam ESTE projeto: <lista CVE · pacote@versão instalada → mínima segura · KEV sim/não> (ou "nenhum")
- Último CVE processado: <id>

### Sumário
- N findings: X 🔴 / Y 🟠 / Z 🟡 / W 🟢
- Arquivos auditados: <count>
- Áreas de maior risco: <auth | input | race | etc>

### 🔴 CRÍTICO (bloqueia deploy)
<findings com formato acima — inclui dependência em KEV/CVSS ≥ 9 com versão afetada>

### 🟠 ALTO (corrigir antes do próximo release)
...

### 🟡 MÉDIO
...

### 🟢 RECOMENDAÇÕES
...

### 📦 Modulação sugerida (fases independentes para corrigir em PRs separados)

Quando há muitos findings, agrupar em fases lógicas que possam ser mergeadas separadamente. Princípio: dentro de uma fase, mudanças são coesas e baixo acoplamento; entre fases, respeitar dependências.

Exemplo de agrupamento (ajustar ao stack real):
- **Fase A — Dependências com CVE**: bump de versão, sem refactor, deploy isolado → [F1]
- **Fase B — Segredos & Config**: não-funcional, baixo risco → [F2, F5]
- **Fase C — Headers & TLS**: incrementável, sem refactor → [F3, F8]
- **Fase D — Auth & Sessão**: alto impacto, exige testes de regressão → [F4, F7, F9]
- **Fase E — Input validation & Race conditions**: pode mudar contrato → [F6, F10, F11]
- **Fase F — Privacidade & Compliance**: endpoints novos, sem refactor → [F12, F13]

Ordem sugerida de execução: A → B → C → D → E → F (justificar quando divergir).

### ⚠️ Análise de regressão agregada
Lista de superfícies que podem quebrar e exigem atenção redobrada em testes:
- Endpoints com mudança de contrato (body/response/status)
- Migrations de schema necessárias (com plano de backfill se aplicável)
- Comportamentos que clientes assumem (TTL de token, rate limit, formato de erro)
- Headers novos que podem quebrar consumidores específicos (CSP em SPA com inline scripts, etc.)
- Bumps de major (Next 15→16, Prisma 6→7, zod 3→4) que exigem migração de API
- Testes existentes que provavelmente vão falhar e precisam atualizar

### 🧑 Tarefas que SOMENTE o humano pode fazer
(O agente pode até preparar PR, mas não consegue executar essas — listar explicitamente para não passarem despercebidas.)
- [ ] Rotacionar secrets vazados (KMS/Vault/CI)
- [ ] Atualizar serviços self-hosted (n8n, banco de dados, imagens de container) no provedor de hospedagem
- [ ] Configurar/atualizar WAF / CDN rules
- [ ] Criar role de DB com least-privilege e migrar serviços
- [ ] Habilitar RLS / revisar policies no painel do Supabase
- [ ] Provisionar provider de MFA (Auth0/Clerk/TOTP server)
- [ ] Habilitar assinatura de artefatos no CI (cosign/sigstore)
- [ ] Aprovar política de retenção de logs/backups (compliance/legal)
- [ ] Comunicar usuários afetados se houve vazamento
- [ ] Notificar autoridade (ANPD/DPA) se incidente reportável
- [ ] Atualizar Política de Privacidade / Termos
- [ ] Configurar alertas no SIEM para novos eventos logados
- [ ] Pedir API key da NVD (acelera a Fase 0 em 10x)

### ✅ Verificado OK
- <lista explícita do que foi auditado e está correto — evita sensação de "achou tudo">

### 👉 Próximo passo (decisão do usuário)
Pergunte ao usuário:
1. Endereçar **todos os findings**, só os 🔴, ou um conjunto específico?
2. Aplicar **tudo num PR** ou seguir a **modulação sugerida** (fases A→F)?
3. Alguma "brecha" listada é **intencional no contexto** e deve ser ignorada?

A partir das respostas, o agente usa seu planejamento normal para executar — a skill **não constrói plano próprio**, não chama TaskCreate para fases de implementação, não edita código. Apenas relatou.
```

Se não achar nada crítico, diga explicitamente: **"Nenhuma brecha crítica encontrada"** e preencha a seção "Verificado OK". Não invente problemas para parecer útil.

## Princípios

- **Defesa em profundidade**: cada camada deve ser independentemente segura. Frontend valida + backend valida + DB tem constraint.
- **Fail closed**: se algo der errado, sistema **nega acesso por default**. Erros não podem abrir brechas.
- **Never trust the frontend**: tudo do cliente é input não-confiável (headers, cookies, body, MIME types, filenames). **Nem o LLM**: output de modelo e conteúdo que ele leu são input não-confiável também.
- **Verifique no código, não na memória**: o checklist guia o que procurar, mas a vulnerabilidade tem que estar no diff atual.
- **CVE é fato, não opinião**: dependência com CVE em KEV ou CVSS ≥ 9 em versão afetada é 🔴 mesmo que o diff não toque nela — o deploy leva a dependência junto.
- **Não cause falso pânico**: se não tem certeza se é exploitable, classifique como 🟡 e explique o cenário de ataque. CVE com pré-condição que o projeto não atende (só Windows, só dev server, só feature X) é 🟢 informativo.
- **Foque no que mudou**: não audite a base inteira — só o que está pendente para deploy (exceção: dependências e CVEs, que valem pro artefato inteiro).
- **Cite linhas específicas**: sempre formato `arquivo.ts:42` para o usuário navegar direto.

## Histórico do checklist

Este checklist combina:
1. **Padrões recorrentes de exploração** em aplicações web modernas — particularmente as construídas com "vibe coding": `JWT_SECRET` com fallback default, middleware que só checa existência de cookie, SSRF sem bloqueio de IPs internos, race conditions em operações financeiras, `if (session)` que falha aberto, Server Action sem revalidar auth.
2. **OWASP Top 10:2025** (lançado nov/2025 — [top10.owasp.org/2025](https://top10.owasp.org/2025)): A01 Broken Access Control (absorveu SSRF), A02 Security Misconfiguration, A03 Software Supply Chain Failures (novo), A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions (novo). As tags `[A0x:2025]` das seções seguem essa numeração.
3. **OWASP Cheat Sheets** ([Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html), [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html), [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html), [Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)).
4. **OWASP Secure Headers Project** — lista oficial de headers recomendados.
5. **OWASP Top 10 for LLM Applications (2025)** ([genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/)) e **OWASP Top 10 for Agentic Applications (2026)** (ASI01 Agent Goal Hijack … ASI10 Rogue Agents) — base do bloco AI/LLM/Agentes.
6. **NVD (nvd.nist.gov) + CISA KEV + GitHub Advisory Database** — fontes da Fase 0 (`nvd_check.py` e `gh_advisories.py`); a tabela viva de CVEs por componente está em `cve-watch.md`, o estado máquina em `nvd-state.json`.
7. **Padrões consolidados** (timing-safe comparison, timing-safe response anti-enumeração, idempotency keys, SELECT FOR UPDATE, refresh token rotation, SLSA/SBOM para supply chain, image proxy estilo Camo, Data Access Layer do Next.js).
8. **LGPD/GDPR baseline** — endpoints de data subject rights (acesso, correção, portabilidade, exclusão, revogação) e retenção cobrindo logs/backups.
9. **Checklist de segurança do Tiago ([@construindoumastartup](https://instagram.com/construindoumastartup))** — referência usada para validar e expandir a skill nas seções de **Insecure Design** (catálogo de regras de negócio backend-side), **cenários ampliados de race conditions** (likes/follows/recursos únicos/convites), **Exception Handling** explícito, **logging estruturado** com vocabulário consistente, **baseline LGPD/GDPR** e **CI/CD integrity**. Os pontos do checklist do Tiago foram cruzados com OWASP Cheat Sheets antes de entrarem na skill.

A regra é: aplicar todos os itens **desde o início**, não deixar para "depois do MVP". E o output desta skill é **sempre só relatório** — execução vem do planner do agente após o usuário definir escopo.
