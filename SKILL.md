---
name: security-check
description: Faz review de segurança das mudanças pendentes na branch atual aplicando checklist anti-vibe-coding + OWASP Top 10:2025 + OWASP LLM/Agentic Top 10 + método da Cloudflare (gate de fronteira e resultado, veredictos confirmado/precisa validar/rejeitado, verificação adversarial). Antes de auditar o código, sincroniza com a NVD (nvd.nist.gov), o catálogo KEV da CISA e o GitHub Advisory Database pra processar CVEs novos do stack identificado no projeto (framework, auth, ORM, banco de dados, runtime, automação, servidores MCP...). Use quando quiser auditar brechas antes de fazer deploy, após implementar feature sensível (auth, upload, query, fetch externo, operação financeira, webhook, LLM/agente), quando quiser saber se saiu CVE novo relevante pro stack, para uma pergunta pontual de segurança ou triagem de um achado, e para auditoria completa do repositório inteiro ("audita o repo todo", "pentest do código", "review completo de segurança").
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash, Write, Edit
---

# Security Check — Review de Brechas

Você audita as mudanças pendentes na branch atual buscando vulnerabilidades comuns. Combina o foco do `/security-review` (auditar diff da branch) com:
1. **Sincronização com NVD, CISA KEV e GitHub Advisory** (Fase 0) — o stack do projeto é identificado e os CVEs novos dele são processados antes de olhar o código
2. Checklist consolidado de padrões recorrentes de exploração em aplicações web modernas (especialmente "vibe coded")
3. Práticas validadas do **OWASP Top 10:2025**, **OWASP Cheat Sheets**, **OWASP Secure Headers Project**, **OWASP Top 10 for LLM Applications (2025)** e **OWASP Top 10 for Agentic Applications (2026)**
4. O **método da [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill)**: só é achado o que cruza uma fronteira de confiança real com resultado concreto; três veredictos (confirmado, precisa validar, rejeitado); severidade calibrada pelo impacto demonstrado; verificação adversarial por agente que não caçou; classes de ataque por domínio (HTTP/identidade, client-side, filas, recursos, isolamento de dados, deploy, supply chain, LLM); modo auditoria completa com ledger de cobertura

Arquivos da skill (todos relativos a esta pasta):

| Arquivo | Papel |
|---|---|
| `SKILL.md` | este workflow + checklist |
| `scripts/nvd_check.py` | consulta a NVD API 2.0 por termo da watchlist desde a última verificação (KEV + componentes que não são pacote: runtime, banco de dados, cache, serviços self-hosted); imprime digest; `--commit` grava estado |
| `scripts/gh_advisories.py` | consulta o GitHub Advisory Database por **dependência direta** do projeto (`package.json`/lockfile/`requirements.txt`) com range semver exato e diz o que afeta a versão instalada + versão mínima segura (precisa de `gh auth`) |
| `nvd-watchlist.json` | termos consultados (um por componente do stack) — vem com uma lista inicial genérica e é **ajustado ao stack identificado** no passo 0 da Fase 0 |
| `nvd-state.json` | estado máquina: `last_check`, `last_cve_processed`, `processed{id: lastModified}` — só o script escreve |
| `cve-watch.md` | registro humano: última verificação, último CVE processado, tabela de CVEs relevantes por componente com versão mínima segura e o que grepar no código |
| `cloudflare/` | cópia da skill da Cloudflare (MIT, ver `cloudflare/README.md`): arquivos de domínio com a versão longa de cada classe de ataque, prompts do modo completo, `report-schema.json` e os validadores `validate-findings.cjs` / `validate-coverage-ledger.cjs` |
| `runs/<repo>/run-N/` | saída do modo auditoria completa (ledger, findings, relatório); runs anteriores servem de base para a próxima |

## Quando usar

- ANTES de qualquer deploy de feature nova
- Após mexer em: auth, sessão, cookies, upload, query SQL/NoSQL, fetch externo, CORS, operações financeiras/aprovações, webhooks, integração com LLM/agente/MCP
- Quando o usuário pedir "review de segurança", "checa brechas", "audita esse código", "saiu CVE novo?"

## Modos de operação

| Modo | Quando | O que roda |
|---|---|---|
| **Diff** (padrão) | `/security-check` sem mais nada, "review antes do deploy", "checa essa branch" | Fases 0 → 4 sobre as mudanças pendentes |
| **Focado** | pergunta de segurança, um arquivo/endpoint, triagem de um achado, "esse CVE me afeta?" | só os blocos relevantes do checklist + gate + veredicto; Fase 0 só se a pergunta envolver dependência/CVE; resposta curta, sem relatório completo nem arquivos |
| **Auditoria completa** | pedido explícito: "audita o repo inteiro", "pentest do código", "review completo/de ponta a ponta", "quero o relatório" | seção **Auditoria completa** no fim deste arquivo (reconhecimento em paralelo, ledger de cobertura, caçadores, crítico de cobertura, verificadores independentes, `findings.json` validado) |

Se o pedido couber em mais de um modo, fazer **uma** pergunta antes de começar (o modo completo gasta dezenas de agentes).

## ⛔ Regra inegociável: ZERO mudanças automáticas no projeto auditado

Esta skill **NUNCA** modifica código, configuração, infra, env vars ou dependências **do projeto auditado**. O escopo é **só auditar + reportar**. A skill entrega um **relatório rico** (findings + risco de regressão + ordem sugerida + dependências + modulação) que serve como **insumo para o planejamento nativo do agente** (Claude Code / Codex / outro harness) — a skill não constrói plano de execução próprio, pois isso conflita com o planner do harness.

**Única exceção de escrita:** os arquivos de estado **dentro da pasta desta skill** (`nvd-state.json` via `--commit`, `cve-watch.md`, `nvd-watchlist.json`, `runs/`). Nada fora dela. A auditoria descreve o fix; não aplica.

Fluxo:

1. **Sincronizar NVD/KEV/GitHub Advisory** (Fase 0) — identificar o stack, processar CVEs novos, registrar o último processado
2. **Auditar** o diff (apenas leitura: `Read`, `Grep`, `Glob`, `Bash` de inspeção)
3. **Entregar o relatório** estruturado (Fase 4)
4. **Aguardar decisão do usuário** sobre quais findings endereçar (todos / só CRÍTICO / fatiar em PRs)
5. A execução em si fica fora da skill — o agente usa o planejamento normal dele com o relatório como contexto

Se o usuário disser "corrige" no meio do relatório, confirmar uma vez: "Quer endereçar todos os CRÍTICOS de uma vez, ou prefere fatiar (ex: auth primeiro, depois input validation)?" — nunca presumir escopo.

## ⛔ Execução segura (vale em todos os modos)

A auditoria é **leitura de fonte**. Rodar código do projeto é exceção, só para confirmar um achado, e com limites:

- **Nunca sondar nada que está no ar**: endpoint deployado, produção, staging compartilhado, webhook real, instância self-hosted, banco de produção, provedor de LLM pago, conta real, dado de usuário. Se o fato decisivo só existe no ambiente deployado, o achado vira **precisa validar** com a checagem que o dono faz (ver gate abaixo).
- Checagem local só com **principal, dado e segredo fictícios**, sem rede externa, sem instalar dependência (`npm install`, `pip install`, `npx` que baixa pacote), sem publicar nada, sem gastar quota paga, com limite de tempo, escrevendo só em diretório temporário. Se não der para garantir isso, **não execute**: fica precisa validar, com o plano de checagem.
- Preferir a checagem mais estreita que resolve: teste unitário existente, harness mínimo chamando a função, fixture pequena, política renderizada. Parar no **menor efeito observável** (registro fictício errado, valor de retorno errado). Nunca teste de carga ou de disponibilidade.
- Se precisar de e-mail num teste, usar um endereço de teste descartável (com sufixo `+teste`), nunca o e-mail real de um usuário ou do dono do projeto.
- Ferramentas de inspeção da Fase 1 (`npm audit`, `pip-audit`, `osv-scanner`, `gitleaks`, `git grep`) são leitura e continuam liberadas.

## O que é um achado (gate da Cloudflare — aplicar antes de reportar qualquer item)

O checklist da Fase 2 diz **onde olhar**. Um item do checklist em falta **não é achado por si só**. Para virar achado, o candidato precisa nomear:

1. **Principal de menor confiança** e o que ele já pode fazer (anônimo, usuário comum, outro tenant, remetente de webhook, autor de conteúdo que o LLM lê, contribuidor de PR)
2. **Entrada ou ação aceita** (campo, header, ID, arquivo, mensagem, argumento de tool)
3. **Controle que deveria barrar** (e onde ele está, ou onde deveria estar)
4. **Fronteira cruzada** (auth, tenant, dono do recurso, papel, origem, processo)
5. **Principal ou recurso afetado** (outro usuário, dado de outro tenant, saldo, segredo, servidor)
6. **Resultado concreto**, observado ou observável pelo dono (lê pedido de outro cliente, executa código, libera curso sem pagar)

Se faltar um desses, ou é **hardening** (vai para a seção própria do relatório, sem severidade de achado), ou é **precisa validar** (se o que falta é um fato fora do código).

### Três veredictos

- **✅ Confirmado** — rastro completo no código (entrada → propagação → sink), controle mais forte visível conferido, condições listadas, resultado demonstrado ou inequívoco no código. **Só confirmado recebe severidade.**
- **🔍 Precisa validar** — hipótese ancorada no código, bloqueada por **um fato específico** que o repositório não mostra (config do provedor de hospedagem/CDN, proxy na frente, política do IdP, RLS aplicada no painel, header injetado pela borda, versão em produção). Traz o **bloqueio exato** + o **plano de checagem** (local com fixture, ou o que o dono olha no painel). **Sem severidade.** Não é estacionamento para ideia especulativa.
- **❌ Rejeitado** — o código, um controle visível, uma pré-condição impossível ou a falta de impacto real derruba o candidato. Registrar em uma linha no relatório (evita que a próxima rodada levante o mesmo falso alarme).

### Calibração de severidade (só para confirmado)

| Severidade | Âncora |
|---|---|
| 🔴 CRÍTICO | ator **não autenticado** consegue execução de código, acesso total ao banco/storage ou tomar conta de qualquer conta |
| 🟠 ALTO | derrota **por completo** um controle explícito com consequência real: bypass de auth, leitura/escrita entre tenants, XSS armazenado que atinge outros usuários, RCE autenticado, derrubar serviço compartilhado sem auth, liberar acesso pago sem pagar |
| 🟡 MÉDIO | violação real de fronteira com raio limitado, pré-condição incomum ou efeito restrito a poucos recursos |
| 🟢 BAIXO/INFO | vaza detalhe interno não secreto, exige esforço contínuo para ganho mínimo, ou só serve de degrau dentro de outro achado |

- **Discriminador alto × médio:** o resultado demonstrado **derrota por completo** um controle explícito numa ação com consequência real, ou só o enfraquece? Se não dá para dizer o dano concreto, a severidade é menor do que parece.
- Separar **probabilidade** (pré-condições, quem alcança) de **impacto** (o que acontece). A severidade final nunca passa do impacto demonstrado.
- Não rebaixar um crítico não verificado para "médio confirmado": se falta o fato, é **precisa validar**.
- **Exceção mantida de propósito (Fase 0):** dependência em versão afetada por CVE em **KEV** ou com **CVSS ≥ 9** é 🔴 quando a pré-condição do CVE é atendida **ou não dá para determinar pelo código**, mesmo fora do diff: a exploração já está ativa e o fix (bump) é barato. Pré-condição claramente não atendida (só Windows, só dev server, feature não usada) → 🟢 informativo.

### Visibilidade de fonte

Proxy, CDN, WAF, headers injetados pela borda, config do provedor de hospedagem, política do banco aplicada no painel, IdP, cookie policy do navegador e topologia de rede são controles reais. Quando o código não mostra se existem, **não presumir nem presença nem ausência**: precisa validar, dizendo exatamente o que olhar.

### Anti-padrões (não reportar assim)

1. Desvio de checklist apresentado como vulnerabilidade
2. Conselho de defesa em profundidade sem violação de fronteira alcançável
3. Teste em ambiente vivo ou compartilhado quando o local não basta
4. Adivinhar comportamento de provedor, proxy, navegador ou deploy que não está no código
5. Tratar autoridade do próprio usuário sobre os próprios dados (self-impact) como cruzamento de fronteira
6. Reportar efeito mais forte que o observado (crash de parser ≠ RCE; trabalho normal ≠ DoS de serviço compartilhado)
7. Dar severidade a precisa validar
8. Header, flag de cookie, MFA ou rate limit faltando **sozinho** como achado: exige requisição inválida aceita, impacto entre principais, rebaixamento de garantia ou vazamento de credencial. Sem isso, é hardening

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
- **Principais e autoridade** (Cloudflare 1b): cada principal de menor confiança e o que ele pode fazer por design; onde a identidade é estabelecida em cada entrada; onde mora a autorização por recurso e o escopo de tenant/dono; mudanças de privilégio, revogação, recuperação e caminhos de fallback
- **Entradas → sinks** (Cloudflare 1c): para cada superfície tocada pelo diff (HTTP, Server Action, webhook, fila, arquivo, CLI/env, contexto de LLM/argumento de tool, deep link, IPC local), seguir transformações, **cópias derivadas** (cache, índice de busca, export, log, embedding) e sinks sensíveis; anotar caminhos paralelos que chegam ao mesmo efeito
- **Visível × deploy**: quais controles estão no código e quais dependem de fato de deploy (proxy, CDN, painel do banco/provedor de hospedagem) — esses viram precisa validar se forem decisivos
- **Blocos de domínio a aplicar**: escolher na Fase 2 só os blocos cuja fronteira apareceu aqui (não escolher por nome de dependência; escolher porque a fronteira existe). Ao escolher, ler o arquivo correspondente em `cloudflare/` (Core discipline + Validation rules) para o caso concreto
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

Para cada arquivo modificado, busque os padrões abaixo. Use `grep` e `Read` — no modo diff a caça é feita por você, direto no código, sem subagente caçador (subagente entra só na verificação adversarial da Fase 3). As tags `[A0x:2025]` referem-se ao OWASP Top 10:2025.

#### Método de caça (Cloudflare — aplicar em cada superfície do diff)

**Leia a fundo.** Siga cada entrada por parsing, identidade, autorização, normalização, estado, cópias derivadas e sink final. Leia os caminhos irmãos que produzem o mesmo efeito: legado, batch, retry, cancelamento, migração, erro. Compare os controles irmãos por **equivalência**, não só presença, e compare o que um componente garante com o que o próximo presume.

**Trabalhe a partir de um invariante concreto:**
1. Nomeie o principal de menor confiança e a capacidade inicial
2. Nomeie o valor, ação, transição de estado ou seletor de recurso aceito
3. Ache o controle que deveria rejeitar, vincular, isolar, limitar ou revogar
4. Trace o caminho exato depois dessa decisão
5. Pare no menor efeito: registro fictício afetado, retorno errado, efeito local observável
6. Escreva a mudança no código e o caso de teste de regressão que garantem o invariante

**Limite de profundidade:** pare a linha de investigação assim que o invariante estiver resolvido (seguro, achado ou bloqueado) e registre.

**Caminhos tristes e divergências:** ausente, vazio, zero, negativo, máximo, acima do limite, duplicado, encoding misto, expirado, revogado, fora de ordem, concorrente, migração pela metade, dependência fora do ar, rollback — só onde a interface aceita. Compare canonicalização e unidades em cada troca entre parser e política.

**A política efetiva é a do caminho paralelo mais fraco**, não a da UI mais caprichada: liste toda porta para a mesma identidade e toda rota para a mesma operação sensível.

**Variantes:** quando um candidato 🔴/🟠 revelar uma causa raiz reutilizável, procure variantes léxicas, estruturais e lógicas no resto do diff (e, se barato, no repo: `grep` do padrão). Mesma causa raiz = um achado com o rastro mais forte; controles ausentes independentes = achados separados.

**Segunda ordem:** dado seguro ao ser gravado pode virar perigoso depois — nome de campo vira caminho JSON, slug vira caminho de arquivo, texto escapado entra em render cru, string gravada vira URL, regex, template ou expressão de política. Injeção também entra por **nomes de campo, chaves, headers e metadados**, não só valores, e em sistemas secundários (log, cache, índice de busca, analytics).

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
- [ ] **Caminho paralelo mais fraco**: existe outra rota para a mesma mudança de estado que checa uma permissão diferente (mais fraca)? Mesmo recurso com vários caminhos de acesso e checks inconsistentes?
- [ ] **Autenticação sem autorização**: endpoint exige login mas esquece de checar se aquele usuário pode agir naquele recurso
- [ ] **Campo do body sobrescreve o que a permissão restringiu** (ex.: `tenantId`, `userId`, `status` no payload ganhando da sessão)
- [ ] **Bulk/batch/export/import**: cada item é autorizado individualmente, não só a operação em lote
- [ ] **Path traversal completo**: inclui symlink, sequência codificada (`%2e%2e%2f`, `..%5c`), null byte; extração de arquivo compactado (**zip slip**: cada entrada resolvida dentro do destino); arquivo temporário com nome previsível; TOCTOU entre checar e usar o arquivo

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
- [ ] **Máquina de estados**: dá para pular etapa, voltar, chegar a estado inválido, repetir um fluxo já concluído? Se o passo 2 de 3 falha, o passo 1 é desfeito?
- [ ] **Manipulação numérica**: valor negativo, zero, overflow, perda de precisão (float em dinheiro), coerção string ↔ número (`"10" + 1`), quantidade fracionária onde só cabe inteiro
- [ ] **Lógica de tempo**: expiração no instante exato da fronteira, janela de rate limit, clock skew, fuso diferente entre componentes (servidor UTC × regra em horário de Brasília)
- [ ] **Default e fallback**: qual a postura de segurança quando a config falta, a feature flag está desligada, a dependência caiu, a migração está pela metade?
- [ ] **Confiança implícita em dado armazenado**: "validamos na entrada" — e se outro caminho (import, admin, job, n8n) gravou esse dado sem validar?
- [ ] **Ação irreversível**: autorização e confirmação vinculadas ao principal, ação e recurso **finais** (não ao que a tela mostrou antes)

#### 🟠 Abuso de funcionalidade e vazamento (Cloudflare — "Feature abuse")
Funcionalidade legítima usada para outro fim. São bugs de desenho, não de linha de código:
- [ ] **Export/backup como exfiltração**: usuário de baixo privilégio exporta dado acima do acesso dele, de outros usuários, rascunho, privado, deletado ou histórico que devia ter sido apagado?
- [ ] **Import/restore como injeção**: import sobrescreve dado existente, cria registro sem a validação normal, grava em coleção sem permissão de escrita, ignora o modelo de permissão da UI?
- [ ] **Busca/filtro/ordenação como oráculo**: busca revela que existe conteúdo que o usuário não acessa? Filtro deixa sondar status, papel ou campo oculto? Ordenar por campo oculto revela o valor pela ordem?
- [ ] **Enumeração por efeito colateral**: "não existe" × "sem acesso" com status, tamanho de resposta ou tempo diferentes; enumeração de usuário por reset, convite, cadastro
- [ ] **Vazamento de preview/rascunho/staging**: token de preview vale só para um item? Rascunho aparece em busca, RSS, sitemap, listagem da API? Header de cache faz a CDN servir conteúdo privado como público?
- [ ] **Notificação/webhook/callback configurável pelo usuário como SSRF**: URL validada contra rede interna **também depois de redirect**
- [ ] **Encadeamento**: mapear o que um principal de baixo privilégio pode ler, gravar, invocar e reter, e ligar só saídas concretas a decisões de confiança posteriores (A valida e passa para B: o que A garante é o que B presume? truncamento, coerção, normalização, escopo de tenant)
- [ ] **Escopo que cresce**: token, API key, OAuth, MCP ou capacidade de agente fica mais amplo depois de delegação, refresh, cache, troca de papel ou composição?
- [ ] **Rollback e recuperação**: undelete, restore, reverter revisão e cancelamento reaplicam dono, validação e autorização **atuais**?

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
- [ ] **OAuth**: `state` + `nonce` + PKCE obrigatórios e **vinculados ao provider** que os emitiu; `redirect_uri` exato (sem wildcard); lib de auth na versão mínima de `cve-watch.md`; comparar callback inicial, retry, deep link mobile e rota de vincular conta (mesma exigência em todos)
- [ ] **JWT**: assinatura verificada com **algoritmo fixado no servidor** e chave de fonte fixa; `kid`/`jku`/`x5u` tratados como seletor não confiável; checa `exp`, `nbf`, `aud`, `iss`; nenhum caminho `decode()` sem `verify()` decidindo acesso; token válido emitido para **outro serviço** (mesmo issuer, outra `aud`) é inválido aqui
- [ ] **Invalidação de sessão**: sessão/refresh token/cookie assinado/estado de WebSocket morrem no logout, troca de senha, revogação, desativação de conta e remoção de papel — inclusive cópias em cache
- [ ] **Escopo de cookie**: `Domain`/`Path` amplos demais (subdomínio de terceiro ou menos confiável lê/sobrescreve o cookie de sessão)
- [ ] **CSRF completo**: inventariar toda mutação autenticada por cookie, incluindo form, multipart, `_method` override e rotas legadas; login CSRF; rota só leitura ou com bearer não-ambiente não conta
- [ ] **Recuperação é o elo mais fraco**: token de reset aleatório, vinculado a usuário + ação, expira, uso único, com rate limit; **gerar um novo invalida os anteriores e derruba as sessões**; troca de e-mail/telefone exige reautenticação; link de entrega montado de URL fixa
- [ ] **MFA (quando existe)**: cadastrar, trocar ou desativar o segundo fator e gerar códigos de recuperação exigem autenticação recente; step-up vinculado à sessão, ação e recurso certos, uso único; rotas alternativas (API, batch, recuperação, fluxo retomado) não pulam o step-up
- [ ] **Vincular conta** (adicionar Google/passkey/e-mail/telefone a conta existente): exige sessão atual, posse verificada da nova identidade e `state` vinculado à conta que iniciou; revisar desvincular/revincular e aceitar convite (colisão de identificador verificado ou de tenant)
- [ ] **API keys**: chave autentica só no escopo (tenant, recurso, ação, ambiente) do registro no servidor; parâmetro do request não amplia; confusão entre chave publicável e secreta; revogação vale mesmo com cache; chave não aparece em URL, redirect, log, bundle ou resposta
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
- [ ] **Injeção indireta (segunda ordem)**: dado gravado "seguro" e depois usado em contexto perigoso por outro código; injeção por **nome de campo, chave, header ou metadado**; injeção em sistema secundário (log, cache, índice de busca, analytics); **template engine** (SSTI) e LDAP/XPath quando existirem
- [ ] **Injeção em header de resposta**: dado do usuário em `Location`, `Set-Cookie`, CSP ou outro header com CR/LF — conferir se o framework rejeita antes de reportar
- [ ] **Execução dinâmica**: `Function()`, `vm.runInContext`, `import()` / `require()` com caminho dinâmico, `pickle.loads`, `yaml.load` sem `SafeLoader`
- [ ] Validação de comprimento de URLs (max 2048 chars) e campos de texto (max length explícito)
- [ ] **Pagination com max page_size** — nunca permitir requisitar 999999 records
- [ ] Rate limiting granular em rotas sensíveis (login, upload, financeiro, endpoints que chamam LLM)

#### 🔴 SSRF Protection (qualquer fetch que use URL de input) [A01:2025]
- [ ] Bloqueia RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- [ ] Bloqueia loopback: `127.0.0.0/8`, `::1`, `localhost`
- [ ] Bloqueia link-local `169.254.0.0/16` (metadata AWS/GCP) e CGNAT `100.64.0.0/10`
- [ ] Timeout curto (10s) em fetches externos
- [ ] Verifica IP **após** DNS resolution (anti DNS rebinding)
- [ ] Revalida o destino **a cada redirect** (ou desliga redirect); cuidado com divergência de parser de URL (`http://a@169.254.169.254`, `http://[::ffff:127.0.0.1]`, decimal/octal `http://2130706433`)
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
- [ ] **Criptografia mal usada**: ECB, IV estático, nonce reutilizado, criptografia sem autenticação (CBC/CTR sem HMAC; preferir AES-GCM/ChaCha20-Poly1305), derivação de chave fraca; **quando a operação cripto falha, o erro cai para "sem cripto"?**; segredo em URL, mensagem de erro ou resposta visível ao cliente
- [ ] `.env` e `.env.local` em `.gitignore`, `.env.example` com valores fictícios
- [ ] Sem credenciais default em qualquer environment
- [ ] Sem stack traces em error responses de prod
- [ ] Endpoints de debug (`/debug`, `/__status`) desabilitados em prod
- [ ] **Directory listing desabilitado** no webserver (Apache `Options -Indexes`; nginx é default-off — confirmar reverse proxy / static server / S3 bucket)
- [ ] **Ambientes não-prod (dev/staging/preview) não acessíveis publicamente**: auth básica, IP allowlist, VPN, ou domínio sem indexação. **Dev server (Vite/Next) nunca com `--host`/`0.0.0.0` em máquina exposta** (Vite CVE-2025-31125 em KEV é só dev server, mas está em KEV; Vite 7/8 tiveram mais 3 bypasses de `server.fs.deny` em 2026), nem `vitest --ui`/`--api` escutando na rede (CVE-2026-47429, 9.8: lê e executa arquivo arbitrário)
- [ ] DB roles com mínimo privilégio por serviço (read-only quando não precisa escrever)
- [ ] Container não roda como root
- [ ] **Redis/Postgres/filas só na rede privada** (rede privada do provedor, sem porta pública) e com senha; BullMQ/Bull Board e painéis de admin atrás de auth
- [ ] **Deriva de precedência de config**: valor de dev, default de chart/Dockerfile, variável de ambiente, flag de linha de comando ou feature flag desliga auth, TLS, escopo de tenant ou auditoria em produção — "renderizar" a config final de cada ambiente mantido, não só o arquivo base
- [ ] **Segredo vazando entre fronteiras**: em log, crash report, argumento de processo (`ps`), saída de build, imagem Docker (`COPY . .` sem `.dockerignore` cobrindo `.env*`), artefato de CI
- [ ] **Header de identidade de proxy confiado de qualquer peer**: backend aceita `X-Forwarded-For`/`X-User-Id`/subject de mTLS vindo de fora do ingress (porta alternativa, rota de health/legado que pula o proxy); o que acontece quando o proxy não está na frente?
- [ ] **URL assinada / objeto**: vincula operação, objeto/versão exata, expiração curta e tenant; continua válida depois que a ACL do recurso muda?
- [ ] **Edge × origem** (Cloudflare Workers, middleware edge): segredo, API, isolamento ou política de tenant presumidos no edge diferem da origem; fallback para a origem muda autoridade ou cache
- [ ] **Identidade de carga de trabalho**: credencial de serviço (token do provedor de hospedagem, chave de cloud, service account) só alcança os recursos do papel, e entrada do usuário não escolhe o recurso-alvo dessa credencial

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
- [ ] **Política × query divergentes**: RLS, escopo default do ORM e filtro de autorização aplicam o mesmo predicado? Joins, agregações, views, cliente `service_role`/`unscoped` e caminhos de erro sem contexto de usuário ignoram o filtro?

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

> Pelo gate: header ausente sozinho é **hardening**. Vira achado quando há caminho concreto (ex.: ação que muda estado e pode ser enquadrada em iframe → clickjacking; CORS que reflete origem com credencial e devolve dado sensível). Header injetado pela borda (Cloudflare, Railway, Vercel) não aparece no código → precisa validar.

#### 🟠 Cache e protocolo HTTP (condicional — CDN, proxy, cache compartilhado) · `cloudflare/WEB-PROTOCOL-AND-AUTH.md`
- [ ] **Cache poisoning por entrada fora da chave**: header (`X-Forwarded-Host`, `X-Forwarded-Proto`, idioma, device), cookie ou query que muda o conteúdo ou headers de segurança da resposta mas não entra na chave de cache
- [ ] **Cache deception**: rota dinâmica privada tratada como estática pela borda (`/conta/perfil.css`, path parameter `;`), ou resposta com identidade cacheada sem `Cache-Control: private`/`no-store`
- [ ] **Request smuggling/desync**: só quando o projeto tem proxy próprio ou parser HTTP customizado — `Content-Length` duplicado, `Transfer-Encoding`, downgrade HTTP/2 → 1.1, normalização de header diferente entre front e back
- [ ] Achado de framing ou cache exige **duas interpretações** do mesmo request/chave: nomear os dois componentes e o valor normalizado em cada lado

#### 🟠 Client-side e navegador (condicional — SPA, extensão, webview, service worker) · `cloudflare/CLIENT-SIDE.md`
Exige fonte controlável + sink que executa ou revela, e impacto na sessão de **outra** vítima, outra origem ou persistência compartilhada (self-XSS não conta):
- [ ] **DOM XSS**: `location.hash`/`search`, `document.referrer`, `window.name`, `event.data`, storage → `innerHTML`, `document.write`, `eval`/`setTimeout(string)`, `href`/`src` com `javascript:`/`data:`, APIs HTML do jQuery, escape hatches do framework
- [ ] **`postMessage`**: handler confere `event.origin` contra allowlist **exata** (nada de `includes`/`startsWith`/regex sem âncora) e, com vários frames da mesma origem, `event.source`; envio de dado sensível nunca com `targetOrigin: '*'`
- [ ] **WebSocket cross-site (CSWSH)**: upgrade autenticado por cookie confere `Origin` ou exige token do canal
- [ ] **Prototype pollution só conta com gadget**: escrita recursiva com chave controlada **e** uma propriedade poluída que muda autorização, execução, navegação ou render
- [ ] **DOM clobbering**: `id`/`name` injetados por markup permitido (sanitizer que mantém `id`) sombreando global ou flag de config usada depois
- [ ] **Service worker**: script e escopo não controláveis pelo atacante (`Service-Worker-Allowed`); cache do SW não serve resposta personalizada de outra conta depois de logout/troca de conta
- [ ] **Storage do navegador**: token, resposta privada ou decisão de autorização em `localStorage`/IndexedDB/Cache Storage sobrevivendo ao logout ou lida por outra conta no mesmo navegador; `BroadcastChannel`/evento `storage` levando identidade entre abas sem vincular à sessão atual
- [ ] **XS-Leaks**: página atacante distingue estado protegido (existe esse objeto? esse usuário é admin?) por load/error, frames, redirect, tempo ou tamanho — exige um predicado secreto concreto
- [ ] **Navegação**: redirect/navegação client-side a partir de fonte controlável sem política de esquema e destino; `window.open` mantendo `opener`

#### 🟠 Filas, jobs, webhooks e mensageria (condicional — BullMQ, n8n, webhooks, pub/sub, SSE/WebSocket) · `cloudflare/PROTOCOLS-RPC-AND-MESSAGING.md`
- [ ] **"Interno" não é autenticação**: nomear a identidade do peer em cada salto e como ela vira o principal da aplicação
- [ ] **Envelope × payload**: autorização usa metadado do envelope/rota mas o handler age sobre tenant/conta/objeto diferente no corpo
- [ ] **Mensagem que se declara privilegiada**: corpo diz "evento de admin", "callback do provedor", "migração" sem produtor autenticado independente
- [ ] **Dedupe depois da mutação** ou com chave que colide entre tenants/operações; ack antes do commit (perde trabalho) ou commit antes do ack (duplica)
- [ ] **Fora de ordem / estado velho**: mensagem antiga (membro já removido, trabalho cancelado) chega depois e sobrescreve o estado novo — checar versão/sequência
- [ ] **Dead-letter, fila de erro, tracing**: carregam segredo ou payload de outro tenant visível a consumidor menos confiável
- [ ] **Streaming/assinatura** (SSE, WebSocket, subscription): autorizada uma vez e continua depois de revogação/troca de papel, ou itens seguintes apontam outro recurso
- [ ] **Correlação de resposta**: ID de correlação previsível/reutilizado deixa uma resposta/callback satisfazer a operação pendente de outro chamador
- [ ] **Transição em vários consumidores**: falha parcial deixa só parte de uma transição de autorização/negócio gravada

#### 🟠 Esgotamento de recursos e custo (condicional) · `cloudflare/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`
Exige caminho entrada → custo, ausência de limite efetivo e impacto em **outro** usuário, serviço compartilhado ou gasto do operador. Rate limit faltando sozinho não basta. **Nunca validar com teste de carga** — análise de complexidade e fixture pequena.
- [ ] **Amplificação por descompressão/representação**: zip/gzip bomb, imagem com dimensões gigantes, XML com entidades, body comprimido — limite **depois** de cada expansão
- [ ] **Amplificação de consulta**: `include`/`expand`/profundidade de GraphQL, filtro sem cardinalidade máxima, sort/agregação sem limite, fan-out para muitas chamadas downstream
- [ ] **Trabalho caro antes da auth**: parse de body grande, bcrypt/argon, descompressão ou chamada externa antes do primeiro gate de tamanho/rate
- [ ] **Trabalho que continua depois do cancelamento**: cliente desconecta/timeout e a chamada ao LLM, query ou job segue rodando (propagar `AbortSignal`)
- [ ] **Cardinalidade sem teto**: chaves únicas de cache, labels de métrica, sessões, assinaturas, jobs pendentes crescendo sem limite por item e agregado
- [ ] **Contabilidade de quota por dimensão manipulável**: IP via `X-Forwarded-For` forjável, chave de rota, prefixo de API key, troca de conta
- [ ] **Erro fatal alcançável**: entrada não confiável chega a exceção não tratada, `process.exit`, loop infinito ou deadlock no processo compartilhado
- [ ] **Tempestade de retry** sem jitter/teto/circuit breaker; **mensagem venenosa** travando a cabeça da fila de todos os tenants

#### 🟠 Isolamento de dados e ciclo de vida (condicional — multi-tenant, cache, busca, export, deleção) · `cloudflare/DATA-ISOLATION-AND-LIFECYCLE.md`
**Campo de tenant no registro não é isolamento**: achar a query, chave, path ou política que o aplica em cada leitura e escrita.
- [ ] **Chave composta sem tenant**: chave de cache, path de objeto no bucket, unicidade no banco, ID de documento no índice, arquivo temporário ou chave de dedupe sem tenant/ambiente
- [ ] **Cópias derivadas com ACL atrasada**: mudança de ACL ou deleção não invalida busca, cache, embedding, thumbnail, RSS, preview — filtrar também na leitura
- [ ] **Log, analytics, trace como leitor alternativo**: conteúdo privado ou credencial indo para sistema com acesso mais amplo ou retenção maior
- [ ] **Soft delete ignorado**: lookup direto, busca, relação, link de objeto, job ou restore devolvem/agem sobre registro deletado; identificador deletado pode ser recadastrado enquanto ainda há referência
- [ ] **Autorização velha**: remoção de membro, mudança de ACL, retirada de consentimento ou revogação não invalida sessões, caches, assinaturas, jobs ou dado materializado
- [ ] **Fila recria o que foi deletado**: deleção termina no banco principal mas retry, export, analytics ou artefato gerado retém ou recria o dado
- [ ] **Restore/undelete reintroduz estado inválido**: permissões, membros ou credenciais que a política atual não permite mais
- [ ] **Migração**: registros antigos sem `tenant_id`/ACL, backfill parcial, leitor velho e novo com defaults diferentes

#### 🟡 Apps locais, desktop e mobile (condicional — servidor em localhost, Electron, webview, deep link, MCP local) · `cloudflare/DESKTOP-MOBILE-AND-LOCAL-IPC.md`
- [ ] **Servidor HTTP em localhost sem autenticação de peer**: qualquer aba do navegador consegue fazer POST nele (CSRF para localhost) e DNS rebinding alcança GET — exigir token/header customizado + checar `Origin`/`Host`; nunca `0.0.0.0`
- [ ] **Principal declarado × identidade do canal**: IPC/socket aceita "sou o usuário X" no corpo sem amarrar ao peer autenticado
- [ ] **Deep link / esquema customizado**: parâmetros do link disparam ação privilegiada, troca de conta ou abrir arquivo sem confirmação
- [ ] **Webview/Electron**: `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`; bridge nativa expõe só o necessário e confere a origem que está chamando; navegação para origem externa não herda a bridge
- [ ] **Helper privilegiado como confused deputy**: processo com mais privilégio executa caminho/comando escolhido por processo menos privilegiado; TOCTOU em arquivo de outro dono

> Memória (C/C++/Rust `unsafe`, parsers binários, FFI, kernel): fora do foco desta skill (web, JS/TS, Python). Se aparecer, aplicar `cloudflare/MEMORY-SAFETY-AND-BINARY.md`.

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
- [ ] **Pelo gate** (Cloudflare `SUPPLY-CHAIN-AND-RELEASE.md`): dependência mutável ou vulnerável **sozinha** não é achado (exceto a regra KEV/CVSS ≥ 9 da Fase 0) — mostrar quem influencia a resolução, que build consome e que fronteira de execução ou release vem depois
- [ ] **Dependency confusion**: pacote com nome interno/escopo privado que pode ser resolvido do registro público (`.npmrc` sem `@escopo:registry`, `--extra-index-url` no pip)
- [ ] **Injeção em workflow**: `${{ github.event.issue.title }}`, `head_ref`, mensagem de commit, nome de branch ou de artefato dentro de `run:` (usar `env:` intermediário); `pull_request_target`/`workflow_run` fazendo checkout do código do PR com secrets ou token de escrita
- [ ] **Cache/artefato entre jobs de confiança diferente**: job de PR popula cache ou artefato que o job de deploy restaura e executa
- [ ] **Promoção por nome mutável**: teste, assinatura e publicação apontam para tag/nome mutável, não para o mesmo digest imutável; checksum baixado do mesmo lugar que o artefato não prova integridade
- [ ] **Contexto de build** inclui `.env`, config local, `.git` ou fixture com dado real na imagem/pacote publicado
- [ ] **Plugin/community node/extensão** ganha autoridade além do escopo declarado, ou hook de install roda antes da checagem de autenticidade

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

Disciplina da Cloudflare (`cloudflare/AI-AND-LLM.md`) — **prompt injection sozinha não é achado**; exige falha de fronteira no código: conteúdo chega ao contexto de outro principal, aciona autoridade que o solicitante não tem, revela dado que ele não lê ou alimenta um sink que ele não alcança direto. **Prompt de guardrail não é fronteira**: só contam checagens determinísticas, autorização por recurso, isolamento, vínculo e credencial restrita. Mapear antes: cada identidade de execução, cada capacidade, toda fonte gravável de contexto/memória e cada destino de saída; começar pelas tools com efeito colateral e andar para trás.
- [ ] **Confused deputy**: tool roda com credencial de serviço ampla e o handler **não** checa de novo se o solicitante pode aquela operação naquele recurso (credencial compartilhada com escopo por usuário aplicado na query é OK)
- [ ] **Vínculo de ação e aprovação**: o que o usuário aprovou (nome normalizado da tool + objeto de argumentos completo + alvo + valor + expiração) é exatamente o que executa; retry ou sessão retomada não reaproveita a aprovação para argumento alterado ou efeito duplicado; conteúdo do atacante não dispara ação sob a autoridade válida da vítima sem pedido dela
- [ ] **Schema da tool × handler**: schema aceita alias, campo extra, chave duplicada, coerção ou objeto livre que o handler interpreta diferente; revalidar onde o valor vira seletor de recurso
- [ ] **Argumento de tool até o sink**: SQL, shell, arquivo, fetch de URL, API privilegiada — saída estruturada limita formato, não autoriza nem torna o caminho/URL seguro
- [ ] **Confusão de papel/proveniência**: concatenação de string, histórico sem tipo, campo `role` vindo do cliente, serialização que perde o rótulo da fonte deixa texto não confiável se passar por system, turno anterior, resultado de tool ou memória
- [ ] **Vazamento de contexto entre sessões/tenants**: histórico, embeddings, resultados de retrieval e **cache de prompt** com chave ampla demais; filtro de tenant/ACL na própria query e em toda chave de cache
- [ ] **Envenenamento de memória persistente**: quem cria, atualiza, mescla e apaga memória; proveniência e tenant; observação de baixa confiança vira instrução ou fato durável usado em outra tarefa/usuário/sessão privilegiada
- [ ] **Loop de ação sem teto**: um pedido enfileira gasto, envio, mutação ou chamada externa repetida sem orçamento por pedido, autorização por ação, cancelamento ou idempotência
- [ ] **Subagente/MCP herda autoridade demais**: tarefa delegada recebe a sessão, credenciais e memória inteiras em vez do mínimo; resultado delegado tratado como confiável na volta
- [ ] **Identidade de servidor/tool MCP**: chamadas e respostas roteadas por nome de servidor/tool/ID escolhido pelo modelo, não pela conexão autenticada; dois servidores podem reivindicar a mesma tool; reconexão muda o vínculo
- [ ] **Metadado MCP como política**: descrição de tool, schema, prompt ou hint de um servidor MCP tratado como autorização — allowlist determinística e authz no handler continuam valendo quando o metadado conflita

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

#### 🔎 Varredura literal dos óbvios (Cloudflare "Obvious things" — fazer item por item, reportar cada resultado)
Ninguém olha porque todo mundo acha que alguém já olhou. Não precisa criatividade, precisa ser literal. Mas **flag não é achado**: antes de reportar, seguir o caminho até o impacto (cookie sem `HttpOnly` só importa se carrega dado sensível e o JS não precisa ler).
- [ ] `git grep -nE "password|secret|apikey|api_key|token|Bearer|-----BEGIN"` e senhas default comuns
- [ ] `git grep -nE "TODO|FIXME|HACK|XXX" | grep -iE "auth|valid|permiss|secur|check|skip|bypass"` (`TODO: add auth`, `HACK: skip permission check`)
- [ ] Modo debug/dev ativável em produção por variável de ambiente, query string ou header
- [ ] Credenciais de teste/exemplo/seed que funcionam em produção
- [ ] Rotas `/debug`, `/admin`, `/test`, `/status`, `/health`, `/metrics`, `/env`, `/.env`, `/config` sem proteção ou vazando dado
- [ ] Arquivos `.env*`, `credentials.json`, `*.pem`, `*.key`, `service-account*.json` versionados; `.gitignore` cobre segredos, uploads e config local
- [ ] Dependências fixadas (lockfile) e CVEs conhecidos (Fase 0/1)
- [ ] `eval`, `exec`, `child_process`, `Function()`, `vm.runInContext`, `import()` com entrada dinâmica
- [ ] CORS `*` ou permissivo demais; `Allow-Credentials` com origem curinga/refletida
- [ ] Cookies sem `HttpOnly`/`Secure`/`SameSite`
- [ ] Parâmetros `redirect`, `return`, `returnTo`, `next`, `url`, `goto`, `continue`, `callbackUrl` indo para redirect sem validação
- [ ] Algum endpoint só HTTP; TLS forçado
- [ ] Resposta de erro em produção com stack trace, caminho interno ou erro SQL

#### 🃏 Curinga (Cloudflare "Wildcard" — uma passada sem categoria, no que o diff toca)
- [ ] Qual o código mais estranho do diff? Por que existe? O que acontece se for abusado? Variável chamada `temp`, `hack`, `legacy`: ler com cuidado; comentário dizendo "isso é seguro porque…": verificar a explicação
- [ ] Feature pela metade, experimental ou "colada": é a que teve menos review
- [ ] **API usada de um jeito que o frontend nunca usa**: chamadas possíveis que o cliente nunca faz; endpoints, parâmetros, headers ou features não documentados no registro de rotas/middleware/config
- [ ] Features que não foram feitas para funcionar juntas: localização + preview + cache; import + plugins + webhooks; OAuth + impersonação + API key
- [ ] Histórico do git: fix de segurança revertido, check de auth comentado, segredo commitado e removido (continua no histórico)
- [ ] Presunções sobre o ambiente: banco local, relógio certo, DNS confiável, filesystem case-sensitive
- [ ] **Testes: o que eles não testam?** Compare os casos de borda que o dev pensou (tem teste) com os que não pensou

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

### Fase 3 — Self-check (24 perguntas) e verificação adversarial

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
17. E se eu chamar a API de um jeito que o frontend nunca chama (campo extra, método diferente, rota não usada pela UI)?
18. E se eu usar export, import, busca, filtro ou ordenação para chegar a dado que eu não leio direto?
19. Depois de logout, troca de senha, troca de conta ou remoção de membro, alguma coisa ainda autoriza (sessão, cache, service worker, job, assinatura SSE/WebSocket, token de refresh)?
20. Se o passo 2 de 3 falhar, o passo 1 é desfeito? E se eu repetir um fluxo já concluído?
21. E se a mesma mensagem/evento chegar duas vezes, ou fora de ordem, ou depois que o estado mudou?
22. A aprovação que o usuário deu vale exatamente para o que executa (mesmos argumentos, mesmo alvo), ou um retry/turno seguinte usa argumentos alterados?
23. Uma requisição pequena e barata pode gerar trabalho grande e compartilhado (descompressão, query sem limite, chamada ao LLM que continua depois do cliente cair)?
24. Existe outra porta para o mesmo efeito com checagem mais fraca (rota legada, batch, admin, job, n8n, import)?

Se alguma pergunta não tem resposta clara no código, é um **candidato** — passa pelo gate e pela verificação abaixo antes de virar achado.

#### Fase 3b — Verificação adversarial (Cloudflare: "tente refutar")

Todo candidato passa por uma tentativa de refutação antes de entrar no relatório:

1. **Auto-refutação (todos os candidatos):** reler cada linha citada no código atual; reconstruir o controle mais forte no caminho (validação, identidade, autorização, normalização, framework, middleware, constraint do banco); confirmar que a primeira etapa do rastro é uma entrada real de menor confiança e a última é o sink/efeito alegado; conferir se severidade e fix batem só com o que a evidência estabelece. Decidir **confirmado / precisa validar / rejeitado**.
2. **Verificador independente (candidatos 🔴 e 🟠 no modo diff; todos no modo completo):** lançar um subagente novo (Agent, `general-purpose`, no modelo mais capaz disponível), um por candidato (agrupar por arquivo se passar de 6), que **não caçou** e **não recebe a conclusão de outro verificador**. Passar só: o candidato (rastro, evidência, condições, causa raiz alegada), os caminhos do repo, os fatos de arquitetura necessários e as regras de validação do domínio (`Validation rules` do arquivo em `cloudflare/`). Prompt base:

   > Você não escreveu este candidato. Tente refutá-lo a partir do código do repositório. Não contate nada que está no ar; não execute código do projeto (só leitura). (1) Confira cada arquivo, linha, escopo e descrição do rastro; confirme que a primeira etapa é uma entrada real de menor confiança e a última é o sink ou efeito alegado. (2) Reconstrua o controle mais forte visível no caminho: validação, identidade, autorização, normalização, ciclo de vida, framework, contenção. (3) Confira entradas, condições e o principal/recurso afetado; não infira resultado mais forte que o rastro mostra. (4) Confira se probabilidade, impacto e fix batem só com o que a evidência estabelece. (5) Se o candidato depende de um fato fora do código, decida se esse fato é mesmo decisivo; se o código refuta o rastro, rejeite. Responda com: veredicto (confirmado | precisa validar | rejeitado), justificativa com `arquivo:linha`, severidade corrigida (só se confirmado), bloqueio exato e plano de checagem (só se precisa validar).

   O resultado do verificador substitui a redação original. Discordância entre você e o verificador sobre um 🔴: reportar a posição mais conservadora **com o motivo da divergência**, nunca escolher em silêncio.
3. Candidato rejeitado sai dos achados e entra em uma linha na seção **❌ Rejeitados**.

### Fase 4 — Reportar (insumo para o planner do agente)

**A skill encerra aqui.** O relatório precisa ser rico o suficiente para que o usuário decida o escopo e o agente use seu planejamento nativo (Claude Code / Codex) para executar — não duplicar o planner do harness.

Cada finding deve trazer **fix + risco de regressão + dependências + esforço + tarefas humanas associadas**:

**Achado confirmado:**

```
[ID] [CATEGORIA] Severidade: 🔴 CRÍTICO | 🟠 ALTO | 🟡 MÉDIO | 🟢 BAIXO/INFO   ·   Verificado por: auto | subagente
Fingerprint: <id estável da causa raiz, sem linha nem severidade — ex.: authz/orders-get-missing-owner-check>
Arquivo: <arquivo:linha>
Rastro: <entrada arquivo:linha → propagação arquivo:linha → sink arquivo:linha>
Evidência: <snippet de código>
Fronteira: <principal de menor confiança> → <controle que falta/falha> → <principal/recurso afetado>
Condições: <pré-requisitos para explorar: logado? papel? feature ligada? deploy self-hosted?>
Por que importa: <impacto em 1 frase — o que o atacante consegue>
Cenário de ataque: <como o atacante explora, na interface nativa: request HTTP, Server Action, mensagem, arquivo>
Probabilidade × impacto: <quem alcança e com que esforço> × <o que acontece>
Invariante: <a regra que o código precisa garantir>
Fix sugerido: <menor mudança efetiva no último ponto de decisão confiável — ou "tarefa humana" se não for editável por agente>
Teste de regressão: <o caso que falha hoje e passa depois do fix>
Risco de regressão: <o que pode quebrar ao aplicar: contrato de API alterado, migration necessária, testes que vão exigir update, header novo que pode quebrar consumidor X, comportamento que clientes assumem>
Dependências: <IDs de findings que precisam vir antes, OU "nenhuma">
Esforço: S (≤1h) | M (≤4h) | L (>4h, exige refactor)
```

**Precisa validar (sem severidade):**

```
[ID] [CATEGORIA] 🔍 PRECISA VALIDAR
Fingerprint: <id estável>
Rastro: <arquivo:linha → ... → arquivo:linha>
Causa raiz alegada: <o que estaria errado>
Fronteira em jogo: <principal> → <recurso> (resultado possível, não demonstrado)
Bloqueio: <o fato exato que o código não mostra — ex.: "o proxy do provedor sobrescreve X-Forwarded-For?", "a policy de RLS da tabela orders está ativa no painel?">
Como resolver: <checagem local com fixture> e/ou <o que o dono olha no painel/config — nunca "mande tráfego para produção">
```

Estrutura do report final:

```
## Security Check — <branch>

### 📡 NVD/KEV
- Verificação: <data/hora> · janela desde <last_check anterior> · CVEs novos/alterados: N · relevantes pro stack: M (registrados em cve-watch.md)
- Afetam ESTE projeto: <lista CVE · pacote@versão instalada → mínima segura · KEV sim/não> (ou "nenhum")
- Último CVE processado: <id>

### Sumário
- Postura em 1-2 frases
- N achados confirmados: X 🔴 / Y 🟠 / Z 🟡 / W 🟢 · P precisa validar · R rejeitados
- Arquivos auditados: <count>
- Áreas de maior risco: <auth | input | race | etc>

### Tabela de achados confirmados
| Sev. | Título | Fronteira afetada | Resultado em 1 linha |
|---|---|---|---|

### 🔴 CRÍTICO (bloqueia deploy)
<findings com formato acima — inclui dependência em KEV/CVSS ≥ 9 com versão afetada>

### 🟠 ALTO (corrigir antes do próximo release)
...

### 🟡 MÉDIO
...

### 🟢 BAIXO / INFO
...

### 🔍 PRECISA VALIDAR (sem severidade — leads priorizados)
<formato "precisa validar" acima; ordenar pelo que estaria em jogo se confirmado>

### 🧱 Hardening (não são achados)
<itens do checklist em falta que não passaram no gate: header ausente sem caminho de exploração, defesa em profundidade, boas práticas — cada um em 1 linha com o motivo de não ser achado>

### ❌ Rejeitados
<fingerprint · o que parecia · por que caiu (controle em arquivo:linha, pré-condição impossível, sem impacto)>

### 🗺️ Cobertura
- Superfícies auditadas e blocos de domínio aplicados (e os descartados, com motivo)
- O que ficou de fora (arquivos não lidos, domínios não aplicados, fatos de deploy não verificados)
- Nenhuma passada é exaustiva: dizer o que não foi coberto, nunca "o resto está ok"

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
- [ ] Fazer as checagens de painel dos itens 🔍 PRECISA VALIDAR (provedor de hospedagem, CDN, banco, IdP) e devolver o resultado

### ✅ Verificado OK
- <lista explícita do que foi auditado e está correto — evita sensação de "achou tudo">

### 👉 Próximo passo (decisão do usuário)
Pergunte ao usuário:
1. Endereçar **todos os findings**, só os 🔴, ou um conjunto específico?
2. Aplicar **tudo num PR** ou seguir a **modulação sugerida** (fases A→F)?
3. Alguma "brecha" listada é **intencional no contexto** e deve ser ignorada?

A partir das respostas, o agente usa seu planejamento normal para executar — a skill **não constrói plano próprio**, não chama TaskCreate para fases de implementação, não edita código. Apenas relatou.
```

Se não achar nada crítico, diga explicitamente: **"Nenhuma brecha crítica encontrada"** e preencha a seção "Verificado OK". Não invente problemas para parecer útil. Uma rodada limpa pode ter **zero** achados confirmados: dizer isso e os limites de cobertura, sem inventar 🟢 para encher o relatório.

## Princípios

- **Defesa em profundidade**: cada camada deve ser independentemente segura. Frontend valida + backend valida + DB tem constraint.
- **Fail closed**: se algo der errado, sistema **nega acesso por default**. Erros não podem abrir brechas.
- **Never trust the frontend**: tudo do cliente é input não-confiável (headers, cookies, body, MIME types, filenames). **Nem o LLM**: output de modelo e conteúdo que ele leu são input não-confiável também.
- **Verifique no código, não na memória**: o checklist guia o que procurar, mas a vulnerabilidade tem que estar no diff atual.
- **CVE é fato, não opinião**: dependência com CVE em KEV ou CVSS ≥ 9 em versão afetada é 🔴 mesmo que o diff não toque nela — o deploy leva a dependência junto.
- **Não cause falso pânico, nem rebaixe para esconder dúvida**: se não dá para saber se é explorável porque falta um fato fora do código, é **precisa validar** (sem severidade, com o bloqueio exato), não um 🟡 genérico. CVE com pré-condição que o projeto não atende (só Windows, só dev server, só feature X) é 🟢 informativo.
- **Fronteira + resultado, ou não é achado**: checklist diz onde olhar; o gate diz o que reportar. O resto é hardening.
- **A política efetiva é a do caminho mais fraco**: toda porta para a mesma identidade, toda rota para a mesma operação.
- **Prompt de guardrail não é fronteira**: em LLM/agente só contam checagens determinísticas, authz por recurso, isolamento e credencial restrita.
- **Fix no último ponto de decisão confiável**: o menor ajuste que garante o invariante, com teste de regressão — não conselho genérico de hardening, e sem só mover a confiança de lugar.
- **Nenhuma passada é exaustiva**: o relatório diz o que não cobriu.
- **Foque no que mudou**: não audite a base inteira — só o que está pendente para deploy (exceção: dependências e CVEs, que valem pro artefato inteiro).
- **Cite linhas específicas**: sempre formato `arquivo.ts:42` para o usuário navegar direto.

## Auditoria completa (modo repo inteiro)

Só com pedido explícito (ver **Modos**). Adaptação do fluxo de 6 fases da Cloudflare (`cloudflare/SKILL-original.md`, `RECONNAISSANCE.md`, `HUNTING.md`, `VALIDATION-AND-REPORTING.md` — ler esses quatro antes de começar; os prompts deles são a referência literal). O que muda em relação a eles está abaixo; o resto segue o original.

**Antes de lançar qualquer agente:**
1. **Perfil**: `quick` (1 onda de caçadores + 1 crítico final; 1 verificador por candidato), `standard` (padrão: ondas até o crítico final voltar limpo), `deep` (unidades por subsistema e ciclo de vida, verificação de candidato e de registro separadas). Escopo opcional: caminhos, um subsistema, um domínio ou o diff entre duas refs (o resto vira `out_of_scope`, nunca `covered`).
2. **Orçamento**: estimar o número de agentes (4 de reconhecimento + caçadores ≈ unidades do ledger + 1-2 críticos por onda + 1-2 verificadores por candidato) e **mostrar a estimativa ao usuário e esperar o ok**. Reservar críticos e verificação antes de gastar com caçadores; se o orçamento não cobre, propor escopo menor ou perfil mais leve, nunca afinar a evidência em silêncio.
3. **Pasta de saída**: `~/.claude/skills/security-check/runs/<repo>/run-<N>/` (N = próximo inteiro livre). Nunca dentro do repo auditado.
4. **Fase 0 (NVD/KEV)** roda igual ao modo diff, uma vez, e o resultado entra no relatório.
5. **Runs anteriores**: ler `coverage-ledger.json` e `findings.json` das runs anteriores do mesmo repo; achado confirmado com código inalterado é reverificado, não recaçado; código mudado vira unidade de revalidação; `needs_validation`, `deferred` e `blocked` anteriores viram trabalho atual. Sem run anterior: dizer isso no relatório.

**Execução:**
- Agentes: `Agent` com `subagent_type: general-purpose` no modelo mais capaz disponível. Reconhecimento: os 4 agentes 1a-1d de `RECONNAISSANCE.md` em paralelo, só leitura. Caçadores, críticos e verificadores: prompts de `HUNTING.md` e `VALIDATION-AND-REPORTING.md`, com os blocos de domínio copiados **literalmente** de `cloudflare/` (o checklist deste arquivo entra junto como lista do que procurar).
- **Execução de código do alvo: desligada por padrão.** Sem o sandbox de SO que a Cloudflare exige (sem rede, ambiente vazio, alvo só leitura, limites de CPU/memória/tempo). Então caçadores e verificadores trabalham **só com leitura de fonte** (`method: "source"`, `artifact: null`), e o que precisaria de execução para confirmar vira `needs_validation` com o plano de checagem local. Ignorar o procedimento de promoção de artefatos.
- Só o agente principal escreve na pasta da run (`run-metadata.json`, `architecture.md` ≤ 1.000 palavras, `coverage-ledger.json`, `findings.json`). Subagentes devolvem JSON estruturado.
- Validar sempre que mexer:
  ```bash
  node ~/.claude/skills/security-check/cloudflare/validate-coverage-ledger.cjs <run>/coverage-ledger.json
  node ~/.claude/skills/security-check/cloudflare/validate-findings.cjs <run>/findings.json
  ```
  `findings.json` segue `cloudflare/report-schema.json` (campos em inglês, `confirmed` / `needs_validation` / `rejected`). Mapear severidade: critical → 🔴, high → 🟠, medium → 🟡, low/informational → 🟢.
- Estados terminais (só dois): relatório escrito e os dois validadores passando, **ou** `run_status: "incomplete"` com o motivo exato e a lacuna dita no relatório. Nunca parar no meio de uma fase.

**Saída:** `REPORT.md` em português, no formato da Fase 4 deste arquivo (com a seção 📡 NVD/KEV, cobertura vinda do ledger e o resultado do crítico final), mais `FINDINGS-DETAIL.md` (achados 🟡+ com rastro e reprodução local) e `NEEDS-VALIDATION.md`. Na resposta, passar os caminhos absolutos. A regra de ouro continua: **só relatório**, a correção vem do planner depois que o usuário escolher o escopo.

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
10. **[Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill)** (MIT, commit c1c8a8c, cópia em `cloudflare/`) — a skill que deu origem ao harness de descoberta de vulnerabilidades da Cloudflare. Trouxe: gate de fronteira + resultado, três veredictos (precisa validar sem severidade), âncoras de severidade, visibilidade de fonte, anti-padrões, método de caça por invariante, verificação adversarial por agente independente, varredura literal dos óbvios, curinga, e as classes de ataque de HTTP/identidade, client-side, mensageria, esgotamento de recursos, isolamento de dados, deploy, supply chain e LLM/MCP; e o modo auditoria completa com ledger de cobertura e validadores.

A regra é: aplicar todos os itens **desde o início**, não deixar para "depois do MVP". E o output desta skill é **sempre só relatório** — execução vem do planner do agente após o usuário definir escopo.
