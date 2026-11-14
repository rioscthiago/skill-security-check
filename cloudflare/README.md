# Referência: Cloudflare security-audit-skill

Cópia sem alteração de https://github.com/cloudflare/security-audit-skill (commit c1c8a8c, 2026-09-14), licença MIT (`LICENSE`).
O `SKILL.md` original foi renomeado para `SKILL-original.md` para não ser carregado como skill.

Uso pela `security-check`:
- Os arquivos de domínio (`WEB-PROTOCOL-AND-AUTH.md`, `CLIENT-SIDE.md`, `AI-AND-LLM.md`, ...) são a versão longa dos blocos do checklist. No modo auditoria completa, os blocos são copiados literalmente nos prompts dos caçadores.
- `RECONNAISSANCE.md`, `HUNTING.md`, `VALIDATION-AND-REPORTING.md`: prompts e contratos do modo auditoria completa.
- `report-schema.json`, `validate-findings.cjs`, `validate-coverage-ledger.cjs`: schema e validadores (Node puro, sem dependência) do `findings.json` e do `coverage-ledger.json`.

Para atualizar: clonar o repo de novo e comparar com `diff -r`.
