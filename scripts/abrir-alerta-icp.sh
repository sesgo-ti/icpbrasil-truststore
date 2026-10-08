#!/usr/bin/env bash
# Abre a issue de alerta do raizes-icp.yml ou comenta nela, se já estiver aberta.
# Corpo: relatório dos testes (AlertaIcp) ou texto fixo. Requer GH_TOKEN e as variáveis GITHUB_* do Actions.
set -euo pipefail

titulo="Alerta ICP-Brasil/TLS do ITI"
relatorio=icpbrasil-truststore-core/target/alerta-icp.md

if [[ -f "$relatorio" ]]; then
  corpo=$(cat "$relatorio")
else
  corpo="Falha no download do ITI ou antes da conferência das raízes."
fi
corpo+=$'\n\n'"Execução: $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"

aberta=$(gh issue list -R "$GITHUB_REPOSITORY" --state open --search "\"$titulo\" in:title" \
  --json number,title -q "map(select(.title == \"$titulo\")) | .[0].number // empty")

if [[ -n "$aberta" ]]; then
  gh issue comment "$aberta" -R "$GITHUB_REPOSITORY" --body "$corpo"
else
  gh issue create -R "$GITHUB_REPOSITORY" --title "$titulo" --body "$corpo"
fi
