#!/usr/bin/env bash
# Abre a issue de alerta do workflow raizes-icp.yml ou, se ela já estiver aberta, comenta nela.
# O corpo é o relatório gravado pelos testes de integração (AlertaIcp) ou, sem ele, um texto fixo
# (ex.: falha de TLS no download, antes da conferência das raízes).
# Requer GH_TOKEN e as variáveis GITHUB_* do Actions.
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
