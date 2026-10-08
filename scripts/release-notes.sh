#!/usr/bin/env bash
# Extrai do CHANGELOG.md a seção de uma versão (sem o título), para as notas da GitHub Release.
# Uso: scripts/release-notes.sh <versão> [CHANGELOG.md]
# Falha se a seção não existir ou estiver vazia: uma release sem notas não deve ser publicada.
set -euo pipefail

version="${1:?informe a versão, ex.: 0.0.2}"
changelog="${2:-CHANGELOG.md}"

notes=$(awk -v header="## [${version}]" '
  index($0, header) == 1 { inside = 1; next }
  inside && /^## \[/ { exit }
  inside { print }
' "$changelog" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')

if [[ -z "${notes//[[:space:]]/}" ]]; then
  echo "Seção [${version}] ausente ou vazia em ${changelog}" >&2
  exit 1
fi
printf '%s\n' "$notes"
