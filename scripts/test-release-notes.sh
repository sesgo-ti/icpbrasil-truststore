#!/usr/bin/env bash
# Testa scripts/release-notes.sh sem publicar nada: extração da seção certa, recusa de versão
# ausente ou vazia e ausência do título e das seções vizinhas nas notas.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/CHANGELOG.md" <<'MD'
# Changelog

## [Unreleased]

## [1.1.0] - 2026-01-02

## [1.0.0] - 2026-01-01

### Adicionado

- Primeira versão.

## [0.9.0] - 2025-12-01

- Anterior.
MD

falhas=0
esperar() { if [[ "$2" != "$3" ]]; then echo "FALHOU: $1"; echo "  esperado: $3"; echo "  obtido:   $2"; falhas=$((falhas + 1)); fi; }

esperar "seção existente" "$(scripts/release-notes.sh 1.0.0 "$tmp/CHANGELOG.md")" $'### Adicionado\n\n- Primeira versão.'
if scripts/release-notes.sh 2.0.0 "$tmp/CHANGELOG.md" >/dev/null 2>&1; then echo "FALHOU: versão ausente aceita"; falhas=$((falhas + 1)); fi
if scripts/release-notes.sh 1.1.0 "$tmp/CHANGELOG.md" >/dev/null 2>&1; then echo "FALHOU: seção vazia aceita"; falhas=$((falhas + 1)); fi
esperar "prefixo de versão não casa com outra" "$(scripts/release-notes.sh 0.9.0 "$tmp/CHANGELOG.md")" "- Anterior."
real=$(scripts/release-notes.sh 0.0.1 CHANGELOG.md)
[[ "$real" == *"Arquitetura hexagonal"* && "$real" != *"## [0.0.1]"* ]] || { echo "FALHOU: CHANGELOG real (0.0.1)"; falhas=$((falhas + 1)); }

[[ $falhas -eq 0 ]] && echo "release-notes: todos os casos passaram"
exit "$falhas"
