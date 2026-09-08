#!/usr/bin/env bash
set -euo pipefail

# Sem argumento, valida a versao candidata; no workflow, a tag e obrigatoria.
tag=${1:-}
if [[ $# -gt 1 ]] || [[ $# -eq 1 && ! "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf '%s\n' 'Tag invalida: esperado vMAJOR.MINOR.PATCH, sem zeros iniciais ou sufixos.' >&2
  exit 1
fi

./mvnw -B -ntp -Prelease -Dgpg.skip=true \
  org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom \
  -Doutput=target/release-effective-pom.xml
python3 scripts/verify-release-artifacts.py "$tag"
