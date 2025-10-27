#!/bin/bash

# Script para baixar o certificado SSL do Vault
# Uso: ./scripts/download-vault-cert.sh

set -e

VAULT_HOST="${VAULT_HOST:-hl7-fhir.saude-go.net}"
VAULT_PORT="${VAULT_PORT:-8200}"
CERT_FILE="src/main/resources/vault-ssl-cert.pem"

echo "Baixando certificado SSL do Vault: ${VAULT_HOST}:${VAULT_PORT}"

# Verificar se openssl está disponível
if ! command -v openssl &> /dev/null; then
    echo "Erro: openssl não encontrado. Instale o openssl primeiro."
    exit 1
fi

# Baixar o certificado SSL
openssl s_client -connect "${VAULT_HOST}:${VAULT_PORT}" -showcerts < /dev/null 2>/dev/null | \
    openssl x509 -outform PEM > "${CERT_FILE}"

# Verificar se o arquivo foi criado e não está vazio
if [ ! -s "${CERT_FILE}" ]; then
    echo "Erro: Falha ao baixar o certificado SSL"
    exit 1
fi

# Mostrar informações do certificado SSL
echo ""
echo "Informações do certificado SSL:"
openssl x509 -in "${CERT_FILE}" -text -noout | grep -E "(Subject:|Issuer:|Not Before|Not After)"

echo ""
echo "Certificado SSL baixado com sucesso em: ${CERT_FILE}"
