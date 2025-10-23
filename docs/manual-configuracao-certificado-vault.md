# Configuração do Certificado SSL do Vault

## Problema

A aplicação Trust Store precisa se conectar com o Vault (https://hl7-fhir.saude-go.net:8200) para carregar certificados confiáveis de outros serviços. No entanto, a JVM não reconhece o certificado SSL do Vault como confiável, causando o erro:

```
PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
```

## Arquitetura da Solução

A aplicação usa **dois tipos de certificados**:

1. **Certificado SSL do Vault** - Para conectar com o Vault (deve estar nos resources)
2. **Certificados confiáveis de outros serviços** - Armazenados no Vault e carregados dinamicamente

## Solução

Para resolver este problema de forma segura, o certificado SSL do Vault deve ser colocado nos resources da aplicação.

## Passos para Configuração

### 1. Obter o Certificado SSL do Vault

Execute o seguinte comando para baixar o certificado SSL do Vault:

```bash
# Baixar o certificado SSL do servidor
openssl s_client -connect hl7-fhir.saude-go.net:8200 -showcerts < /dev/null 2>/dev/null | openssl x509 -outform PEM > vault-ssl-cert.pem
```

### 2. Colocar o Certificado SSL nos Resources

1. Copie o arquivo `vault-ssl-cert.pem` para o diretório `src/main/resources/`
2. O arquivo deve estar no formato PEM (texto)

### 3. Verificar a Configuração

O arquivo `application.yaml` já está configurado para usar o certificado SSL:

```yaml
truststore:
  vault:
    certificate-path: 'certificates'  # Path dos certificados confiáveis no Vault
    ssl-certificate-path: 'classpath:vault-ssl-cert.pem'  # Certificado SSL do Vault
```

### 4. Testar a Aplicação

Após colocar o certificado nos resources, execute os testes da aplicação:

```bash
mvn clean test
```

## Segurança

- ✅ **Seguro**: Apenas certificados previamente validados são aceitos
- ✅ **Auditável**: O certificado está versionado no controle de código

## Manutenção

Quando o certificado do Vault for renovado:

1. Baixe o novo certificado SSL usando o comando `openssl` acima
2. Substitua o arquivo `src/main/resources/vault-ssl-cert.pem`
3. Recompile e redistribua a aplicação

## Troubleshooting

### Erro: "Certificado SSL do Vault não encontrado"

- Verifique se o arquivo `vault-ssl-cert.pem` existe em `src/main/resources/`
- Verifique se o caminho no `application.yaml` está correto

### Erro: "Certificado SSL inválido"

- Verifique se o arquivo está no formato PEM correto
- Execute `openssl x509 -in vault-ssl-cert.pem -text -noout` para validar

### Erro: "Certificado SSL expirado"

- Baixe um novo certificado SSL do Vault
- Substitua o arquivo nos resources