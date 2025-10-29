# Configuração do Certificado SSL do Vault

## Variáveis

- URL_VAULT: `https://hl7-fhir.saude-go.net:8200`

## Problema

A aplicação Trust Store precisa se conectar com o Vault (URL_VAULT) para carregar certificados confiáveis de outros serviços. No entanto, a JVM não reconhece o certificado SSL do Vault como confiável, causando o erro:

```
PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
```

## Solução

Para resolver este problema de forma segura, a aplicação não deve confiar nos certificados do sistema operacional ou da JVM. Em vez disso, o operador vai configurar explicitamente o certificado do Vault na aplicação.

## Arquitetura da Solução

A aplicação usa **dois tipos de certificados**:

1. **Certificado SSL do Vault** - Para conectar com o Vault
2. **Certificados confiáveis de outros serviços** - Armazenados no Vault e carregados dinamicamente

## Passos para Configuração

### 1. Obter o Certificado SSL do Vault

Execute o seguinte comando para baixar o certificado SSL do Vault:

```bash
# Baixar o certificado SSL do servidor
openssl s_client -connect $URL_VAULT -showcerts < /dev/null 2>/dev/null | openssl x509 -outform PEM > vault-ssl-cert.pem
```

### 2. Criar um truststore somente com o certificado do Vault

Com o certificado baixado, crie um truststore Java (JKS) contendo apenas este certificado:

> A ferramenta `keytool` vem com o JDK.

```bash
keytool -importcert \
  -file vault-ssl-cert.pem \
  -alias vault-ssl-cert \
  -keystore mytruststore.jks \
  -storepass changeit \
  -storetype PKCS12
```

### 3. Testar

**AMBIENTE DE TESTE:**

1. Copie o arquivo `mytruststore.jks` para o diretório `src/test/resources/` do projeto
    ```bash
    cp mytruststore.jks src/test/resources/
    ```
2. Rode os testes automatizados para garantir que a aplicação consegue se conectar ao Vault usando o certificado configurado:

    ```bash
    mvn clean test
    ```
   
### 4. Executar a aplicação com o truststore customizado

**AMBIENTE DE PRODUÇÃO:**
- Configure as propriedades da JVM
    - `javax.net.ssl.trustStore`: caminho para o arquivo `mytruststore.jks`
    - `javax.net.ssl.trustStorePassword`: senha do truststore (ex: `changeit`)

Exemplo: 
```bash 
java \
  -Djavax.net.ssl.trustStore=mytruststore.jks \
  -Djavax.net.ssl.trustStorePassword=changeit \
  -jar target/trust-store-1.0.jar
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

### Aplicação travada ou falhando ao conectar com o Vault

- Verifique se está acessando o serviço dentro da rede correta (VPN)

### Erro: "Certificado SSL expirado"

- Baixe um novo certificado SSL do Vault válido
- Atualize o truststore com o novo certificado seguindo os passos acima