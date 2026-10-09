# Quero usar o S3 como armazenamento

O acervo de ACs baixado do ITI é gravado num bucket S3-compatível (AWS S3, MinIO etc.). Útil
quando várias instâncias devem compartilhar o mesmo acervo.

> **No serviço REST** o SDK e o mapeamento das variáveis já vêm prontos: pule para o
> [passo 3](#3-variáveis-de-ambiente) e defina também `icpbrasil-truststore.storage.type=s3`.

## 1. Dependências

O starter não traz o AWS SDK. Para usar S3, declare o SDK na sua aplicação:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>software.amazon.awssdk</groupId>
            <artifactId>bom</artifactId>
            <version>2.55.8</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>br.gov.go.saude</groupId>
        <artifactId>icpbrasil-truststore-spring-boot-starter</artifactId>
        <version>0.0.3</version>
    </dependency>
    <dependency>
        <groupId>software.amazon.awssdk</groupId>
        <artifactId>s3</artifactId>
    </dependency>
    <dependency>
        <groupId>software.amazon.awssdk</groupId>
        <artifactId>apache-client</artifactId>
    </dependency>
</dependencies>
```

A versão 2.55.8 é a usada nos testes da biblioteca. O BOM do Spring Boot não gerencia o AWS SDK,
por isso a versão precisa ser informada.

## 2. Configuração

No `application.yml`:

```yaml
icpbrasil-truststore:
  storage:
    type: s3
  s3:
    endpoint: ${S3_ENDPOINT}
    region: ${S3_REGION}
    access-key: ${S3_ACCESS_KEY}
    secret-key: ${S3_SECRET_KEY}
    bucket: ${S3_BUCKET}
    ca-cert-path: ${S3_CA_CERT_PATH:}
```

## 3. Variáveis de ambiente

| Variável | Obrigatória | Exemplo |
|---|---|---|
| `S3_ENDPOINT` | sim | `https://s3.amazonaws.com` ou `https://minio.empresa.local` |
| `S3_REGION` | sim | `us-east-1` (no MinIO, qualquer valor, ex.: `us-east-1`) |
| `S3_ACCESS_KEY` | sim | chave de acesso |
| `S3_SECRET_KEY` | sim | chave secreta |
| `S3_BUCKET` | sim | `icpbrasil-truststore` |
| `S3_CA_CERT_PATH` | não | `file:/etc/ssl/certs/minha-ca.crt`, só se o servidor S3 usa CA própria |

## 4. Bucket

- O bucket precisa existir: a biblioteca não o cria.
- As credenciais precisam de permissão para listar o bucket e para ler, gravar e apagar objetos
  (`s3:ListBucket`, `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`).
- Use um bucket só para o acervo: os objetos ficam na raiz e a biblioteca apaga gerações antigas
  ([como o acervo é gravado](armazenamento-funcionamento.md)).

## 5. Pronto

Na subida, a biblioteca baixa o acervo do ITI, grava no bucket e carrega o cache.

## Se algo faltar

| Sintoma na subida | Causa |
|---|---|
| `storage.type=s3 requer as dependências software.amazon.awssdk:s3 e ...` | Faltam as dependências do passo 1 |
| `Could not resolve placeholder 'S3_...'` (biblioteca) ou `S3 ... must be provided` (serviço REST) | Falta uma variável obrigatória do passo 3 |
| Erro de certificado/TLS ao acessar o endpoint | Servidor com CA própria: defina `S3_CA_CERT_PATH` |
