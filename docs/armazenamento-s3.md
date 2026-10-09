# Quero gravar o acervo no S3

O acervo de ACs baixado do ITI é gravado num bucket S3-compatível (AWS S3, MinIO etc.). Útil
quando várias instâncias devem compartilhar o mesmo acervo.

**No serviço REST**, o SDK e o mapeamento das variáveis já vêm prontos: faça só os passos
[3](#3-defina-as-variáveis-de-ambiente) e [4](#4-prepare-o-bucket) e passe
`--icpbrasil-truststore.storage.type=s3`.

## 1. Adicione o AWS SDK

O starter não traz o AWS SDK ([por quê](#por-que-o-sdk-não-vem-junto)). Declare-o na sua aplicação,
além do [starter](usar-como-biblioteca.md#1-adicione-a-dependência):

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

## 2. Ligue as propriedades às variáveis

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

## 3. Defina as variáveis de ambiente

| Variável | Obrigatória | Exemplo |
|---|---|---|
| `S3_ENDPOINT` | sim | `https://s3.amazonaws.com` ou `https://minio.empresa.local` |
| `S3_REGION` | sim | `us-east-1` (no MinIO, qualquer valor) |
| `S3_ACCESS_KEY` | sim | chave de acesso |
| `S3_SECRET_KEY` | sim | chave secreta |
| `S3_BUCKET` | sim | `icpbrasil-truststore` |
| `S3_CA_CERT_PATH` | não | `file:/etc/ssl/certs/minha-ca.crt`, só se o servidor S3 usa CA própria |

## 4. Prepare o bucket

- O bucket precisa existir: a biblioteca não o cria.
- As credenciais precisam de `s3:ListBucket`, `s3:GetObject`, `s3:PutObject` e `s3:DeleteObject`.
- Use um bucket só para o acervo: os objetos ficam na raiz e gerações antigas são apagadas.

## Se algo faltar

| Erro na subida | Causa |
|---|---|
| `storage.type=s3 requer as dependências software.amazon.awssdk:s3 e ...` | Falta o passo 1 |
| `Could not resolve placeholder 'S3_...'` (biblioteca) ou `S3 ... must be provided` (serviço) | Falta uma variável do passo 3 |
| Erro de certificado/TLS ao acessar o endpoint | Servidor com CA própria: defina `S3_CA_CERT_PATH` |

## Por que o SDK não vem junto

O AWS SDK é grande e a maioria das aplicações grava em disco. Por isso ele é uma dependência
opcional do starter: as classes de S3 estão no starter, mas só são ativadas quando o SDK está no
classpath.

## Veja também

- [Como o acervo é gravado](armazenamento-funcionamento.md)
- [Armazenamento em diretório local](armazenamento-filesystem.md)
