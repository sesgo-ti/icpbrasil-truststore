# Trust Store ICP-Brasil

Biblioteca de auto-configuração Spring Boot para gerenciamento do repositório de certificados ICP-Brasil. Realiza o download, verificação de integridade, cache em memória e atualização automática do bundle oficial de ACs da ICP-Brasil, disponibilizando os certificados para qualquer aplicação Spring Boot que a utilize como dependência.

---

## Por que esta biblioteca existe

Certificados ICP-Brasil são exigidos para validar assinaturas digitais e conexões TLS em sistemas do governo brasileiro. O bundle oficial de ACs é publicado pelo ITI e atualizado periodicamente. Esta biblioteca gerencia todo esse ciclo de vida — download, verificação de hash, cache e atualização agendada — sem necessidade de intervenção manual.

---

## Funcionalidades

- Download do bundle de ACs ICP-Brasil (ZIP) com verificação de hash SHA-512
- Cache em memória com TTL configurável e limiares de criticidade
- Atualização agendada em background para manter o bundle sincronizado com o ITI
- Dois backends de armazenamento: sistema de arquivos local ou S3-compatível (MinIO, AWS S3, etc.)
- Endpoint REST opcional para consulta de certificados por SKI
- `SSLContext` e `X509TrustManager` customizados com trust exclusivo nas CAs embutidas
- Auto-configuração Spring Boot completa — sem boilerplate na aplicação consumidora

---

## Requisitos

- Java 21
- Spring Boot 3.4.x

---

## Uso como biblioteca

Adicione a dependência no `pom.xml`:

```xml
<dependency>
    <groupId>br.gov.go.saude.fhir</groupId>
    <artifactId>trust-store-icpbrasil</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

A biblioteca se auto-configura via mecanismo de auto-configuração do Spring Boot. Nenhuma anotação `@Import` ou registro manual de beans é necessário. Na inicialização, verifica se o bundle está disponível no repositório configurado e realiza o download caso necessário.

O `Cache` em memória é populado com objetos `X509Certificate` indexados por SKI, prontos para uso em validações de certificados.

---

## Uso como microsserviço

Execute a aplicação diretamente para utilizá-la como serviço standalone ou sidecar:

```bash
./mvnw spring-boot:run
```

Com a API REST habilitada (ver configuração abaixo), consulte um certificado pelo SKI:

```bash
# Formato PEM
curl -X GET "http://localhost:8080/certificate?ski=<SKI>&type=pem"

# Formato DER (binário)
curl -X GET "http://localhost:8080/certificate?ski=<SKI>&type=der" --output certificado.der
```

---

## Configuração

Todas as propriedades estão sob o prefixo `truststore-icpbrasil`.

### Armazenamento: sistema de arquivos (padrão)

```yaml
truststore-icpbrasil:
  storage:
    type: filesystem
  filesystem:
    base-dir: .data/truststore-icpbrasil
```

### Armazenamento: S3-compatível

```yaml
truststore-icpbrasil:
  storage:
    type: s3
```

As credenciais S3 são lidas de variáveis de ambiente:

| Variável | Descrição |
|---|---|
| `S3_ENDPOINT` | URL completa do servidor S3 (ex: `https://s3.amazonaws.com`) |
| `S3_REGION` | Região (ex: `us-east-1`, `sa-east-1`) |
| `S3_ACCESS_KEY` | Chave de acesso |
| `S3_SECRET_KEY` | Chave secreta |
| `S3_BUCKET` | Nome do bucket |
| `S3_CA_CERT_PATH` | Caminho do certificado CA do servidor S3 (opcional) |

`S3_CA_CERT_PATH` é necessário quando a CA que assinou o certificado TLS do servidor S3 **não está** entre as CAs embutidas em `registries/certificates/`. Quando definido, a biblioteca cria um `SSLContext` dedicado exclusivamente para a conexão S3. Quando omitido, usa o `SSLContext` global da aplicação.

### Atualização agendada

```yaml
truststore-icpbrasil:
  scheduling:
    enabled: true
  refresh-interval-hours: 2     # intervalo entre verificações (mín: 1)
  cache-ttl-critical-hours: 72  # horas até o cache entrar em estado crítico (24–168)
  cache-ttl-max-hours: 168      # horas até o cache expirar completamente (72–720)
```

### Endpoint REST

```yaml
truststore-icpbrasil:
  rest:
    enabled: true
```

### Rede

```yaml
truststore-icpbrasil:
  network:
    download-timeout-seconds: 60
    max-retries: 3
    retry-interval-seconds: 30
```

---

## Contexto SSL e segurança

A biblioteca cria um bean `SSLContext` customizado usando **exclusivamente** os certificados embutidos em `registries/certificates/` (atualmente raízes Let's Encrypt). A truststore padrão da JVM é intencionalmente ignorada em todas as conexões de saída.

Isso é necessário porque sistemas ICP-Brasil operam em um ambiente de confiança controlado. Depender da truststore padrão da JVM introduziria confiança implícita em CAs de terceiros o que não é desejado.

O comportamento por contexto é o seguinte:

| Contexto | Trust utilizado |
|---|---|
| Conexões gerais da aplicação | Apenas CAs de `registries/certificates/` |
| Conexão S3 sem `S3_CA_CERT_PATH` | Mesmo `SSLContext` global |
| Conexão S3 com `S3_CA_CERT_PATH` | `SSLContext` dedicado com apenas aquela CA |

Para adicionar uma CA ao trust global da aplicação, inclua o arquivo JSON com o campo `pem` em `registries/certificates/` e reconstrua o artefato.

Para configurar a CA da conexão S3:

```bash
export S3_CA_CERT_PATH=file:/etc/ssl/certs/minha-ca.crt
```

---

## Testes

```bash
# Todos os testes
./mvnw test
```

```bash
# Build sem testes
./mvnw clean install -DskipTests
```

---

## Build

```bash
./mvnw clean install
```

Gera um JAR em `target/` pronto para ser utilizado como dependência. O projeto não gera fat JAR — é uma biblioteca.

---

## Backlog

Funcionalidades identificadas como necessárias e ainda não implementadas:

- [ ] **Notificação de cache crítico** — ao atingir `cache-ttl-critical-hours` sem sincronização bem-sucedida, notificar o operador via webhook, e-mail ou outro canal configurável
- [ ] **Notificação de cache expirado** — ao atingir `cache-ttl-max-hours`, além de invalidar o cache, emitir alerta de severidade máxima ao operador
- [ ] **Endpoint de status do cache** — expor via REST o estado atual do cache (válido, crítico, expirado) e a data da última confirmação com o ITI
- [ ] **Suporte a múltiplas CAs para S3** — `S3_CA_CERT_PATH` aceita apenas um certificado; suporte a um bundle completo seria necessário em ambientes com cadeia intermediária
