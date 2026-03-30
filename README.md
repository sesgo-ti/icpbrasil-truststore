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

`S3_CA_CERT_PATH` é necessário apenas para endpoints S3 privados (MinIO, etc.) cujo certificado TLS foi assinado por uma CA não reconhecida pela JVM. Quando definido, o cliente S3 usa um `TrustManager` dedicado com exclusivamente aquela CA. Quando omitido, o AWS SDK usa o JVM default truststore (`cacerts`) — suficiente para AWS S3 e outros provedores públicos.

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

A biblioteca cria um bean `SSLContext` customizado usando **exclusivamente** os certificados embutidos em `registries/certificates/`. Esse contexto é usado apenas para o download do bundle ICP-Brasil — não é aplicado globalmente à JVM.

O isolamento é intencional: o endpoint `acraiz.icpbrasil.gov.br` (de onde o bundle é baixado) é a raiz de confiança para validação de assinaturas digitais governamentais. Usar a truststore padrão da JVM para essa conexão exporia o download a um MITM com qualquer uma das ~150 CAs comerciais presentes no `cacerts`.

**Certificados embutidos em `registries/certificates/`:**

| Arquivo | Tipo | Propósito |
|---|---|---|
| `isrgrootx1.json` | Raiz (ISRG Root X1) | Âncora de confiança para cadeia E7 |
| `isrgrootx2.json` | Raiz (ISRG Root X2) | Âncora de confiança para cadeia E7 |
| `letsencrypt_e7.json` | Intermediário (E7) | Necessário porque o servidor `acraiz.icpbrasil.gov.br` não envia o intermediário no TLS handshake |

O comportamento por contexto é o seguinte:

| Contexto | Trust utilizado |
|---|---|
| Download do bundle ICP-Brasil | Apenas CAs de `registries/certificates/` |
| Conexão S3 sem `S3_CA_CERT_PATH` | JVM default truststore (`cacerts`) |
| Conexão S3 com `S3_CA_CERT_PATH` | `TrustManager` dedicado com apenas aquela CA |

Para adicionar uma CA ao trust do download ICP-Brasil, inclua o arquivo JSON com o campo `pem` em `registries/certificates/` e reconstrua o artefato.

Para configurar a CA da conexão S3 privado:

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
