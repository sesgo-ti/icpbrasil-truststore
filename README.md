# Trust Store ICP-Brasil

Biblioteca de auto-configuração Spring Boot que mantém atualizado o acervo de certificados das Autoridades Certificadoras (ACs) vigentes da ICP-Brasil. Realiza download do repositório oficial publicado pelo ITI, verificação de integridade por hash SHA-512, cache em memória e sincronização automática.

---

## Funcionalidades

- Download do acervo de ACs vigentes da ICP-Brasil (ZIP publicado pelo ITI) com verificação de hash SHA-512
- Cache em memória com TTL configurável e limiares de criticidade
- Sincronização automática em background
- Dois backends de armazenamento: filesystem local ou S3-compatível (MinIO, AWS S3, etc.)
- Endpoint REST opcional para consulta de certificados por SKI
- Verificação de revogação de certificados via OCSP e CRL com cache e fallback automático
- `SSLContext` e `X509TrustManager` com trust exclusivo nas CAs embutidas
- Health indicator (`/actuator/health`) com estados VALID / CRITICAL / EXPIRED

---

## Requisitos

- Java 21
- Spring Boot 3.4.x

---

## Modo 1: Biblioteca

Adicione a dependência:

```xml
<dependency>
    <groupId>br.gov.go.saude.fhir</groupId>
    <artifactId>trust-store-icpbrasil</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

A biblioteca se auto-configura via mecanismo de auto-configuração do Spring Boot — nenhuma anotação `@Import` ou registro manual de beans é necessário.

Na inicialização, verifica se o acervo de ACs da ICP-Brasil já está disponível localmente. Se não, baixa do repositório oficial do ITI. O cache em memória é populado com os certificados das ACs vigentes, indexados por SKI.

Para um exemplo de integração com consulta por SKI, veja [docs/exemplo-integracao.md](docs/exemplo-integracao.md).

**Configuração mínima:**

```yaml
truststore-icpbrasil:
  storage:
    type: filesystem
  filesystem:
    base-dir: .data/truststore-icpbrasil
```

---

## Modo 2: Serviço standalone

### Build

```bash
./mvnw clean package -P standalone -DskipTests
```

Gera `target/trust-store-icpbrasil-*-standalone.jar` (fat JAR executável).

### Execução

```bash
java -jar target/trust-store-icpbrasil-*-standalone.jar \
  --truststore-icpbrasil.rest.enabled=true \
  --truststore-icpbrasil.storage.filesystem.base-dir=/data/truststore
```

### Verificação

```bash
curl http://localhost:8080/actuator/health
```

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=pem"
```

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=der" --output certificado.der
```

Para detalhes sobre health check, estados do cache e logs de monitoramento, veja [docs/manual-monitoramento.md](docs/manual-monitoramento.md).

---

## Referência de configuração

### Propriedades principais

| Propriedade | Padrão | Descrição |
|---|---|---|
| `certificate-url` | Repositório ITI | URL do ZIP com as ACs vigentes da ICP-Brasil (HTTPS obrigatório) |
| `hash-url` | Repositório ITI | URL do hash SHA-512 para verificação de integridade |
| `refresh-interval-hours` | `2` | Intervalo de verificação de atualizações (1 a `cache-ttl-critical-hours`) |
| `cache-ttl-critical-hours` | `72` | Horas sem atualização para estado CRITICAL (24–168) |
| `cache-ttl-max-hours` | `168` | Horas até o cache expirar (72–720, deve ser > critical) |
| `storage.type` | `filesystem` | `filesystem` ou `s3` |
| `rest.enabled` | `false` | Ativa o endpoint `/certificate` |
| `scheduling.enabled` | `true` | Ativa a rotina de atualização em background |
| `trusted-certs.dir` | `classpath:registries/certificates` | Diretório com CAs fixas (JSON) |

### Armazenamento: filesystem

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

Credenciais via variáveis de ambiente:

| Variável | Descrição |
|---|---|
| `S3_ENDPOINT` | URL do servidor S3 (ex: `https://s3.amazonaws.com`) |
| `S3_REGION` | Região (ex: `us-east-1`) |
| `S3_ACCESS_KEY` | Chave de acesso |
| `S3_SECRET_KEY` | Chave secreta |
| `S3_BUCKET` | Nome do bucket |
| `S3_CA_CERT_PATH` | CA do servidor S3 privado — opcional, apenas para MinIO ou endpoints com CA própria |

### Rede

```yaml
truststore-icpbrasil:
  network:
    download-timeout-seconds: 60  # 30–300
    max-retries: 3                 # 1–10
    retry-interval-seconds: 30    # 10–300
```

### Revogação (OCSP e CRL)

```yaml
truststore-icpbrasil:
  revocation:
    ocsp-timeout-seconds: 10
    crl-timeout-seconds: 10
    max-retries: 2
    retry-interval-seconds: 3
    ocsp-cache-ttl-seconds: 3600
    crl-cache-ttl-seconds: 3600
```

O `RevocationService` verifica se um certificado foi revogado consultando OCSP e CRL. A estratégia é:

1. Tenta OCSP (se o certificado possuir a extensão AIA com endpoint OCSP)
2. Se OCSP for inconclusivo, tenta CRL (se o certificado possuir CRL Distribution Points)
3. Respostas OCSP e CRLs são cacheadas em memória com TTL configurável

O resultado é um `RevocationStatus` (sealed interface) com os seguintes estados:

| Status | Significado |
|---|---|
| `Good` | Certificado não revogado (inclui bytes da resposta para LTV) |
| `Revoked` | Certificado revogado |
| `NoDistributionPoints` | Certificado não possui extensões OCSP nem CRL |
| `OcspUnavailable` | Servidor OCSP inacessível após todas as tentativas |
| `CrlUnavailable` | CRL inacessível após todas as tentativas |
| `NoConnectivity` | Verificação interrompida (thread interrupted) |
| `Malformed` | Resposta OCSP ou CRL corrompida ou com status inesperado |

Se a seção `revocation` não for definida no YAML, valores padrão são aplicados automaticamente.

---

## Contexto SSL e segurança

A biblioteca cria um `SSLContext` interno usando **exclusivamente** os certificados embutidos em `registries/certificates/`. Esse contexto é encapsulado em `TrustStoreManager` e usado apenas para o download do acervo de ACs vigentes do repositório do ITI — não é exposto como bean Spring nem aplicado globalmente à JVM.

O isolamento é intencional: usar a truststore padrão da JVM para essa conexão exporia o download a um MITM com qualquer uma das ~150 CAs comerciais presentes no `cacerts`.

| Contexto | Trust utilizado |
|---|---|
| Download do acervo de ACs (repositório ITI) | Apenas CAs de `registries/certificates/` |
| Conexão S3 sem `S3_CA_CERT_PATH` | JVM default truststore (`cacerts`) |
| Conexão S3 com `S3_CA_CERT_PATH` | TrustManager dedicado com aquela CA |

**CAs embutidas em `registries/certificates/`:**

| Arquivo | Tipo | Propósito |
|---|---|---|
| `isrgrootx1.json` | Raiz (ISRG Root X1) | Âncora de confiança para cadeia E7 |
| `isrgrootx2.json` | Raiz (ISRG Root X2) | Âncora de confiança para cadeia E7 |
| `letsencrypt_e7.json` | Intermediário (E7) | Necessário pois `acraiz.icpbrasil.gov.br` não envia o intermediário no TLS handshake |

---

## Build e testes

```bash
./mvnw test
```

```bash
./mvnw clean install
```

```bash
./mvnw clean package -P standalone -DskipTests
```

---

## Backlog

- [ ] **Notificação de cache crítico** — webhook ou e-mail ao atingir `cache-ttl-critical-hours` sem sincronização
- [ ] **Notificação de cache expirado** — alerta de severidade máxima ao atingir `cache-ttl-max-hours`
- [ ] **Suporte a múltiplas CAs para S3** — `S3_CA_CERT_PATH` aceita apenas um certificado; suporte a bundle completo para cadeias intermediárias
