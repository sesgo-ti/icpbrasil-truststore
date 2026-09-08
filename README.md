# Trust Store ICP-Brasil

[![Build](https://github.com/sesgo-ti/icpbrasil-truststore/actions/workflows/ci.yml/badge.svg)](https://github.com/sesgo-ti/icpbrasil-truststore/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/br.gov.go.saude/icpbrasil-truststore)](https://central.sonatype.com/artifact/br.gov.go.saude/icpbrasil-truststore)

Biblioteca de auto-configuração Spring Boot que mantém atualizado o acervo de certificados das Autoridades Certificadoras (ACs) vigentes da ICP-Brasil. Realiza download do repositório oficial publicado pelo ITI, verificação de integridade por hash SHA-512, cache em memória e sincronização automática.

## Módulos

| Módulo | Papel | Publicado no Maven Central |
|---|---|---|
| `icpbrasil-truststore-core` | Domínio e lógica (parsers X.509, cache, revogação OCSP/CRL, download) — **Java puro, zero Spring/AWS** | ✅ |
| `icpbrasil-truststore-autoconfigure` | Auto-configuração Spring Boot: beans, binding de properties, scheduler, bootstrap, health, S3 | ✅ |
| `icpbrasil-truststore-rest` | Microserviço standalone (endpoint REST + fat jar) | ❌ (artefato de deploy) |

Para consumir como **biblioteca**, dependa de `icpbrasil-truststore-autoconfigure`. Para rodar como **serviço**, use o fat jar do módulo `rest`.

Mantenedores: processo de release, chave GPG (renovação/revogação) e secrets estão centralizados em [MAINTAINERS.md](MAINTAINERS.md).

---

## Funcionalidades

- Download do acervo de ACs vigentes da ICP-Brasil (ZIP publicado pelo ITI) com verificação de hash SHA-512
- Cache em memória com TTL configurável e limiares de criticidade
- Sincronização automática em background
- Dois backends de armazenamento: filesystem local ou S3-compatível (MinIO, AWS S3, etc.)
- Endpoint REST opcional para consulta de certificados por SKI
- Montagem de cadeia de certificados via AIA CA Issuers (suporte a DER, PEM e PKCS#7)
- Verificação de revogação de certificados via OCSP e CRL com cache e fallback automático
- Proteção contra SSRF e limites de tamanho configuráveis para downloads iniciados por extensões de certificados (AIA, OCSP, CRL)
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
    <groupId>br.gov.go.saude</groupId>
    <artifactId>icpbrasil-truststore-autoconfigure</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

A biblioteca se auto-configura via mecanismo de auto-configuração do Spring Boot — nenhuma anotação `@Import` ou registro manual de beans é necessário.

Na inicialização, um `ApplicationRunner` síncrono verifica se o acervo de ACs da ICP-Brasil já está disponível localmente. Se não, baixa do repositório oficial do ITI e popula o cache em memória (indexado por SKI) **antes** de o Spring declarar o contexto "Started". Requisições só chegam à aplicação após o cache estar pronto — eliminando a race condition entre startup e scheduler.

Se a carga inicial falhar (rede indisponível, hash inválido, timeout), o startup é abortado por padrão (`bootstrap.fail-fast=true`). Veja [Inicialização síncrona (bootstrap)](#inicialização-síncrona-bootstrap) para ajustar esse comportamento em testes ou cenários de desenvolvimento sem conectividade.

Para um exemplo completo de integração (incluindo o comportamento do bootstrap síncrono e testes), veja [docs/exemplo-integracao-lib.md](docs/exemplo-integracao-lib.md).

**Configuração mínima:**

```yaml
icpbrasil-truststore:
  storage:
    type: filesystem
  filesystem:
    base-dir: .data/icpbrasil-truststore
```

---

## Modo 2: Serviço standalone

### Build

```bash
./mvnw clean package -DskipTests
```

Gera `icpbrasil-truststore-rest/target/icpbrasil-truststore-rest-*.jar` (fat JAR executável — módulo `rest`).

### Execução

```bash
java -jar icpbrasil-truststore-rest/target/icpbrasil-truststore-rest-*.jar \
  --icpbrasil-truststore.filesystem.base-dir=/data/truststore
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

Para detalhes sobre health check, estados do cache e logs de monitoramento, veja [docs/manual-monitoramento.md](docs/manual-monitoramento.md). Para um guia completo do modo standalone (endpoints, parâmetros e variáveis relevantes), veja [docs/exemplo-integracao-microservico.md](docs/exemplo-integracao-microservico.md).

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
| `scheduling.enabled` | `true` | Ativa a rotina de atualização em background |
| `bootstrap.enabled` | `true` | Executa carga síncrona do cache no startup |
| `bootstrap.fail-fast` | `true` | Falha no bootstrap aborta o startup |
| `trusted-certs.dir` | `classpath:registries/certificates` | Diretório com CAs fixas (JSON) |

### Armazenamento: filesystem

```yaml
icpbrasil-truststore:
  storage:
    type: filesystem
  filesystem:
    base-dir: .data/icpbrasil-truststore
```

### Armazenamento: S3-compatível

```yaml
icpbrasil-truststore:
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
icpbrasil-truststore:
  network:
    download-timeout-seconds: 60  # 30–300
    max-retries: 3                 # 1–10
    retry-interval-seconds: 30    # 10–300
```

### Revogação (OCSP e CRL)

```yaml
icpbrasil-truststore:
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
| `Good` | Evidência aceita de não revogação no presente (inclui bytes; não comprova validade histórica/LTV) |
| `Revoked` | Certificado revogado |
| `NoDistributionPoints` | Certificado não possui extensões OCSP nem CRL |
| `OcspUnavailable` | Servidor OCSP inacessível após todas as tentativas |
| `CrlUnavailable` | CRL inacessível após todas as tentativas |
| `NoConnectivity` | Verificação interrompida (thread interrupted) |
| `Malformed` | Evidência inválida; em OCSP inclui identidade, assinatura, autorização ou datas rejeitadas |

Se a seção `revocation` não for definida no YAML, valores padrão são aplicados automaticamente.

#### Contrato OCSP

O `OcspClient.check` consulta o **presente**, não o instante de uma assinatura histórica.
O chamador deve estabelecer a confiança no emissor; `Good` não substitui validação
de cadeia PKIX, validade do certificado alvo ou validação LTV. Os bytes retornados
podem ser arquivados, mas exigem validação histórica separada para esse uso.

- Exige serial e hashes do nome/chave do emissor no `CertID`, calculados com o algoritmo indicado na resposta via Bouncy Castle. São permitidos SHA-1 (identificação, não assinatura), SHA-224, SHA-256, SHA-384 e SHA-512. A assinatura do certificado alvo também deve conferir com o emissor informado.
- Respostas múltiplas são aceitas somente com um resultado correspondente ao alvo. Ausência ou duplicação desse resultado, inclusive com algoritmos distintos, é inconclusiva (`Malformed`).
- `thisUpdate` e `producedAt` não podem estar no futuro além de 5 minutos. `producedAt` deve estar entre `thisUpdate` e `nextUpdate` (quando presente), com a mesma tolerância. `nextUpdate` não pode preceder `thisUpdate`; a evidência expira em `nextUpdate` mais 5 minutos.
- Sem `nextUpdate`, a idade máxima de `thisUpdate` é **24 horas mais 5 minutos de tolerância**, independente de `ocsp-cache-ttl-seconds`. Esse TTL limita armazenamento, nunca prolonga a validade assinada.
- O ResponderID (nome ou hash da chave) deve corresponder ao assinante. São aceitos o emissor ou um delegado diretamente emitido por ele, não CA, com EKU `id-kp-OCSPSigning` e `digitalSignature` se KeyUsage estiver presente. O delegado deve estar válido no presente e em `producedAt`, sem tolerância nas datas do certificado.
- Extensões críticas de resposta/SingleResp são rejeitadas. No delegado, apenas basicConstraints, EKU e KeyUsage são processadas quando críticas; demais extensões críticas são rejeitadas conservadoramente. Não são consultadas a revogação do delegado ou cadeias alternativas de autorização.
- Cada hit no cache revalida identidade, assinatura, autorização e datas. A chave contém SHA-256 do DER do alvo e do emissor, compartilhada entre URLs. Um hit inválido retorna `Malformed`, sem nova requisição até a remoção por TTL/eviction; a facade preserva seu fallback CRL.
- Não há nonce: replay permanece possível dentro da janela temporal aceita. O construtor com `Clock` permite controlar o presente em testes; os construtores existentes usam `Clock.systemUTC()`.

Essas garantias são do caminho OCSP; não ampliam as garantias do fallback CRL.

### Montagem de cadeia (AIA CA Issuers)

```yaml
icpbrasil-truststore:
  chain:
    download-timeout-seconds: 10  # 1–60
    max-retries: 1                # 0–5
    retry-interval-seconds: 2     # 1–30
```

O `CertificateChainResolver` recebe um certificado folha (leaf) e constrói a cadeia completa `[leaf, intermediário1, ..., raiz]` baixando os emissores via extensão AIA (Authority Information Access) — CA Issuers. O download pode retornar um certificado único (DER/PEM) ou um pacote PKCS#7 (.p7b) contendo a cadeia inteira.

Características:

- **Independente do cache ICP-Brasil** — funciona com qualquer certificado X.509
- Profundidade máxima de 10 níveis, com detecção de referência circular
- Verificação criptográfica da assinatura em cada nível da cadeia
- Pool de certificados baixados (um p7b com cadeia completa evita downloads redundantes)
- Lança `IncompleteChainException` se não alcançar um certificado raiz (auto-assinado)

Se a seção `chain` não for definida no YAML, valores padrão são aplicados automaticamente.

### Política de download (SSRF e limites de tamanho)

```yaml
icpbrasil-truststore:
  download-policy:
    max-ocsp-response-bytes: 1048576   # 1 MB — padrão; intervalo válido: 1024–10485760
    max-crl-response-bytes: 52428800   # 50 MB — padrão; intervalo válido: 1024–524288000
    max-aia-response-bytes: 10485760   # 10 MB — padrão; intervalo válido: 1024–104857600
    block-private-hostnames: true      # Resolve DNS para bloquear IPs privados
    allowed-domains: []                # Lista de domínios permitidos (vazio = qualquer domínio público)
```

O `DownloadPolicy` protege contra SSRF (Server-Side Request Forgery) e exaustão de memória em downloads disparados por URLs extraídas de extensões de certificados X.509 (AIA CA Issuers, endpoints OCSP e pontos de distribuição de CRL).

**Validações sempre aplicadas:**

- Apenas esquemas `http` e `https` são permitidos
- Endereços localhost e reservados são bloqueados (127.x.x.x, ::1, etc.)
- IPs privados literais são bloqueados (10.x.x.x, 172.16–31.x.x, 192.168.x.x)
- O corpo é acumulado de forma compacta, com limite aplicado durante o recebimento e cancelamento ao excedê-lo, inclusive em respostas chunked e erros HTTP
- Redirects HTTP são rejeitados, sem acessar o destino de `Location`. Endpoints AIA, OCSP e CRL devem responder diretamente; clientes `HttpClient` injetados devem usar `Redirect.NEVER`
- O timeout de cada tentativa abrange toda a troca HTTP, incluindo o corpo, mesmo quando o servidor continua enviando bytes

**`block-private-hostnames`:** quando `true` (padrão), o hostname é resolvido via DNS antes do download; falhas de resolução ou qualquer endereço não público bloqueiam a conexão, incluindo ULA IPv6 e CGNAT. Desabilitar remove essa proteção para hostnames, mas não para IPs literais. A resolução da política depende do resolvedor da JVM e não está incluída no timeout HTTP. Como o IP validado não é fixado à conexão, DNS rebinding permanece um risco residual: restrinja também o egress na rede de execução.

**`allowed-domains`:** lista de sufixos de domínio. Quando vazia (padrão), qualquer domínio público é aceito. A correspondência é por sufixo do hostname: `icpbrasil.gov.br` cobre `ocsp.icpbrasil.gov.br`, `crl.icpbrasil.gov.br`, etc. Exemplo para restringir apenas a domínios governamentais:

```yaml
icpbrasil-truststore:
  download-policy:
    allowed-domains:
      - icpbrasil.gov.br
      - caixa.gov.br
      - serpro.gov.br
```

Se a seção `download-policy` não for definida no YAML, valores padrão são aplicados automaticamente.

### Inicialização síncrona (bootstrap)

```yaml
icpbrasil-truststore:
  bootstrap:
    enabled: true           # default — carga síncrona no startup
    fail-fast: true         # default — aborta startup se a carga falhar
```

A carga inicial do cache é executada por um `ApplicationRunner` (`TrustStoreBootstrap`) de forma **síncrona**, antes de o Spring Boot declarar o contexto "Started". Isso garante que nenhuma requisição seja atendida enquanto o cache estiver vazio — eliminando a race condition em que a aplicação aceitava assinaturas antes de o scheduler completar o primeiro download.

**Comportamento conforme as flags:**

| `enabled` | `fail-fast` | Efeito no startup |
|---|---|---|
| `true` (padrão) | `true` (padrão) | Baixa e carrega o cache; se falhar, lança `IllegalStateException` e a aplicação **não sobe** |
| `true` | `false` | Baixa e carrega o cache; se falhar, loga erro e a aplicação sobe com cache vazio (não recomendado em produção) |
| `false` | — | Bootstrap desativado; cache só será populado na primeira execução do scheduler (útil em testes sem rede) |

**Quando desabilitar (`enabled: false`):**

- Testes que sobem o `ApplicationContext` sem acesso à internet e mockam `IcpBrasilCertificateProvider` ou o `Downloader`.
- Desenvolvimento local onde o consumidor deseja iterar rapidamente sem esperar o download.

**Relação com o scheduler:** com o bootstrap habilitado, a primeira execução do `TrustStoreScheduler` ocorre apenas após um intervalo completo (`refresh-interval-hours`) — o `initialDelay` do `@Scheduled` foi ajustado para não competir com a carga do bootstrap.

---

## Contexto SSL e segurança

A biblioteca cria um `SSLContext` interno usando **exclusivamente** os certificados embutidos em `registries/certificates/`. Esse contexto é encapsulado em `TrustStoreManager` e usado apenas para o download do acervo de ACs vigentes do repositório do ITI — não é exposto como bean Spring nem aplicado globalmente à JVM.

O isolamento é intencional: usar a truststore padrão da JVM para essa conexão exporia o download a um MITM com qualquer uma das ~150 CAs comerciais presentes no `cacerts`.

| Contexto | Trust utilizado |
|---|---|
| Download do acervo de ACs (repositório ITI) | Apenas CAs de `registries/certificates/` |
| Conexão S3 sem `S3_CA_CERT_PATH` | JVM default truststore (`cacerts`) |
| Conexão S3 com `S3_CA_CERT_PATH` | TrustManager dedicado com aquela CA |
| Downloads de AIA CA Issuers, OCSP e CRL | JVM default truststore (`cacerts`) — sem `SSLContext` personalizado |

> **Diferença importante:** Ao contrário do download do acervo ITI — que usa um `SSLContext` isolado com CAs próprias —, os downloads disparados por extensões de certificados X.509 (AIA CA Issuers, endpoints OCSP, CRL Distribution Points) **não possuem isolamento de `SSLContext`**. Esses endpoints são públicos, operados pelas próprias ACs, e a confiança no certificado TLS deles recai sobre a truststore padrão da JVM. A camada de segurança aplicada a esses downloads é o `DownloadPolicy` — um mecanismo distinto que atua na validação da URL de destino (bloqueio de SSRF, IPs privados, esquemas não-HTTP(S)) e no limite de tamanho da resposta antes de carregá-la em memória. Veja a seção [Política de download](#política-de-download-ssrf-e-limites-de-tamanho) para detalhes de configuração.

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
./mvnw clean package -DskipTests
```

---

## Backlog

- [ ] **Notificação de cache crítico** — webhook ou e-mail ao atingir `cache-ttl-critical-hours` sem sincronização
- [ ] **Notificação de cache expirado** — alerta de severidade máxima ao atingir `cache-ttl-max-hours`
- [ ] **Suporte a múltiplas CAs para S3** — `S3_CA_CERT_PATH` aceita apenas um certificado; suporte a bundle completo para cadeias intermediárias
