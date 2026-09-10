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
- Validação PKIX (RFC 5280) de certificados pelo `CertPathBuilder`/`CertPathValidator` do JDK, ancorada nas raízes do acervo, com revogação de todo o caminho
- Montagem de cadeia de certificados via AIA CA Issuers (suporte a DER, PEM e PKCS#7)
- Verificação de revogação de certificados via OCSP e CRL com cache e fallback automático
- Proteção contra SSRF e limites de tamanho configuráveis para downloads iniciados por extensões de certificados (AIA, OCSP, CRL)
- `SSLContext` e `X509TrustManager` com trust exclusivo nas CAs embutidas
- Health indicator (`/actuator/health`) com estados VALID / CRITICAL / EXPIRED / UNAVAILABLE

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

Na inicialização, um `ApplicationRunner` síncrono verifica se o acervo de ACs da ICP-Brasil já está disponível localmente. Se não, baixa do repositório oficial do ITI e popula o cache em memória (indexado por SKI — uma entrada por SKI: se o bundle trouxer dois certificados com a mesma chave, o último prevalece e o caso é registrado em WARN). O runner executa antes do `ApplicationReadyEvent`, mas o servidor HTTP pode aceitar conexões antes de o cache estar pronto: o health indicator `trustStoreCache` fica `DOWN` até a carga concluir — inclua-o no grupo de readiness (`management.endpoint.health.group.readiness.include=readinessState,trustStoreCache`) para que a instância só receba tráfego com acervo vigente.

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

Credenciais via variáveis de ambiente (no modo biblioteca, adicione `software.amazon.awssdk:s3` e `software.amazon.awssdk:apache-client` à aplicação — são dependências opcionais do `autoconfigure`):

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

O resultado é um `RevocationStatus` (sealed interface) com os seguintes estados; `lookup(cert, issuer)` devolve, junto do status, a evidência que o fundamenta (`RevocationEvidence`: resposta OCSP em DER ou CRL decodificada) quando ele é conclusivo:

| Status | Significado |
|---|---|
| `Good` | Certificado não revogado (inclui bytes da resposta para LTV) |
| `Revoked` | Certificado revogado |
| `NoDistributionPoints` | Certificado não possui extensões OCSP nem CRL |
| `OcspUnavailable` | Servidor OCSP inacessível após todas as tentativas |
| `CrlUnavailable` | CRL inacessível ou sem evidência utilizável após todas as tentativas |
| `NoConnectivity` | Verificação interrompida (thread interrupted) |
| `Malformed` | Resposta OCSP ou CRL corrompida, com status inesperado ou evidência inválida, vencida ou não correspondente ao certificado consultado |

Se a seção `revocation` não for definida no YAML, valores padrão são aplicados automaticamente.

### Validação de certificados (PKIX)

O `PkixCertificateValidator` responde se um certificado é confiável **agora**: constrói o caminho até uma raiz do acervo ICP-Brasil com o `CertPathBuilder` PKIX do JDK, valida-o (encadeamento de nomes, assinaturas, validade, BasicConstraints, KeyUsage, políticas, extensões críticas e `jdk.certpath.disabledAlgorithms`) e verifica a revogação de cada certificado do caminho.

```java
ValidationResult result = validator.validate(certificado);          // só o certificado
ValidationResult result = validator.validate(certificado, extras);  // com intermediárias conhecidas (ex.: de uma assinatura CMS)

switch (result) {
    case ValidationResult.Valid valid -> usar(valid.path(), valid.anchor(), valid.evidence());
    case ValidationResult.Revoked revoked -> rejeitar(revoked.certificate(), revoked.reason());
    case ValidationResult.Untrusted untrusted -> rejeitar(untrusted.reason());
    case ValidationResult.RevocationUndetermined undetermined -> rejeitar(undetermined.status());
    case ValidationResult.TrustStoreUnavailable unavailable -> indisponivel();
}
```

Somente `Valid` autoriza o uso do certificado; os demais estados são terminais e devem ser tratados como rejeição — inclusive `RevocationUndetermined`, que nunca equivale a "não revogado".

| Resultado | Significado |
|---|---|
| `Valid` | Caminho até uma âncora do acervo, válido na data da consulta e sem revogação; `path` (folha até o último intermediário), `anchor` e uma `evidence` por certificado do caminho |
| `Revoked` | Algum certificado do caminho consta como revogado; `revokedAt`, `reason` e a `evidence` (resposta OCSP ou CRL) que o sustenta |
| `Untrusted` | Não há caminho válido até uma âncora — `reason` é o motivo PKIX do JDK (`EXPIRED`, `NOT_YET_VALID`, `NO_TRUST_ANCHOR`, `INVALID_SIGNATURE`, ...) |
| `RevocationUndetermined` | Caminho confiável, mas a revogação de `certificate` não pôde ser determinada; `status` é o `RevocationStatus` correspondente |
| `TrustStoreUnavailable` | Acervo indisponível ou expirado; nenhuma validação é possível |

A revogação é verificada em duas camadas, certificado a certificado (da folha até o último intermediário): o `RevocationService` obtém e valida a evidência (OCSP, depois CRL) dentro da política de download, e o `PKIXRevocationChecker` do JDK a reavalia, alimentado exclusivamente com essa evidência — cada certificado é submetido como caminho de um só elemento ancorado no seu emissor, por isso a folha pode ser verificada por OCSP e a AC por CRL. O JDK não abre conexões por conta própria: o download de CRL exige a propriedade global `com.sun.security.enableCRLDP` e a consulta OCSP só ocorre sem resposta pré-fornecida. Evidência aceita pela biblioteca e rejeitada pelo JDK resulta em `RevocationUndetermined` com `Malformed`.

Emissores ausentes do acervo e dos `extras` são baixados via AIA pelo `CertificateChainResolver` apenas como candidatos. Para confiar em um emissor por outros meios (ex.: hierarquia de homologação, fora do acervo), use `validate(certificado, extras, TrustMaterial.anchoredAt(List.of(emissor)))`; a revogação da própria âncora não é verificada. Não há validação histórica (LTV): as evidências em `Valid.evidence()` ficam disponíveis para quem precisar preservá-las.

### Montagem de cadeia (AIA CA Issuers)

```yaml
icpbrasil-truststore:
  chain:
    download-timeout-seconds: 10  # 1–60
    max-retries: 1                # 0–5
    retry-interval-seconds: 2     # 1–30
```

O `CertificateChainResolver` recebe um certificado folha (leaf) e constrói a cadeia completa `[leaf, intermediário1, ..., raiz]` baixando os emissores via extensão AIA (Authority Information Access) — CA Issuers. O download pode retornar um certificado único (DER/PEM) ou um pacote PKCS#7 (.p7b) contendo a cadeia inteira.

> **O resolver não estabelece confiança.** Ele apenas encadeia assinaturas até *qualquer* auto-assinado, sem consultar o acervo nem verificar validade, BasicConstraints, KeyUsage ou políticas. Para decidir se um certificado é confiável, use o `PkixCertificateValidator` acima, que o emprega apenas como fonte de emissores via AIA.

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
- O limite de tamanho da resposta é aplicado durante o recebimento: a conexão é cancelada assim que o limite é excedido, inclusive em respostas de erro
- Redirects HTTP não são seguidos

**`block-private-hostnames`:** quando `true` (padrão), o hostname é resolvido via DNS antes do download — a conexão é bloqueada se algum IP resultante não for público (inclusive ULA `fc00::/7` e CGNAT `100.64.0.0/10`) ou se a resolução falhar. Desabilite em ambientes de desenvolvimento onde os servidores OCSP/CRL estão em rede interna.

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

A carga inicial do cache é executada por um `ApplicationRunner` (`TrustStoreBootstrap`) de forma **síncrona**, antes do `ApplicationReadyEvent`. O servidor HTTP pode aceitar conexões antes disso: quem impede tráfego até o cache carregar é a readiness (`readinessState` + `trustStoreCache`, configurada no serviço standalone), e o endpoint REST responde 503 enquanto não há acervo vigente.

**Comportamento conforme as flags:**

| `enabled` | `fail-fast` | Efeito no startup |
|---|---|---|
| `true` (padrão) | `true` (padrão) | Baixa e carrega o cache; se falhar, lança `IllegalStateException` e a aplicação **não sobe** |
| `true` | `false` | Baixa e carrega o cache; se falhar, loga erro e a aplicação sobe com cache vazio (não recomendado em produção) |
| `false` | — | Bootstrap desativado; cache só será populado na primeira execução do scheduler (útil em testes sem rede) |

**Quando desabilitar (`enabled: false`):**

- Testes que sobem o `ApplicationContext` sem acesso à internet e mockam `IcpBrasilCertificateProvider` ou o `Downloader`.
- Desenvolvimento local onde o consumidor deseja iterar rapidamente sem esperar o download.

**Relação com o scheduler:** o `TrustStoreScheduler` usa um executor dedicado (não `@Scheduled`) e sua primeira execução ocorre apenas após um intervalo completo (`refresh-interval-hours`), para não competir com a carga do bootstrap.

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
