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
| `icpbrasil-truststore-rest` | Microserviço standalone (endpoint REST + fat jar) | ❌ |

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
- `SSLContext` dedicado ao download do acervo: raízes ISRG fixadas, intermediárias via AIA restrito a `i.lencr.org`
- Health indicator (`/actuator/health`) com estados VALID / CRITICAL / EXPIRED / UNAVAILABLE

---

## Requisitos

- Java 21
- Spring Boot 3.5.x

---

## Modo 1: Biblioteca

Adicione a dependência:

```xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>icpbrasil-truststore-autoconfigure</artifactId>
    <version>0.0.1</version>
</dependency>
```

A biblioteca se auto-configura via mecanismo de auto-configuração do Spring Boot — nenhuma anotação `@Import` ou registro manual de beans é necessário.

Na inicialização, um `ApplicationRunner` síncrono verifica se o acervo de ACs da ICP-Brasil já está disponível localmente. Se não, baixa do repositório oficial do ITI e popula o cache em memória (indexado por SKI — uma entrada por SKI: se o bundle trouxer dois certificados com a mesma chave, o último prevalece e o caso é registrado em WARN). O runner executa antes do `ApplicationReadyEvent`, mas o servidor HTTP pode aceitar conexões antes de o cache estar pronto: o health indicator `trustStoreCache` fica `DOWN` até a carga concluir — inclua-o no grupo de readiness (`management.endpoint.health.group.readiness.include=readinessState,trustStoreCache`) para que a instância só receba tráfego com acervo vigente.

Se a carga inicial falhar (rede indisponível, hash inválido, timeout), o startup é abortado por padrão (`bootstrap.fail-fast=true`). Veja [Inicialização síncrona (bootstrap)](#inicialização-síncrona-bootstrap) para ajustar esse comportamento em testes ou cenários de desenvolvimento sem conectividade.

**Verificação da assinatura:** o Maven não verifica os arquivos `.asc` por padrão. Para exigir que as dependências estejam assinadas por chaves conhecidas, use o [`pgpverify-maven-plugin`](https://www.simplify4u.org/pgpverify-maven-plugin/) e inclua a chave de release no `keysMap` (fingerprint `8EF6 6D44 5A97 6C0A 2C3B 4FB5 566A 199A 481E 3355`, conforme [MAINTAINERS.md](MAINTAINERS.md#chave-gpg-de-release)).

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

O build é reproduzível: `project.build.outputTimestamp` fixa as datas gravadas nos JARs, e o
workflow de release usa a data do commit da tag, de modo que o mesmo commit gera os mesmos JARs. O
wrapper confere o SHA-256 da distribuição do Maven (`distributionSha256Sum`).

### Artefatos da release

Cada GitHub Release traz o executável REST, o SBOM CycloneDX (`*-sbom.cdx.json`) e o
`SHA256SUMS`. Confira depois de baixar:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

As bibliotecas `core` e `autoconfigure` são publicadas no Maven Central assinadas com GPG (veja
[MAINTAINERS.md](MAINTAINERS.md#chave-gpg-de-release)); os assets da GitHub Release não têm
assinatura GPG própria — a integridade é dada pelo `SHA256SUMS` publicado na mesma Release.

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
| `refresh-interval-hours` | `2` | Intervalo de verificação de atualizações (1 a `cache-ttl-critical-hours`) |
| `cache-ttl-critical-hours` | `72` | Horas sem atualização para estado CRITICAL (24–168) |
| `cache-ttl-max-hours` | `168` | Horas até o cache expirar (72–720, deve ser > critical) |
| `storage.type` | `filesystem` | `filesystem` ou `s3` |
| `scheduling.enabled` | `true` | Ativa a rotina de atualização em background |
| `bootstrap.enabled` | `true` | Executa carga síncrona do cache no startup |
| `bootstrap.fail-fast` | `true` | Falha no bootstrap aborta o startup |

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

### Layout do armazenamento

Filesystem e S3 gravam o acervo por **geração**: cada geração fica em `geracoes/<hash>/` (ZIP e
última confirmação) e o arquivo/objeto `hash.txt` na base é o ponteiro para a geração vigente.
Todo arquivo é escrito num temporário e movido atomicamente (no S3, o PUT de cada objeto é
atômico), e o ponteiro é trocado por último: uma interrupção no meio da escrita (queda do
processo, disco cheio) deixa vigente a geração anterior, completa.

- **Várias instâncias no mesmo diretório ou bucket:** gerações são imutáveis e endereçadas pelo
  hash, então instâncias que gravam a mesma geração escrevem o mesmo conteúdo; o ponteiro segue a
  última troca. Cada instância valida o SHA-512 do ZIP ao carregar.
- **Limpeza:** a cada commit são removidas as gerações que não são a vigente nem a anterior e que
  não mudam há mais de 24 h, além de temporários abandonados há mais de 24 h — o prazo evita
  apagar o commit em andamento de outra instância.
- **Migração:** o layout da 0.0.1 (ZIP, hash e confirmação soltos na base) é lido como geração e
  convertido no primeiro commit ou renovação, sem novo download.

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
    ocsp-cache-max-bytes: 16777216    # orçamento em bytes de DER (1 MiB–1 GiB)
    crl-cache-max-bytes: 268435456    # orçamento em bytes de DER (16 MiB–4 GiB)
```

Os caches de revogação são limitados por **bytes**, não por quantidade de entradas: uma CRL da
ICP-Brasil vai de poucos kilobytes a dezenas de megabytes. O peso de cada entrada é o tamanho do
DER; como a CRL fica guardada decodificada, ela ocupa mais que isso no heap — dimensione a memória
com folga. Consultas simultâneas pela mesma CRL (mesma URL) ou pela mesma resposta OCSP (mesmo
emissor, serial e responder) compartilham um único download; falhas não ficam memorizadas.

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

Raízes aceitas: só as fixadas em `RaizesFixadas` (v5, v6, v7, v10, v11, v12); raiz fora da lista e seus descendentes são descartados do acervo publicado.

A hierarquia v7 usa algoritmo proprietário (Kryptus, curva E-521) não suportado pelo JDK nem pelo BouncyCastle; certificados sob ela resultam em `Untrusted`.

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
- Emissor escolhido entre **todos** os candidatos com SKI igual ao AKI, exigindo subject igual ao issuer e assinatura válida; o autoassinado é preferido. Um SKI forjado ou a versão cross-signed de uma raiz não desviam a cadeia
- URLs CA Issuers tentadas em ordem até uma fornecer emissor utilizável
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

| Canal | Confiança |
|---|---|
| Download do acervo (ITI) | Raízes ISRG X1/X2 fixadas; intermediárias via AIA em `i.lencr.org` |
| AIA, OCSP e CRL | `cacerts` da JVM; URLs `http://` e integridade pela assinatura |
| S3/MinIO | `cacerts` da JVM ou a CA de `S3_CA_CERT_PATH` |

O `SSLContext` do download não é exposto como bean nem aplicado à JVM. A confiança no canal do ITI e nas raízes ICP-Brasil nunca muda por configuração; só código da aplicação pode alterá-la (bean próprio de `TrustStoreManager`, `TrustMaterialSource`, `RaizesFixadas`, `Downloader` ou `CertificateHttpTransport`), e a biblioteca registra `WARN` quando isso acontece. No S3, a confiança é configurada por `S3_CA_CERT_PATH`. A confiança de cada canal é registrada em log no início. Os downloads por extensões X.509 passam pelo `DownloadPolicy` descrito em [Política de download](#política-de-download-ssrf-e-limites-de-tamanho).

Troca de CA do ITI ou nova raiz ICP-Brasil: [manual de gestão](docs/manual-gestao-certificados-confiaveis.md). Sinais de falha: [monitoramento](docs/manual-monitoramento.md).

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

```bash
./mvnw package -DskipTests -Psbom   # SBOM CycloneDX agregado em target/bom.json
```
