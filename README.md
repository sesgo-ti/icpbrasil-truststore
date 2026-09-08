# Trust Store ICP-Brasil

[![Build](https://github.com/sesgo-ti/icpbrasil-truststore/actions/workflows/ci.yml/badge.svg)](https://github.com/sesgo-ti/icpbrasil-truststore/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/br.gov.go.saude/icpbrasil-truststore)](https://central.sonatype.com/artifact/br.gov.go.saude/icpbrasil-truststore)

Biblioteca de auto-configuração Spring Boot que mantém atualizado o acervo de certificados das Autoridades Certificadoras (ACs) vigentes da ICP-Brasil. Realiza download do repositório oficial publicado pelo ITI, verificação de integridade por hash SHA-512, cache em memória e sincronização automática.

> A `0.0.1` é uma candidata preparada localmente, ainda não publicada. As coordenadas
> abaixo antecipam a primeira release; não indicam disponibilidade no Maven Central.

## Módulos

| Módulo | Papel | Previsto no Maven Central |
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
    <version>0.0.1</version>
</dependency>
```

A biblioteca se auto-configura via mecanismo de auto-configuração do Spring Boot — nenhuma anotação `@Import` ou registro manual de beans é necessário.

Na inicialização, um `ApplicationRunner` síncrono revalida o acervo local, quando disponível, e tenta atualização pelo ITI antes do `ApplicationReadyEvent` e do retorno de `SpringApplication.run()`. O servidor HTTP pode aceitar requisições antes de o runner terminar. O roteamento deve respeitar readiness, que no standalone combina `readinessState` e `trustStoreCache`; `/certificate` retorna 503 se não houver snapshot válido.

Se o cache continuar inválido após a carga inicial, o startup é abortado por padrão (`bootstrap.fail-fast=true`). Uma falha remota pode ser tolerada enquanto o snapshot local revalidado ainda estiver no prazo original. Veja [Inicialização síncrona (bootstrap)](#inicialização-síncrona-bootstrap).

Para um exemplo completo de integração (incluindo o comportamento do bootstrap síncrono e testes), veja [docs/exemplo-integracao-lib.md](docs/exemplo-integracao-lib.md).

**Configuração mínima:**

```yaml
icpbrasil-truststore:
  storage:
    type: filesystem
  filesystem:
    base-dir: .data/icpbrasil-truststore
```

Este exemplo não requer AWS SDK nem Actuator. Os defaults existem no próprio
`TrustStoreConfig` (Java puro), inclusive quando nenhuma propriedade é informada.
O health indicator só é registrado se o Actuator estiver no classpath; para expor
`/actuator/health`, adicione `spring-boot-starter-actuator` à aplicação consumidora.

Para inicializar um contexto de teste **sem downloads nem agendamento**, acrescente
ao mesmo bloco `icpbrasil-truststore`:

```yaml
  bootstrap:
    enabled: false
  scheduling:
    enabled: false
```

Nesse caso o cache inicia vazio. Em produção, bootstrap e agendamento continuam
habilitados por padrão e precisam de acesso ao repositório oficial.

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
| `storage.truststore-archive-path` | `ACcompactado.zip` | Nome relativo ao diretório base ou chave S3 do ZIP |
| `storage.hash-file-path` | `hash.txt` | Nome relativo ao diretório base ou chave S3 do hash |
| `storage.confirmation-file-path` | `ultima_confirmacao.txt` | Nome relativo ao diretório base ou chave S3 da confirmação |
| `filesystem.base-dir` | `.data/icpbrasil-truststore` | Diretório local de armazenamento |
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

Na **biblioteca**, adicione `software.amazon.awssdk:s3` e
`software.amazon.awssdk:apache-client` (versões alinhadas pelo BOM AWS SDK, atualmente
`2.29.52`). Essas dependências são opcionais e não chegam transitivamente ao consumidor.
O standalone já inclui ambas. Selecionar `storage.type=s3` sem o SDK falha no startup
com uma mensagem indicando as dependências necessárias.

Configure todas as propriedades abaixo na aplicação consumidora. Este exemplo
faz explicitamente a ponte para os aliases de ambiente `S3_*`:

```yaml
icpbrasil-truststore:
  storage:
    type: s3
  s3:
    endpoint: "${S3_ENDPOINT:https://s3.amazonaws.com}"
    region: "${S3_REGION:us-east-1}"
    access-key: "${S3_ACCESS_KEY}"
    secret-key: "${S3_SECRET_KEY}"
    bucket: "${S3_BUCKET}"
    ca-cert-path: "${S3_CA_CERT_PATH:}"
```

Os aliases `S3_*` são definidos pelo **YAML do REST**, não pela auto-configuração.
Na biblioteca, use o YAML acima ou as propriedades canônicas
`icpbrasil-truststore.s3.endpoint`, `.region`, `.access-key`, `.secret-key`, `.bucket`
e `.ca-cert-path`. Endpoint, região, credenciais e bucket são obrigatórios e não têm
defaults no `S3Properties`; somente a CA é opcional. Não versione credenciais reais.

A auto-configuração registra um `S3Client` e o conecta ao `S3Repository`, sem operações
remotas durante a construção dos beans. Um bean `S3Client` fornecido pelo consumidor
é respeitado (inclusive sem `apache-client`); as propriedades S3 continuam validadas.
Nesse caso endpoint, credenciais e TLS do cliente são responsabilidade do consumidor,
e o repositório usa o bucket configurado. O cliente criado pela biblioteca é fechado
no shutdown. Bootstrap/agendamento podem acessar S3 após o wiring.

Aliases disponíveis no standalone (ou mediante a ponte YAML acima):

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
| `Malformed` | Evidência inválida ou não suportada; inclui identidade, assinatura, autorização, datas ou cobertura rejeitadas |

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

#### Contrato CRL

O `CrlClient.check` também consulta somente o **presente**. O chamador estabelece
a confiança no emissor e valida separadamente a cadeia PKIX e a validade do alvo/emissor;
`Good` não comprova validade histórica/LTV. Somente CRLs completas e diretas são aceitas.

- O DN do emissor do alvo deve corresponder ao subject do emissor informado, e a assinatura do alvo deve conferir com sua chave. O emissor deve ser CA (`basicConstraints`) e, se KeyUsage existir, permitir `cRLSign`. O DN e a assinatura da CRL também devem conferir com esse emissor.
- `thisUpdate` e `nextUpdate` são obrigatórios. `thisUpdate` não pode estar no futuro além de **5 minutos**; a CRL expira em `nextUpdate` mais 5 minutos, e `nextUpdate` não pode preceder `thisUpdate`, sem tolerância. Diferentemente de OCSP, não há aceitação sem `nextUpdate`.
- São rejeitados `deltaCRLIndicator` e qualquer `issuingDistributionPoint` (IDP), mesmo não críticos, inclusive IDP de motivos parciais, restrição de tipo ou CRL indireta. Não há composição de delta/base nem combinação de motivos. Qualquer DP do certificado com `reasons` ou `cRLIssuer` torna a consulta CRL inconclusiva, mesmo se outro DP não tiver restrições.
- Todas as extensões críticas de CRL ou de qualquer entrada são rejeitadas antes de `Good`/`Revoked`, inclusive as conhecidas mas não processadas. Entradas com `certificateIssuer` (mesmo não crítico) ou motivo `removeFromCRL` também são rejeitadas. A ausência do serial só produz `Good` após essas verificações de cobertura.
- Cada hit no cache por URL revalida a evidência inteira para o alvo, emissor e instante atuais. O TTL não prolonga a validade assinada; hit inválido retorna `Malformed`, sem novo download até remoção por TTL/eviction. O construtor com `Clock` controla o presente; os existentes usam `Clock.systemUTC()`.
- Evidência inválida ou formato não suportado retorna `Malformed`, um resultado **inconclusivo**, nunca confirmação de não revogação. Replay permanece possível dentro da janela temporal aceita.

O serviço tenta outros endpoints/mecanismos após resultado inconclusivo e só retorna
`Good`/`Revoked` mediante outra evidência aceita. Sem conclusão, preserva
`NoConnectivity` com prioridade sobre `Malformed`, em vez de ocultá-los como
indisponibilidade. Uma thread interrompida encerra os loops sem novas tentativas.

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

### Snapshot e limites do acervo

O `Cache` publica indice SKI, identidade SHA-512 do ZIP, `confirmedAt` e `expiresAt`
como uma unica geracao. Cada leitura verifica a janela `[confirmedAt, expiresAt)`;
na expiracao, consultas retornam `null` ou mapas vazios mesmo sem executar refresh.
`Cache()` usa UTC e `Cache(Clock)` permite controlar o relogio, usado tambem pelo
servico para confirmar geracoes. `getState()` fornece metadados e validade observada
sem I/O, inclusive metadados do snapshot expirado. Copias ja entregues ao consumidor
nao sao revogadas automaticamente.

`TrustStoreService.refresh()` serializa atualizacoes. Hash, parsing integral e indice
CA+SKI precisam ser validos antes de persistir ou publicar. Reconfirmar o hash remoto
exige validar os bytes correspondentes, nao apenas comparar o arquivo de hash local.
Uma falha conserva o snapshot anterior somente ate seu vencimento original. O pipeline
nao expoe metodos publicos para gravar artefatos ou alterar validade isoladamente.

No startup offline, o formato persistido permanece ZIP + hash SHA-512 + timestamp
`Instant` ISO-8601. A geracao local e revalidada e usa sua confirmacao original;
timestamps futuros ou expirados sao rejeitados, sem tolerancia de clock. A leitura
tambem falha fechada se o relogio retroceder para antes de `confirmedAt`.
Somente confirmacao remota valida pode renovar o prazo.

```yaml
icpbrasil-truststore:
  bundle:
    max-compressed-bytes: 20971520   # 20 MiB; intervalo 1..104857600
    max-entry-bytes: 1048576        # 1 MiB; intervalo 1..10485760
    max-expanded-bytes: 104857600   # 100 MiB; intervalo 1..524288000
    max-entries: 10000              # intervalo 1..100000
    max-hash-bytes: 4096            # intervalo 1..65536
```

Os defaults e a validacao dos limites existem no core, sem depender de Spring.
Entradas ignoradas e diretorios tambem consomem os orcamentos de expansao e contagem.
ZIP vazio, truncado, CRC invalido ou qualquer entrada de certificado invalida rejeita
a geracao inteira. O diretorio e limitado antes de materializar suas entradas;
ZIP64 e arquivos multipart nao sao aceitos. Entradas de certificado aceitam DER
individual ou PEM concatenado, sem conteudo residual. Certificados precisam ser CAs com SKI; nao se exige quantidade
minima de raizes nem validade X.509 atual. Para SKIs repetidos, permanece a selecao
da ultima ocorrencia na ordem fisica do ZIP; alternativas cross-signed nao sao
resolvidas por este indice.

O downloader ITI reutiliza o transporte bounded, mas preserva seu `SSLContext`
dedicado e nao aplica a politica DNS de extensoes X.509 ao host configurado pelo
administrador. Exige HTTPS, rejeita redirects e limita ZIP e hash durante o stream,
inclusive em erros HTTP. `network.download-timeout-seconds` cobre toda a troca de
cada tentativa, incluindo corpo parado ou lento; retries iniciam novo prazo.

**Limite da persistencia:** filesystem/S3 continuam com tres gravacoes independentes,
confirmacao por ultimo, sem transacao ou coordenacao entre processos. Falhas parciais
podem deixar artefatos inconsistentes ou bytes novos com timestamp anterior; a carga
seguinte revalida o conjunto, mas recuperacao transacional de geracoes fica fora deste
contrato. Cada cache/repositorio deve ter um unico servico escritor. O TTL do snapshot
nao substitui validacao PKIX nem a validade individual dos certificados.

### Inicialização síncrona (bootstrap)

```yaml
icpbrasil-truststore:
  bootstrap:
    enabled: true           # default — carga síncrona no startup
    fail-fast: true         # default: aborta startup se o cache continuar inválido
```

A carga inicial é executada pelo `ApplicationRunner` (`TrustStoreBootstrap`) de forma **síncrona**, antes do `ApplicationReadyEvent` e do retorno de `SpringApplication.run()`. Isso **não é uma barreira HTTP**: o contexto e o servidor podem estar ativos durante o runner. Outros beans, seus inicializadores e listeners anteriores também podem consumir o cache antes da carga; devem tratar indisponibilidade. A biblioteca não bloqueia globalmente endpoints de aplicações consumidoras.

No standalone, `/actuator/health/readiness` inclui `readinessState,trustStoreCache`:
somente retorna 200 quando a aplicação aceita tráfego e o snapshot está válido.
Configure o balanceador/orquestrador para retirar instâncias com readiness 503.
`/actuator/health/liveness` inclui somente `livenessState`, sem depender de ITI/S3.
Consumidores da biblioteca precisam adicionar Actuator e configurar esses grupos
explicitamente, conforme o [exemplo da lib](docs/exemplo-integracao-lib.md).

Health consulta apenas `Cache.getState()`, com validade e idade no mesmo instante do
relógio do cache, sem I/O de storage/rede. `VALID` e `CRITICAL` permanecem `UP`;
ausência de snapshot (`UNAVAILABLE`), expiração ou relógio anterior à confirmação
(`EXPIRED`) produzem `DOWN`. A janela é `[confirmedAt, expiresAt)`.
Uma probe é uma observação, não autorização para consultas futuras. `/certificate`
captura disponibilidade e certificado em uma única leitura (`Cache.lookupCertificate`),
distinguindo 503 de SKI ausente (404), e suas respostas usam `Cache-Control: no-store`.

Detalhes de health ficam ocultos por padrão (`show-details: never`). Para diagnóstico
restrito, configure a porta de gerenciamento e controle de acesso conforme o
[manual de monitoramento](docs/manual-monitoramento.md); o serviço não inclui autenticação.

**Comportamento conforme as flags:**

| `enabled` | `fail-fast` | Efeito no startup |
|---|---|---|
| `true` (padrão) | `true` (padrão) | Tenta carga/refresh; se o cache continuar inválido, lança `IllegalStateException` e encerra o contexto, sem desfazer HTTP já atendido |
| `true` | `false` | Se o cache continuar inválido, loga erro e conclui startup degradado, com readiness 503 |
| `false` | — | Sem carga pelo runner; depende do scheduler ou de chamada explícita a `refresh()` (útil em testes sem rede) |

**Quando desabilitar (`enabled: false`):**

- Testes que sobem o `ApplicationContext` sem acesso à internet e mockam `IcpBrasilCertificateProvider` ou o `Downloader`.
- Desenvolvimento local onde o consumidor deseja iterar rapidamente sem esperar o download.

**Relação com o scheduler:** `TrustStoreScheduler` usa um `ScheduledExecutorService` dedicado, sem ativar scheduling global do Spring. A primeira execução ocorre após um intervalo completo (`refresh-interval-hours`) desde a criação do bean, com ou sem bootstrap. Esse atraso não garante ausência de sobreposição com runner lento; `TrustStoreService.refresh()` sincronizado serializa as atualizações.

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
