# Integração — modo microserviço (standalone)

Uso como serviço HTTP independente. Consumidores consultam certificados por SKI via REST.

## 1. Build

```bash
./mvnw clean package -DskipTests
```

Gera `icpbrasil-truststore-rest/target/icpbrasil-truststore-rest-*.jar` (fat JAR executável — módulo `rest`).

## 2. Execução

```bash
java -jar icpbrasil-truststore-rest/target/icpbrasil-truststore-rest-*.jar \
  --icpbrasil-truststore.filesystem.base-dir=/data/truststore
```

O endpoint `/certificate` está sempre ativo — servir REST é a função deste módulo.

O runner tenta carregar o cache antes do `ApplicationReadyEvent`, não antes de abrir
HTTP. O servidor pode responder durante o bootstrap; `/certificate` retorna 503
enquanto não há snapshot válido. Se o cache continuar inválido após o refresh,
o processo encerra com erro (fail-fast). Nas subidas seguintes, o acervo local é
revalidado e o refresh ainda tenta confirmação remota, portanto o startup não é
necessariamente imediato. Falha remota conserva somente o prazo original do cache.

Configure o roteamento para respeitar `/actuator/health/readiness`: o grupo inclui
`readinessState,trustStoreCache`, recusando tráfego até o fim dos runners mesmo se
o cache local já estiver válido. `/actuator/health/liveness` inclui somente
`livenessState`, sem reiniciar a instância por indisponibilidade de ITI/S3.
Não há filtro global bloqueando HTTP; acesso direto pode contornar o roteamento.

## 3. Endpoints

### `GET /certificate`

Retorna um certificado indexado por SKI.

Disponibilidade e certificado são capturados em uma única consulta ao snapshot.
As respostas produzidas pelo controller usam `Cache-Control: no-store` para evitar
reutilização HTTP de um resultado após expiração ou recuperação do acervo.

**Query params:**

| Param | Obrigatório | Valores | Default | Descrição |
|---|---|---|---|---|
| `ski` | sim | hex lowercase | — | Subject Key Identifier do certificado |
| `type` | não | `pem` \| `der` | `pem` | Formato de saída |

**Respostas:**

| Código | Content-Type | Corpo |
|---|---|---|
| `200 OK` (pem) | `text/plain` | Certificado em PEM (`-----BEGIN CERTIFICATE-----` ...) |
| `200 OK` (der) | `application/x-x509-ca-cert` | Bytes DER. `Content-Disposition: attachment; filename=<ski>.der` |
| `400 Bad Request` | `text/plain` | `type` fora de `pem`/`der` |
| `404 Not Found` | — | SKI não está no acervo vigente |
| `503 Service Unavailable` | `text/plain` | Cache inválido/expirado — acervo temporariamente não confiável (distinto de 404) |
| `500 Internal Server Error` | — | Erro interno (conversão ou leitura do certificado) |

**Exemplos:**

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=pem"
```

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=der" --output certificado.der
```

### `GET /actuator/health`

Saúde agregada da aplicação, incluindo o cache, sem I/O em probes. Por padrão não
expõe componentes nem detalhes (`show-details: never`). Readiness retorna 200 para
cache `VALID`/`CRITICAL` após startup, e 503 para `UNAVAILABLE`/`EXPIRED`.
Diagnóstico restrito em [manual-monitoramento.md](manual-monitoramento.md).

```bash
curl http://localhost:8080/actuator/health
```

## 4. Variáveis de configuração relevantes

| Propriedade | Default | Quando mudar |
|---|---|---|
| `icpbrasil-truststore.storage.type` | `filesystem` | Usar `s3` para cache compartilhado entre instâncias |
| `icpbrasil-truststore.filesystem.base-dir` | — | Sempre definir (recomenda-se disco persistente para evitar re-download a cada restart) |
| `icpbrasil-truststore.bootstrap.enabled` | `true` | Manter `true` em produção |
| `icpbrasil-truststore.bootstrap.fail-fast` | `true` | Manter `true` em produção; trocar para `false` só em staging/dev que tolera subir degradado |
| `icpbrasil-truststore.scheduling.enabled` | `true` | Manter `true` (sincronização automática em background) |
| `icpbrasil-truststore.refresh-interval-hours` | `2` | Ajustar se precisar de sincronização mais/menos frequente |
| `server.port` | `8080` | Padrão Spring Boot |
| `management.server.port` | mesma porta HTTP | Separar gerenciamento em porta protegida por rede/proxy |

Credenciais para `storage.type=s3` são definidas via variáveis de ambiente (`S3_ENDPOINT`, `S3_REGION`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET`). Veja o [README](../README.md#armazenamento-s3-compatível).
