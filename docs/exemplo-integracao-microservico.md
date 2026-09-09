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

Na primeira subida, a aplicação baixa o acervo ICP-Brasil do ITI e popula o cache antes do `ApplicationReadyEvent`; o servidor HTTP pode aceitar conexões antes disso, mas a readiness (`readinessState` + `trustStoreCache`) fica `DOWN` e `/certificate` responde 503 até o cache carregar. Se o download falhar, o processo encerra com erro (fail-fast). Nas subidas seguintes, se o `base-dir` contém um acervo válido, o startup é imediato.

## 3. Endpoints

### `GET /certificate`

Retorna um certificado indexado por SKI.

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

Saúde da aplicação, inclui o estado do cache (`VALID`, `CRITICAL`, `EXPIRED`, `UNAVAILABLE`). Detalhes em [manual-monitoramento.md](manual-monitoramento.md).

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

Credenciais para `storage.type=s3` são definidas via variáveis de ambiente (`S3_ENDPOINT`, `S3_REGION`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET`). Veja o [README](../README.md#armazenamento-s3-compatível).
