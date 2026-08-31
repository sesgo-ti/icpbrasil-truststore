# Integração — modo microserviço (standalone)

Uso como serviço HTTP independente. Consumidores consultam certificados por SKI via REST.

## 1. Build

```bash
./mvnw clean package -P standalone -DskipTests
```

Gera `target/icpbrasil-truststore-*-standalone.jar` (fat JAR executável).

## 2. Execução

```bash
java -jar target/icpbrasil-truststore-*-standalone.jar \
  --truststore-icpbrasil.rest.enabled=true \
  --truststore-icpbrasil.storage.filesystem.base-dir=/data/truststore
```

O parâmetro `rest.enabled=true` é obrigatório — é ele que registra o `TrustStoreController` com o endpoint `/certificate`.

Na primeira subida, a aplicação baixa o acervo ICP-Brasil do ITI e popula o cache antes de aceitar requisições. Se o download falhar, o processo encerra com erro (fail-fast). Nas subidas seguintes, se o `base-dir` contém um acervo válido, o startup é imediato.

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
| `404 Not Found` | — | SKI não está no cache |
| `500 Internal Server Error` | — | Erro interno (conversão ou leitura do certificado) |

**Exemplos:**

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=pem"
```

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=der" --output certificado.der
```

### `GET /actuator/health`

Saúde da aplicação, inclui o estado do cache (`VALID`, `CRITICAL`, `EXPIRED`). Detalhes em [manual-monitoramento.md](manual-monitoramento.md).

```bash
curl http://localhost:8080/actuator/health
```

## 4. Variáveis de configuração relevantes

| Propriedade | Default | Quando mudar |
|---|---|---|
| `truststore-icpbrasil.rest.enabled` | `false` | **Obrigatório `true`** no modo server |
| `truststore-icpbrasil.storage.type` | `filesystem` | Usar `s3` para cache compartilhado entre instâncias |
| `truststore-icpbrasil.filesystem.base-dir` | — | Sempre definir (recomenda-se disco persistente para evitar re-download a cada restart) |
| `truststore-icpbrasil.bootstrap.enabled` | `true` | Manter `true` em produção |
| `truststore-icpbrasil.bootstrap.fail-fast` | `true` | Manter `true` em produção; trocar para `false` só em staging/dev que tolera subir degradado |
| `truststore-icpbrasil.scheduling.enabled` | `true` | Manter `true` (sincronização automática em background) |
| `truststore-icpbrasil.refresh-interval-hours` | `2` | Ajustar se precisar de sincronização mais/menos frequente |
| `server.port` | `8080` | Padrão Spring Boot |

Credenciais para `storage.type=s3` são definidas via variáveis de ambiente (`S3_ENDPOINT`, `S3_REGION`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET`). Veja o [README](../README.md#armazenamento-s3-compatível).
