# Exemplo de integração — modo microserviço (standalone)

## Quando usar

Consumir como microserviço standalone faz sentido quando:

- Múltiplos serviços precisam consultar o acervo ICP-Brasil — evita que cada um faça seu próprio download.
- Há restrições de egress (apenas um pod com saída para `acraiz.icpbrasil.gov.br`).
- O consumidor não é Spring/JVM — integra via HTTP (`GET /certificate?ski=...`).

## Diferenças em relação ao modo biblioteca

| Aspecto | Modo biblioteca | Modo microserviço |
|---|---|---|
| Execução | Incorporado ao host (JAR do consumidor) | Processo próprio (fat JAR executável) |
| Acesso ao cache | `Cache.getCertificateBySki(ski)` (estático) | `GET /certificate?ski=...` (HTTP) |
| Controle do startup | Host decide como reagir ao `IllegalStateException` | Kubernetes (ou orquestrador) reage ao exit code != 0 |
| Endpoint REST | `rest.enabled=false` (default) | `rest.enabled=true` (obrigatório) |
| Probes | N/A — a saúde é a do host | `/actuator/health` com `liveness`/`readiness` separados |

O fluxo de bootstrap é o mesmo nos dois modos: `TrustStoreBootstrap` carrega o cache antes do contexto estar "Started". A diferença é **quem reage** ao fail-fast.

---

## 1. Build

```bash
./mvnw clean package -P standalone -DskipTests
```

Resultado: `target/trust-store-icpbrasil-*-standalone.jar` (fat JAR executável).

## 2. Execução local

```bash
java -jar target/trust-store-icpbrasil-*-standalone.jar \
  --truststore-icpbrasil.rest.enabled=true \
  --truststore-icpbrasil.storage.filesystem.base-dir=/data/truststore
```

## 3. Consumo por HTTP

PEM:

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=pem"
```

DER:

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=der" --output certificado.der
```

Health:

```bash
curl http://localhost:8080/actuator/health
```

---

## 4. Deploy em Kubernetes — fluxo recomendado

O bootstrap síncrono + `fail-fast=true` é a combinação ideal para Kubernetes. Se o primeiro download falhar, o processo sai com exit code != 0, o pod fica em `CrashLoopBackOff` e o K8s reagenda — em vez de um pod subindo "Ready" e servindo 404 para certificados válidos.

### Dockerfile mínimo

```dockerfile
FROM eclipse-temurin:21-jre
COPY target/trust-store-icpbrasil-*-standalone.jar /app/app.jar
ENTRYPOINT ["java","-jar","/app/app.jar"]
```

### Manifesto com probes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: trust-store-icpbrasil
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: trust-store
          image: registry.example/trust-store-icpbrasil:0.0.2
          args:
            - --truststore-icpbrasil.rest.enabled=true
            - --truststore-icpbrasil.storage.filesystem.base-dir=/data/truststore
          ports:
            - name: http
              containerPort: 8080
          volumeMounts:
            - name: cache
              mountPath: /data/truststore
          # startupProbe cobre o bootstrap: o pod ganha tempo para baixar o ZIP
          # na primeira subida sem que liveness/readiness falhem prematuramente.
          startupProbe:
            httpGet:
              path: /actuator/health/liveness
              port: http
            failureThreshold: 30   # 30 * 5s = 150s total — acomoda retries do downloader
            periodSeconds: 5
          readinessProbe:
            httpGet:
              path: /actuator/health/readiness
              port: http
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /actuator/health/liveness
              port: http
            periodSeconds: 30
      volumes:
        - name: cache
          persistentVolumeClaim:
            claimName: trust-store-cache   # recomendado: persistir o cache entre restarts
```

### Por que um `PersistentVolumeClaim`?

Sem PVC, cada restart do pod começa com cache vazio → bootstrap baixa do ITI novamente. Isso:

- Adiciona latência ao startup (alguns segundos de download).
- Depende da disponibilidade do ITI durante todo restart.
- Gera tráfego desnecessário contra o repositório oficial.

Com PVC, restarts rápidos reutilizam o cache no disco — o bootstrap valida o hash existente e popula o cache em memória sem I/O de rede.

---

## 5. Configuração das propriedades de bootstrap

Em produção (K8s):

```yaml
truststore-icpbrasil:
  bootstrap:
    enabled: true       # default — mantenha
    fail-fast: true     # default — deixar o K8s decidir via CrashLoopBackOff
```

Em staging com rede intermitente (aceita subir degradado):

```yaml
truststore-icpbrasil:
  bootstrap:
    enabled: true
    fail-fast: false    # aplicação sobe com cache vazio; readinessProbe sinaliza DOWN
```

Com `fail-fast=false`, o pod sobe mas `/actuator/health` responderá `DOWN` (o `TrustStoreCacheHealthIndicator` verifica `Cache.isCacheValid()`). O `readinessProbe` então retira o pod do load balancer até o scheduler (2h depois, por padrão) popular o cache. Em geral, não recomendado para produção — prefira `fail-fast=true` + `PersistentVolumeClaim` para o cache.

---

## 6. Checklist do consumidor em modo microserviço

- [ ] Build com perfil `standalone` (fat JAR).
- [ ] `rest.enabled=true` (senão o endpoint `/certificate` não existe).
- [ ] `bootstrap.enabled=true` e `fail-fast=true` (defaults).
- [ ] Volume persistente para o `base-dir` — evita downloads repetidos.
- [ ] `startupProbe` com `failureThreshold` suficiente para cobrir o pior cenário de download (download-timeout × max-retries × retry-interval). Com defaults (`60s × 3 × 30s`), considerar até ~5 min.
- [ ] Monitoramento: alarmar quando `/actuator/health` reportar `CRITICAL` ou `EXPIRED` (veja [manual-monitoramento.md](manual-monitoramento.md)).
- [ ] Egress liberado para `acraiz.icpbrasil.gov.br` (TLS).
