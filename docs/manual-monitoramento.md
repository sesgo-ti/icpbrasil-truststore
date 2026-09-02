# Monitoramento — Trust Store ICP-Brasil

## Health Check

```bash
curl -s http://localhost:8080/actuator/health | jq '.components.trustStoreCache'
```

### Estados do cache

| Estado | HTTP | Significado | Ação |
|---|---|---|---|
| `VALID` | UP | Sincronizado com ITI | Nenhuma |
| `CRITICAL` | UP | Sem atualização além do limiar crítico | Verificar conectividade com repositório ITI |
| `EXPIRED` | DOWN | Sem atualização além do limiar máximo — cache invalidado | **Ação imediata** — certificados indisponíveis |
| `UNKNOWN` | UNKNOWN | Erro ao verificar saúde | Investigar logs |

Limiares configuráveis via `cache-ttl-critical-hours` (padrão: 72) e `cache-ttl-max-hours` (padrão: 168).

### Kubernetes probes

- `GET /actuator/health/liveness`
- `GET /actuator/health/readiness`

Cache `EXPIRED` → readiness probe `DOWN`.

---

## Logs-chave

### Degradação (filtrar para alertas)

```bash
grep -E "ERROR.*(TrustStoreService|Cache)" app.log
```

| Nível | Mensagem | Significado |
|---|---|---|
| ERROR | `Cache crítico - falha prolongada na atualização` | Sem sync além do limiar crítico, cache ainda ativo |
| ERROR | `Cache expirado - não há como garantir segurança` | Cache invalidado |
| ERROR | `Falha ao repor artefatos no repositório local` | Download ou armazenamento falhou |
| ERROR | `Falha na validação de integridade do zip` | ZIP corrompido ou hash divergente |

### Operação normal

| Nível | Mensagem |
|---|---|
| INFO | `Executando atualização agendada do TrustStore` |
| INFO | `O repositório local está sincronizado com a fonte ICP-Brasil` |
| INFO | `Cache de certificados atualizado com {N} entradas.` |

---

## Endpoint REST de certificados

Requer `icpbrasil-truststore.rest.enabled=true`.

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=pem"
```

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=der" --output cert.der
```

| Código | Significado |
|---|---|
| 200 | Certificado retornado |
| 404 | SKI não encontrado |
| 400 | Tipo inválido (usar `pem` ou `der`) |

