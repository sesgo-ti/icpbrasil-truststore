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
grep -E "(WARN|ERROR).*(TrustStoreService|TrustStoreBootstrap)" app.log
```

| Nível | Mensagem | Significado |
|---|---|---|
| WARN | `Falha na sincronização com o ITI; snapshot atual mantido até o prazo original` | Download, hash, bundle ou rede falharam; acervo anterior segue servido até expirar |
| WARN | `Falha ao carregar acervo do repositório local` | Storage ilegível, hash divergente ou bundle inválido na carga local |
| WARN | `Acervo local expirado desde` | Confirmação persistida além de `cache-ttl-max-hours`; depende do ITI para voltar a servir |
| WARN | `Falha ao persistir … no repositório local` | Acervo válido apenas em memória; próximo cold start dependerá do ITI |
| ERROR | `Acervo ICP-Brasil indisponível: nenhum snapshot válido após a sincronização` | Nenhum certificado servido (endpoint responde 503) |
| ERROR | `aplicação subirá com cache indisponível (fail-fast=false)` | Bootstrap falhou e o startup prosseguiu sem acervo |

### Operação normal

| Nível | Mensagem |
|---|---|
| INFO | `Executando atualização agendada do TrustStore` |
| INFO | `O repositório local está sincronizado com a fonte ICP-Brasil` |
| INFO | `Cache de certificados atualizado com {N} entradas (hash {H}, expira em {T}).` |

---

## Endpoint REST de certificados

Disponível no módulo `rest` (sempre ativo no serviço).

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

