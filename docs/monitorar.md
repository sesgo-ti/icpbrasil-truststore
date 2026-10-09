# Quero monitorar o acervo

Como saber se o acervo está carregado e atualizado, e quais logs indicam problema. Vale para a
biblioteca (com Actuator) e para o serviço REST.

## 1. Consulte o health

```bash
curl -s http://localhost:8080/actuator/health | jq '.components.trustStoreCache'
```

| Estado | Health | Significado | Ação |
|---|---|---|---|
| `VALID` | UP | Sincronizado com o ITI | Nenhuma |
| `CRITICAL` | UP | Sem atualização há mais de `cache-ttl-critical-hours` | Verificar a conexão com o ITI |
| `EXPIRED` | DOWN | Sem atualização há mais de `cache-ttl-max-hours`; acervo invalidado | **Imediata**: nenhum certificado é servido |
| `UNAVAILABLE` | DOWN | Nenhum acervo carregado | Verificar os logs da subida e a conexão com o ITI |

Se o detalhe `raizesNaoFixadas` (`subject` e `fingerprintSha256`) aparecer, o ITI publicou uma
raiz que a biblioteca não conhece; ela e seus descendentes ficam fora do acervo. Se o ZIP trouxer
só raízes desconhecidas, nada é publicado: o acervo atual segue até o prazo original. Confira o
fingerprint no DOU/ITI: se a raiz for legítima, siga
[atualizar raízes confiáveis](atualizar-raizes-confiaveis.md); se não, investigue o canal e o
armazenamento.

## 2. Configure as probes (Kubernetes)

| Probe | Endpoint |
|---|---|
| Liveness | `/actuator/health/liveness` |
| Readiness | `/actuator/health/readiness` |

A readiness deve incluir o acervo, para a instância só receber tráfego com ele carregado. O serviço
REST já vem assim; na biblioteca, adicione:

```properties
management.endpoint.health.group.readiness.include=readinessState,trustStoreCache
```

## 3. Alerte pelos logs

```bash
grep -E "(WARN|ERROR).*(TrustStoreService|TrustStoreBootstrap|Cache)" app.log
```

| Nível | Mensagem | Significado |
|---|---|---|
| WARN | `Falha na sincronização com o ITI; snapshot atual mantido até o prazo original` | O acervo anterior continua em uso até expirar |
| WARN | `Falha ao carregar acervo do repositório local` | Acervo gravado ilegível ou inválido |
| WARN | `Acervo local expirado desde` | O acervo gravado expirou; depende do ITI para voltar |
| WARN | `Falha ao persistir … no repositório local` | Acervo só em memória; a próxima subida dependerá do ITI |
| ERROR | `Raízes fora da lista fixada descartadas (requer conferência e release)` | Raiz desconhecida e seus descendentes não são servidos |
| ERROR | `Acervo ICP-Brasil indisponível: nenhum snapshot válido após a sincronização` | Nenhum certificado servido |
| ERROR | `aplicação subirá com cache indisponível (fail-fast=false)` | A carga inicial falhou e a aplicação subiu sem acervo |

Em operação normal aparecem, em `INFO`: `Executando atualização agendada do TrustStore`,
`O repositório local está sincronizado com a fonte ICP-Brasil` e
`Cache de certificados atualizado com {N} entradas (hash {H}, expira em {T})`.

## Veja também

- [Referência de configuração](configuracao.md): limiares `cache-ttl-*`
- [Segurança](seguranca.md): logs de confiança de cada conexão
