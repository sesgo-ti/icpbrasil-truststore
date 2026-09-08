# Monitoramento — Trust Store ICP-Brasil

## Health Check

```bash
curl -i http://localhost:8080/actuator/health/readiness
curl -i http://localhost:8080/actuator/health/liveness
```

### Estados do cache

| Estado interno | Health / HTTP após startup | Significado | Ação |
|---|---|---|---|
| `VALID` | UP / 200 | Snapshot dentro do limiar crítico | Nenhuma |
| `CRITICAL` | UP / 200 | Idade maior que o limiar crítico, ainda dentro do TTL | Verificar atualização pelo ITI e persistência |
| `EXPIRED` | DOWN / 503 | Prazo atingido ou relógio anterior à confirmação | **Ação imediata**, certificados indisponíveis |
| `UNAVAILABLE` | DOWN / 503 | Sem snapshot publicado | Investigar bootstrap/refresh |

Limiares configuráveis via `cache-ttl-critical-hours` (padrão: 72) e `cache-ttl-max-hours` (padrão: 168).

Health usa uma única observação de `Cache.getState()`: snapshot, validade e instante
do relógio do cache. Não consulta filesystem, S3 nem ITI. O prazo válido é
`[confirmedAt, expiresAt)`, portanto o instante exato do vencimento já retorna DOWN.
O limiar crítico é excedido estritamente; idade igual a 72 horas ainda é VALID.
Falhas de refresh não estendem o prazo; novo snapshot confirmado recupera readiness.
Probes não expõem mensagens de exceção, URLs de storage ou caminhos internos.

### Detalhes restritos

O standalone usa `management.endpoint.health.show-details=never`. Respostas públicas
mostram status (e nomes de grupos no health agregado), não os estados internos acima.
O serviço **não inclui Spring Security nem autenticação**: apenas mudar para
`when-authorized` não instala controle de acesso.

Para diagnóstico operacional, uma opção é separar a porta de gerenciamento:

```yaml
management:
  server:
    port: 9090
    address: 127.0.0.1
  endpoint:
    health:
      show-details: always
      group:
        readiness:
          show-details: never
        liveness:
          show-details: never
```

Este exemplo restringe o socket a loopback; permita acesso somente a operadores
autorizados por túnel SSH ou proxy autenticado. Em contêiner/Kubernetes, ajuste bind
e probes conforme a topologia e imponha firewall/NetworkPolicy, sem publicar a porta
de gerenciamento no ingress público. **Porta separada sozinha não autoriza acesso.**
Como alternativa, o consumidor pode instalar Spring Security, configurar autenticação
e roles e só então usar `show-details: when-authorized`.

Em uma sessão operacional autorizada no host, com a configuração restrita acima:

```bash
curl -s http://127.0.0.1:9090/actuator/health | jq '.components.trustStoreCache'
```

### Kubernetes probes

- `GET /actuator/health/liveness`
- `GET /actuator/health/readiness`

O YAML standalone já define readiness com `readinessState,trustStoreCache` e
liveness apenas com `livenessState`. Na biblioteca, o consumidor deve adicionar
Actuator e os grupos conforme [exemplo de integração](exemplo-integracao-lib.md).

Readiness exige aplicação aceitando tráfego **e** cache válido. Durante runners,
retorna 503 mesmo se o acervo local já estiver carregado; com cache vazio retorna
DOWN e com cache válido pode retornar OUT_OF_SERVICE. Depois do startup, cache
indisponível/expirado retorna 503, sem afetar liveness (200 enquanto o processo saudável).
Configure probes na porta efetivamente usada pelo Actuator. Roteamento deve remover
instâncias não prontas; probes não são uma barreira para HTTP direto. O runner ocorre
antes do `ApplicationReadyEvent`, mas o servidor e outros beans podem operar antes.

O scheduler tem executor dedicado e primeira execução após um intervalo completo
desde a criação do bean, inclusive sem bootstrap. Runner lento pode coincidir com
ele; `refresh()` sincronizado serializa a atualização, sem bloquear leituras/probes.

---

## Logs-chave

### Degradação (filtrar para alertas)

```bash
grep -E "WARN.*TrustStoreService|ERROR.*TrustStoreBootstrap" app.log
```

| Nível | Mensagem | Significado |
|---|---|---|
| WARN | `Refresh falhou; preservando apenas o prazo original do snapshot anterior` | Falha em download, validação ou persistência; TTL não renovado |
| WARN | `Acervo local indisponivel ou invalido` | Falha na carga inicial do storage; ainda tenta recuperação remota |
| ERROR | `Bootstrap concluído mas o cache permaneceu inválido` | Startup degradado se fail-fast=false; com fail-fast=true a exceção encerra o contexto |

Expiração ocorre nas leituras, mesmo sem refresh: não dependa de um log de transição
para alertar. Monitore readiness e, no canal restrito, o estado CRITICAL. Logs com
stack traces são operacionais e também precisam de controle de acesso.

### Operação normal

| Nível | Mensagem |
|---|---|
| INFO | `Executando atualização agendada do TrustStore` |
| INFO | `Bootstrap síncrono concluído com sucesso em {} ms` |

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
| 503 | Acervo indisponível/expirado; não equivale a SKI ausente |

Respostas do controller incluem `Cache-Control: no-store`. A consulta captura validade
e certificado no mesmo instante; health é uma observação independente, não uma reserva
de validade para a próxima requisição. Validação adicional de parâmetros fica fora deste contrato.
