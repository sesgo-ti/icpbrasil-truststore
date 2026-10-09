# Referência de configuração

Todas as propriedades ficam sob o prefixo `icpbrasil-truststore`. Só `filesystem.base-dir` é
obrigatória (com o armazenamento padrão). As demais já têm valores adequados para produção: mude
apenas o que precisar.

## Acervo

| Propriedade | Padrão | Faixa | Descrição |
|---|---|---|---|
| `refresh-interval-hours` | `2` | 1 a `cache-ttl-critical-hours` | Intervalo entre verificações de atualização no ITI |
| `cache-ttl-critical-hours` | `72` | 24–168 | Horas sem atualização até o estado `CRITICAL` |
| `cache-ttl-max-hours` | `168` | 72–720, maior que o crítico | Horas sem atualização até o acervo expirar |
| `scheduling.enabled` | `true` | | Atualização automática em background |

## Armazenamento

| Propriedade | Padrão | Descrição |
|---|---|---|
| `storage.type` | `filesystem` | `filesystem` ou `s3` |
| `filesystem.base-dir` | — | Diretório do acervo. Veja [armazenamento em diretório](armazenamento-filesystem.md) |
| `s3.*` | — | Veja [armazenamento no S3](armazenamento-s3.md) |

## Inicialização

| Propriedade | Padrão | Descrição |
|---|---|---|
| `bootstrap.enabled` | `true` | Carrega o acervo durante a subida da aplicação |
| `bootstrap.fail-fast` | `true` | Se a carga inicial falhar, a aplicação não sobe |

| `enabled` | `fail-fast` | Efeito |
|---|---|---|
| `true` | `true` | Se a carga falhar, a aplicação não sobe (recomendado em produção) |
| `true` | `false` | Se a carga falhar, a aplicação sobe sem acervo e tenta de novo no próximo ciclo |
| `false` | — | Sem carga na subida; útil em testes sem rede |

Em testes que sobem o contexto Spring sem rede, desligue `bootstrap.enabled` e
`scheduling.enabled`.

## Download do acervo

| Propriedade | Padrão | Faixa |
|---|---|---|
| `network.download-timeout-seconds` | `60` | 30–300 |
| `network.max-retries` | `3` | 1–10 |
| `network.retry-interval-seconds` | `30` | 10–300 |

## Revogação

| Propriedade | Padrão | Faixa |
|---|---|---|
| `revocation.ocsp-timeout-seconds` | `10` | 1–60 |
| `revocation.crl-timeout-seconds` | `10` | 1–60 |
| `revocation.max-retries` | `2` | 0–10 |
| `revocation.retry-interval-seconds` | `3` | 1–60 |
| `revocation.ocsp-cache-ttl-seconds` | `3600` | 60–86400 |
| `revocation.crl-cache-ttl-seconds` | `3600` | 60–86400 |
| `revocation.ocsp-cache-max-bytes` | `16777216` (16 MiB) | 1 MiB–1 GiB |
| `revocation.crl-cache-max-bytes` | `268435456` (256 MiB) | 16 MiB–4 GiB |

## Montagem de cadeia

| Propriedade | Padrão | Faixa |
|---|---|---|
| `chain.download-timeout-seconds` | `10` | 1–60 |
| `chain.max-retries` | `1` | 0–5 |
| `chain.retry-interval-seconds` | `2` | 1–30 |

## Proteção dos downloads

Valem para AIA, OCSP e CRL. O que cada uma protege está em [segurança](seguranca.md#proteção-dos-downloads).

| Propriedade | Padrão | Faixa |
|---|---|---|
| `download-policy.max-ocsp-response-bytes` | `1048576` (1 MiB) | 1 KiB–10 MiB |
| `download-policy.max-crl-response-bytes` | `52428800` (50 MiB) | 1 KiB–500 MiB |
| `download-policy.max-aia-response-bytes` | `10485760` (10 MiB) | 1 KiB–100 MiB |
| `download-policy.block-private-hostnames` | `true` | |
| `download-policy.allowed-domains` | vazio (qualquer domínio público) | |
