# Endpoints REST

Referência dos endpoints do [serviço REST](subir-servico.md).

## `GET /certificate`

Devolve o certificado de uma AC do acervo pelo SKI.

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=pem"
```

```bash
curl "http://localhost:8080/certificate?ski=<SKI>&type=der" --output certificado.der
```

### Parâmetros

| Parâmetro | Obrigatório | Valores | Padrão |
|---|---|---|---|
| `ski` | sim, uma vez | Hexadecimal com quantidade par de dígitos (2 a 128), maiúsculas ou minúsculas | — |
| `type` | não, no máximo uma vez | `pem` ou `der`, sem distinção de caixa | `pem` |

O SKI é normalizado para minúsculas. Seu tamanho não é fixo: 20 octetos (SHA-1) é o mais comum,
mas a RFC 5280 admite outros métodos. Se houver mais de um certificado com o mesmo SKI, devolve o
[preferido](usar-como-biblioteca.md#3-use).

### Respostas

| Código | Quando | Corpo |
|---|---|---|
| `200` | Certificado encontrado | PEM (`text/plain`) ou DER (`application/x-x509-ca-cert`, como anexo `<ski>.der`) |
| `400` | `ski` ou `type` ausente, repetido ou inválido | Mensagem (`text/plain`) |
| `503` | Acervo não carregado ou expirado | Mensagem (`text/plain`) |
| `404` | SKI válido que não está no acervo | — |
| `500` | Erro interno | — |

Os parâmetros são validados antes de consultar o acervo: entrada inválida responde `400` mesmo
com o acervo indisponível. Todas as respostas saem com `Cache-Control: no-store`.

## `GET /actuator/health`

Saúde do serviço e do acervo. Estados e probes: [monitoramento](monitorar.md).

## Veja também

- [Subir o serviço](subir-servico.md)
