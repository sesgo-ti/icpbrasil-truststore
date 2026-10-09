# Segurança e rede

Quais conexões a biblioteca abre, em quem cada uma confia e como os downloads disparados por
certificados são protegidos.

## Saídas de rede necessárias

| Destino | Protocolo | Para quê | Quando |
|---|---|---|---|
| `acraiz.icpbrasil.gov.br` | HTTPS | Download do acervo | Sempre |
| `*.i.lencr.org` | HTTP | Intermediárias do certificado TLS do ITI | Sempre |
| Endereços OCSP, CRL e AIA das ACs | HTTP | Revogação e montagem de cadeia | Ao validar certificados |
| Endpoint do S3 | HTTPS | Gravar o acervo | Só com [armazenamento no S3](armazenamento-s3.md) |

Ao validar certificados, libere as CRLs e não só o OCSP: algumas ACs usam um respondedor OCSP
delegado que exige consultar também a CRL da AC.

## Em quem cada conexão confia

| Conexão | Confia em |
|---|---|
| Download do acervo (ITI) | Só nas raízes ISRG X1/X2 fixadas na biblioteca. As intermediárias vêm por AIA restrito a `i.lencr.org` e nunca são âncoras |
| AIA, OCSP e CRL | `cacerts` da JVM. As URLs são `http://`; a integridade vem da assinatura da resposta |
| S3 | `cacerts` da JVM ou a CA definida em `S3_CA_CERT_PATH` |

- A biblioteca não altera o `cacerts` nem o `SSLContext` da JVM, e não exige configurar truststore.
  O `SSLContext` do download do acervo é interno: não é exposto como bean.
- O endereço do acervo e a confiança no ITI e nas raízes ICP-Brasil **não mudam por configuração**.
  Só código da aplicação pode substituir a confiança, com um bean próprio (`TrustStoreManager`, `TrustMaterialSource`,
  `RaizesFixadas`, `Downloader` ou `CertificateHttpTransport`), e a biblioteca registra `WARN`
  quando isso acontece.
- Na subida, cada conexão registra em log em quem confia.

## Proteção dos downloads

As URLs de AIA, OCSP e CRL vêm de dentro dos certificados, ou seja, de quem enviou o certificado.
Para que não sejam usadas para atacar a rede interna (SSRF) ou esgotar a memória, todo download
desse tipo segue estas regras:

- Só `http` e `https`.
- Bloqueia localhost, endereços reservados e IPs privados.
- Não segue redirecionamentos.
- Corta a conexão assim que a resposta passa do tamanho máximo, inclusive em respostas de erro.
- Com `block-private-hostnames: true` (padrão), resolve o DNS antes e bloqueia se algum IP não for
  público (inclusive ULA `fc00::/7` e CGNAT `100.64.0.0/10`) ou se a resolução falhar. Desligue só
  em desenvolvimento, quando OCSP/CRL estão na rede interna.

Para aceitar só alguns domínios (a correspondência é por sufixo):

```yaml
icpbrasil-truststore:
  download-policy:
    allowed-domains:
      - icpbrasil.gov.br
      - serpro.gov.br
```

## Veja também

- [Referência de configuração](configuracao.md#proteção-dos-downloads): limites de tamanho
- [Atualizar raízes confiáveis](atualizar-raizes-confiaveis.md)
- [SECURITY.md](../SECURITY.md): como reportar vulnerabilidades
