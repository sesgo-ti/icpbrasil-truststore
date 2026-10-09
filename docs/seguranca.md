# Segurança: confiança e proteção dos downloads

## Em quem cada conexão confia

| Conexão | Confia em |
|---|---|
| Download do acervo (ITI) | Só nas raízes ISRG X1/X2 fixadas na biblioteca; intermediárias via AIA restrito a `i.lencr.org` |
| AIA, OCSP e CRL | `cacerts` da JVM. As URLs são `http://`; a integridade vem da assinatura da resposta |
| S3/MinIO | `cacerts` da JVM ou a CA definida em `S3_CA_CERT_PATH` |

- A biblioteca não altera o `cacerts` nem o `SSLContext` da JVM.
- A confiança no ITI e nas raízes ICP-Brasil **não muda por configuração**. Só código da aplicação
  pode substituí-la, com um bean próprio (`TrustStoreManager`, `TrustMaterialSource`,
  `RaizesFixadas`, `Downloader` ou `CertificateHttpTransport`), e a biblioteca registra `WARN`
  quando isso acontece.
- Na subida, cada conexão registra em log em quem confia.

## Proteção dos downloads

As URLs de AIA, OCSP e CRL vêm de dentro dos certificados, ou seja, de quem enviou o certificado.
Para que elas não sejam usadas para atacar a rede interna (SSRF) ou esgotar a memória, todo
download desse tipo passa por estas regras:

- Só `http` e `https`.
- Bloqueia localhost, endereços reservados e IPs privados.
- Não segue redirecionamentos.
- Corta a conexão assim que a resposta passa do tamanho máximo.
- Com `block-private-hostnames: true` (padrão), resolve o DNS antes e bloqueia se algum IP não for
  público. Desligue só em desenvolvimento, quando OCSP/CRL estão na rede interna.

Para aceitar só alguns domínios (a correspondência é por sufixo):

```yaml
icpbrasil-truststore:
  download-policy:
    allowed-domains:
      - icpbrasil.gov.br
      - serpro.gov.br
```

Limites de tamanho: [referência de configuração](configuracao.md#proteção-dos-downloads).

## Veja também

- Troca de CA do ITI ou nova raiz ICP-Brasil: [gestão das raízes confiáveis](manual-gestao-certificados-confiaveis.md).
- Sinais de falha: [monitoramento](manual-monitoramento.md).
- Como reportar vulnerabilidades: [SECURITY.md](../SECURITY.md).
