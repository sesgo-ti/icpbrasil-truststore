# Quero consultar a revogação de um certificado

Use o `RevocationService` quando precisar **só** do status de revogação de um certificado, já
sabendo quem é o emissor. Para decidir se um certificado é confiável, use o
[validador](validar-certificado.md), que já verifica a revogação de todo o caminho.

## 1. Consulte

O starter já registra o bean.

```java
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;

RevocationStatus status = revocationService.check(certificado, emissor);
```

Se precisar guardar a prova (resposta OCSP ou CRL), use `revocationService.lookup(certificado, emissor)`,
que devolve o status junto com a evidência.

## 2. Trate o status

| Status | Significado |
|---|---|
| `Good` | Não revogado no instante da consulta |
| `Revoked` | Revogado no instante da consulta |
| `NoDistributionPoints` | O certificado não informa OCSP nem CRL |
| `OcspUnavailable` | Servidor OCSP inacessível após todas as tentativas |
| `CrlUnavailable` | CRL inacessível ou inutilizável após todas as tentativas |
| `NoConnectivity` | Consulta interrompida |
| `Malformed` | Resposta corrompida, vencida, inválida ou de outro certificado |

Só `Good` indica "não revogado". Os demais estados, exceto `Revoked`, significam que não foi
possível saber.

## Como funciona

1. Tenta OCSP. Se o resultado for inconclusivo, tenta a CRL.
2. Respostas OCSP e CRLs ficam em cache em memória. Consultas simultâneas pela mesma CRL ou
   resposta OCSP compartilham um único download.
3. A revogação vale a partir da data informada pela AC: uma revogação com data futura resulta em
   `Good` até essa data chegar.

## Atenção

- **Firewall:** algumas ACs usam um respondedor OCSP delegado que exige consultar também a CRL da
  AC. Liberar só o OCSP não basta: libere o acesso HTTP às CRLs.
- **Memória:** uma CRL da ICP-Brasil pode ter dezenas de megabytes. O cache é limitado em bytes
  (`revocation.crl-cache-max-bytes`, padrão 256 MiB), mas a CRL decodificada ocupa mais que isso
  no heap: dimensione a memória com folga.

Timeouts, tentativas e tamanho dos caches: [referência de configuração](configuracao.md#revogação).
