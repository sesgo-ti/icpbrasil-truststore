# Quero consultar a revogação de um certificado

Use o `RevocationService` quando precisar **só** do status de revogação de um certificado, já
sabendo quem é o emissor. Para decidir se um certificado é confiável, use o
[validador](validar-certificado.md), que já verifica a revogação de todo o caminho.

## 1. Consulte

```java
RevocationStatus status = revocationService.check(certificado, emissor);
```

Para guardar a prova (resposta OCSP ou CRL), use `revocationService.lookup(certificado, emissor)`,
que devolve o status junto com a evidência.

## 2. Trate o status

| Status | Significado |
|---|---|
| `Good` | Não revogado no instante da consulta; traz os bytes da resposta |
| `Revoked` | Revogado no instante da consulta |
| `NoDistributionPoints` | O certificado não informa OCSP nem CRL |
| `OcspUnavailable` | Servidor OCSP inacessível após todas as tentativas |
| `CrlUnavailable` | CRL inacessível ou inutilizável após todas as tentativas |
| `NoConnectivity` | Consulta interrompida |
| `Malformed` | Resposta corrompida, vencida, inválida ou de outro certificado |

Só `Good` indica "não revogado". Os demais estados, exceto `Revoked`, significam que não foi
possível saber.

## Comportamento

- Tenta OCSP. Se o resultado for inconclusivo, tenta a CRL.
- Respostas OCSP e CRLs ficam em cache em memória. Consultas simultâneas pela mesma CRL ou
  resposta OCSP compartilham um único download. Falhas não ficam em cache.
- A revogação vale a partir da data informada pela AC, como no JDK: uma revogação com data futura
  resulta em `Good`, com aviso no log. O cache guarda a evidência, não o veredito, então o
  resultado passa a `Revoked` assim que a data chega, sem esperar o TTL.
- Resposta de um respondedor OCSP delegado sem a extensão `id-pkix-ocsp-nocheck` só é aceita se a
  CRL da AC emissora estiver acessível. Sem ela, a resposta é recusada e a consulta segue para a CRL
  do próprio certificado.
- Uma CRL da ICP-Brasil pode ter de poucos kilobytes a dezenas de megabytes. Por isso o cache é
  limitado pelo tamanho do DER, não pela quantidade de entradas; a CRL decodificada ocupa mais que
  isso no heap: dimensione a memória com folga.

## Veja também

- [Segurança e rede](seguranca.md#saídas-de-rede-necessárias): o que liberar no firewall
- [Referência de configuração](configuracao.md#revogação): timeouts, tentativas e tamanho dos caches
