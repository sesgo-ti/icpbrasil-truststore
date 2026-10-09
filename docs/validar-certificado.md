# Quero validar um certificado

O `PkixCertificateValidator` responde se um certificado é confiável **agora**: monta o caminho até
uma raiz ICP-Brasil do acervo, valida esse caminho com o `CertPathValidator` do JDK (encadeamento
de nomes, assinaturas, validade, BasicConstraints, KeyUsage, políticas, extensões críticas e
`jdk.certpath.disabledAlgorithms`) e verifica a revogação de cada certificado nele.

## 1. Valide

```java
ValidationResult resultado = validator.validate(certificado);
```

Se você já tem as intermediárias (por exemplo, de uma assinatura CMS), passe-as junto:
`validator.validate(certificado, intermediarias)`. O caminho é montado primeiro com as
intermediárias informadas e as do acervo. Só se isso não bastar os emissores são baixados via AIA,
e mesmo assim só como candidatos: a confiança continua vindo das raízes do acervo.

## 2. Trate o resultado

**Só `Valid` autoriza o uso do certificado.** Todo o resto é rejeição.

```java
switch (resultado) {
    case ValidationResult.Valid valid -> usar(valid.path(), valid.anchor(), valid.evidence());
    case ValidationResult.Revoked revoked -> rejeitar(revoked.certificate(), revoked.reason());
    case ValidationResult.Untrusted untrusted -> rejeitar(untrusted.reason());
    case ValidationResult.RevocationUndetermined undetermined -> rejeitar(undetermined.status());
    case ValidationResult.TrustStoreUnavailable unavailable -> indisponivel();
}
```

| Resultado | Significado |
|---|---|
| `Valid` | Caminho válido até uma raiz do acervo e nenhum certificado revogado. Traz `path` (da folha ao último intermediário), `anchor` e uma `evidence` por certificado do caminho |
| `Revoked` | Algum certificado do caminho está revogado. Traz `certificate`, `revokedAt`, `reason` e a `evidence` |
| `Untrusted` | Não há caminho válido até uma raiz. `reason` é o motivo PKIX do JDK (`EXPIRED`, `NOT_YET_VALID`, `NO_TRUST_ANCHOR`, `INVALID_SIGNATURE`...) |
| `RevocationUndetermined` | Caminho válido, mas a revogação não pôde ser verificada. **Não** equivale a "não revogado" |
| `TrustStoreUnavailable` | Acervo indisponível ou expirado |

## Como a revogação é verificada

Certificado a certificado, da folha ao último intermediário, em duas camadas: o
[`RevocationService`](verificar-revogacao.md) obtém e valida a evidência (OCSP, depois CRL), e o
`PKIXRevocationChecker` do JDK a reavalia usando só essa evidência, sem abrir conexões. Por isso a
folha pode ser verificada por OCSP e a AC por CRL. Se as duas camadas discordarem, o resultado é
`RevocationUndetermined` com status `Malformed`, e um aviso vai para o log.

## Limites

- Raízes aceitas: só as fixadas na biblioteca (v5, v6, v7, v10, v11, v12).
- Certificados da hierarquia v7 resultam em `Untrusted`: o algoritmo dela (curva E-521) não é
  suportado pelo JDK.
- Não há validação histórica (LTV). As evidências de revogação ficam em `Valid.evidence()` para
  quem precisar guardá-las. Quando o OCSP vem de um respondedor delegado, a CRL que comprovou esse
  respondedor não é incluída, então essa resposta OCSP sozinha não basta para revalidar depois.
- Para confiar num emissor fora do acervo (por exemplo, homologação), use
  `validate(certificado, extras, TrustMaterial.anchoredAt(List.of(emissor)))`. A revogação da
  própria âncora não é verificada.

## Veja também

- [Revogação](verificar-revogacao.md): status e comportamento da consulta OCSP/CRL
- [Segurança e rede](seguranca.md#saídas-de-rede-necessárias): o que liberar no firewall
- [Referência de configuração](configuracao.md#revogação)
