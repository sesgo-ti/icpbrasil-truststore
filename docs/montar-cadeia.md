# Quero montar a cadeia de um certificado

O `CertificateChainResolver` recebe um certificado e devolve a cadeia
`[certificado, intermediária..., raiz]`, baixando os emissores pela extensão AIA (CA Issuers).

**Montar a cadeia não é validar.** O resolver só encadeia assinaturas até um certificado
autoassinado qualquer, sem consultar o acervo, a validade ou a revogação. Para decidir se um
certificado é confiável, use o [validador](validar-certificado.md).

## 1. Monte

```java
List<X509Certificate> cadeia = certificateChainResolver.resolveChain(certificado);
```

Se a cadeia não chegar a um certificado autoassinado, o método lança `IncompleteChainException`.

## Comportamento

- Funciona com qualquer certificado X.509, não só ICP-Brasil.
- Aceita emissores em DER, PEM ou pacote PKCS#7 (`.p7b`).
- Profundidade máxima de 10 níveis, com detecção de referência circular.
- O emissor é escolhido entre **todos** os candidatos com SKI igual ao AKI, exigindo subject igual
  ao issuer e assinatura válida; o autoassinado é preferido. Um SKI forjado ou a versão
  cross-signed de uma raiz não desviam a cadeia.
- As URLs de CA Issuers são tentadas em ordem até uma fornecer um emissor utilizável.
- Certificados já baixados são reaproveitados: um `.p7b` com a cadeia completa evita novos
  downloads.

## Veja também

- [Segurança e rede](seguranca.md#proteção-dos-downloads): regras aplicadas aos downloads
- [Referência de configuração](configuracao.md#montagem-de-cadeia): timeouts e tentativas
