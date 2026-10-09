# Quero montar a cadeia de um certificado

O `CertificateChainResolver` recebe um certificado e devolve a cadeia
`[certificado, intermediária..., raiz]`, baixando os emissores pela extensão AIA (CA Issuers).

> **Montar a cadeia não é validar.** O resolver só encadeia assinaturas até um certificado
> autoassinado qualquer, sem consultar o acervo, a validade ou a revogação. Para decidir se um
> certificado é confiável, use o [validador](validar-certificado.md).

## Uso

O starter já registra o bean.

```java
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;

List<X509Certificate> cadeia = certificateChainResolver.resolveChain(certificado);
```

Se a cadeia não chegar a um certificado autoassinado, o método lança `IncompleteChainException`.

## Comportamento

- Funciona com qualquer certificado X.509, não só ICP-Brasil.
- Aceita emissores em DER, PEM ou pacote PKCS#7 (`.p7b`).
- Profundidade máxima de 10 níveis, com detecção de referência circular.
- Entre vários emissores possíveis, escolhe o que tem assinatura válida, preferindo o autoassinado.
- Os downloads passam pela [proteção contra SSRF](seguranca.md#proteção-dos-downloads).

Timeouts e tentativas: [referência de configuração](configuracao.md#montagem-de-cadeia).
