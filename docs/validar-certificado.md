# Quero validar um certificado

O `PkixCertificateValidator` responde se um certificado é confiável **agora**: monta o caminho até
uma raiz ICP-Brasil do acervo, valida esse caminho com o JDK e verifica a revogação de cada
certificado nele.

## 1. Injete o validador

O starter já registra o bean.

```java
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;

@Service
public class AssinaturaService {

    private final PkixCertificateValidator validator;

    public AssinaturaService(PkixCertificateValidator validator) {
        this.validator = validator;
    }

    public boolean confiavel(X509Certificate certificado) {
        return validator.validate(certificado) instanceof ValidationResult.Valid;
    }
}
```

Se você já tem as intermediárias (por exemplo, de uma assinatura CMS), passe-as junto:
`validator.validate(certificado, intermediarias)`. O caminho é montado primeiro com as
intermediárias informadas e as do acervo. Só se isso não for suficiente os emissores são baixados
via AIA, e mesmo assim só como candidatos: a confiança continua vindo das raízes do acervo.

## 2. Trate o resultado

**Só `Valid` autoriza o uso do certificado.** Todo o resto é rejeição.

```java
switch (validator.validate(certificado)) {
    case ValidationResult.Valid valid -> usar(valid.path(), valid.anchor(), valid.evidence());
    case ValidationResult.Revoked revoked -> rejeitar(revoked.certificate(), revoked.reason());
    case ValidationResult.Untrusted untrusted -> rejeitar(untrusted.reason());
    case ValidationResult.RevocationUndetermined undetermined -> rejeitar(undetermined.status());
    case ValidationResult.TrustStoreUnavailable unavailable -> indisponivel();
}
```

| Resultado | Significado |
|---|---|
| `Valid` | Caminho válido até uma raiz do acervo e nenhum certificado revogado |
| `Revoked` | Algum certificado do caminho está revogado |
| `Untrusted` | Não há caminho válido até uma raiz (expirado, assinatura inválida, raiz desconhecida...) |
| `RevocationUndetermined` | Caminho válido, mas a revogação não pôde ser verificada. **Não** equivale a "não revogado" |
| `TrustStoreUnavailable` | Acervo indisponível ou expirado |

## Limites

- Raízes aceitas: só as fixadas na biblioteca (v5, v6, v7, v10, v11, v12).
- Certificados da hierarquia v7 resultam em `Untrusted`: o algoritmo dela (curva E-521) não é
  suportado pelo JDK.
- Não há validação histórica (LTV). As evidências de revogação ficam em `Valid.evidence()` para
  quem precisar guardá-las. Quando o OCSP vem de um respondedor delegado, a CRL que comprovou esse
  respondedor não é incluída, então essa resposta OCSP sozinha não basta para revalidar depois.
- Para confiar num emissor fora do acervo (por exemplo, homologação), use
  `validate(certificado, extras, TrustMaterial.anchoredAt(List.of(emissor)))`.

Timeouts e caches de revogação: [referência de configuração](configuracao.md).
