package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Serviço de verificação de revogação de certificados via OCSP e CRL.
 *
 * <p>Estratégia de verificação:</p>
 * <ol>
 *   <li>Tenta OCSP se o certificado possui extensão AIA com endpoints OCSP</li>
 *   <li>Faz fallback para CRL se o OCSP for inconclusivo e existirem CRL Distribution Points</li>
 * </ol>
 *
 * <p>A lógica de protocolo é delegada a {@link OcspClient} e {@link CrlClient}.
 * Este serviço é responsável apenas pela orquestração e decisão de fallback.</p>
 *
 * <p>Nota: o HttpClient usado pelos clients OCSP/CRL utiliza o trust store padrão da JVM
 * intencionalmente, pois os endpoints de revogação são acessados via CAs públicas.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RevocationService {

    private final OcspClient ocspClient;
    private final CrlClient crlClient;

    /**
     * Verifica se um certificado foi revogado, tentando OCSP primeiro e CRL como fallback.
     *
     * @param cert   certificado a verificar
     * @param issuer certificado do emissor (necessário para construir a requisição OCSP)
     * @return status de revogação — ver {@link RevocationStatus} para os possíveis resultados
     */
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer) {
        List<String> ocspUrls = CertificateParser.getOcspUrls(cert);
        List<String> crlUrls = CertificateParser.getCrlUrls(cert);

        if (ocspUrls.isEmpty() && crlUrls.isEmpty()) {
            return new RevocationStatus.NoDistributionPoints();
        }

        for (String url : ocspUrls) {
            RevocationStatus result = ocspClient.check(cert, issuer, url);
            if (isConclusive(result)) return result;
        }

        for (String url : crlUrls) {
            RevocationStatus result = crlClient.check(cert, issuer, url);
            if (isConclusive(result)) return result;
        }

        return crlUrls.isEmpty()
                ? new RevocationStatus.OcspUnavailable()
                : new RevocationStatus.CrlUnavailable();
    }

    /**
     * Determina se um resultado é conclusivo (Good, Revoked ou Malformed)
     * ou se deve prosseguir para o próximo mecanismo de verificação.
     */
    private boolean isConclusive(RevocationStatus status) {
        return status instanceof RevocationStatus.Good
                || status instanceof RevocationStatus.Revoked
                || status instanceof RevocationStatus.Malformed;
    }
}
