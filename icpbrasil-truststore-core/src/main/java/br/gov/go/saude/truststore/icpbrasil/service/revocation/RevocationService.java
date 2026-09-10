package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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
@RequiredArgsConstructor
public class RevocationService {

    private final OcspClient ocspClient;
    private final CrlClient crlClient;

    /**
     * Verifica se um certificado foi revogado, tentando OCSP primeiro e CRL como fallback.
     *
     * <p>Resultados inconclusivos nunca viram {@code Good}: sem conclusão em nenhuma URL, o
     * retorno é {@code NoConnectivity} se alguma tentativa foi interrompida, senão
     * {@code CrlUnavailable} (ou {@code OcspUnavailable} quando não há CRL). Uma interrupção da
     * thread encerra as tentativas restantes.</p>
     *
     * @param cert   certificado a verificar
     * @param issuer certificado do emissor (necessário para construir a requisição OCSP)
     * @return status de revogação — ver {@link RevocationStatus} para os possíveis resultados
     */
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer) {
        return lookup(cert, issuer).status();
    }

    /**
     * Como {@link #check}, devolvendo também, para os status conclusivos, a evidência (resposta
     * OCSP ou CRL) que os fundamenta.
     */
    public RevocationLookup lookup(X509Certificate cert, X509Certificate issuer) {
        List<String> ocspUrls = CertificateParser.getOcspUrls(cert);
        List<String> crlUrls = CertificateParser.getCrlUrls(cert);

        if (ocspUrls.isEmpty() && crlUrls.isEmpty()) {
            return RevocationLookup.inconclusive(new RevocationStatus.NoDistributionPoints());
        }

        boolean noConnectivity = false;
        for (String url : ocspUrls) {
            if (Thread.currentThread().isInterrupted()) {
                break;
            }
            RevocationLookup result = ocspClient.lookup(cert, issuer, url);
            if (result.isConclusive()) return result;
            noConnectivity |= result.status() instanceof RevocationStatus.NoConnectivity;
        }

        for (String url : crlUrls) {
            if (Thread.currentThread().isInterrupted()) {
                break;
            }
            RevocationLookup result = crlClient.lookup(cert, issuer, url);
            if (result.isConclusive()) return result;
            noConnectivity |= result.status() instanceof RevocationStatus.NoConnectivity;
        }

        if (noConnectivity || Thread.currentThread().isInterrupted()) {
            return RevocationLookup.inconclusive(new RevocationStatus.NoConnectivity());
        }
        return RevocationLookup.inconclusive(crlUrls.isEmpty()
                ? new RevocationStatus.OcspUnavailable()
                : new RevocationStatus.CrlUnavailable());
    }
}
