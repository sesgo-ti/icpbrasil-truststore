package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
 * Este serviço é responsável pela orquestração, pela decisão de fallback e por fornecer ao
 * {@link OcspClient} a verificação de revogação do responder delegado sem
 * {@code id-pkix-ocsp-nocheck}: só a LCR da AC emissora do responder é consultada, evidência
 * independente da resposta em análise e que não dispara nova verificação de responder.</p>
 *
 * <p>O certificado é revogado a partir da data de revogação declarada na evidência, como no JDK e
 * no DSS: {@code Revoked} só quando essa data é igual ou anterior ao instante da consulta; com
 * data posterior o resultado é {@code Good}, com aviso no log. O cache guarda a evidência, e não
 * o veredito, de modo que o resultado muda quando a data chega.</p>
 *
 * <p>Nota: o HttpClient dos clients OCSP/CRL usa o trust store da JVM: as URLs de OCSP/CRL do
 * acervo são {@code http://}; a integridade vem da assinatura da resposta.</p>
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

        // A LCR da AC emissora costuma servir tanto ao responder delegado quanto ao fallback da
        // folha; sem memória, uma LCR fora do ar seria baixada (com retries) várias vezes na mesma
        // consulta. Local à chamada: nada é compartilhado entre threads nem entre consultas.
        Map<String, RevocationStatus> unavailableCrls = new HashMap<>();
        ResponderRevocationCheck responderCheck =
                (responder, responderIssuer) -> checkOcspResponder(responder, responderIssuer, unavailableCrls);

        boolean noConnectivity = false;
        for (String url : ocspUrls) {
            if (Thread.currentThread().isInterrupted()) {
                break;
            }
            RevocationLookup result = ocspClient.lookup(cert, issuer, url, responderCheck);
            if (result.isConclusive()) return result;
            noConnectivity |= result.status() instanceof RevocationStatus.NoConnectivity;
        }

        for (String url : crlUrls) {
            if (Thread.currentThread().isInterrupted()) {
                break;
            }
            RevocationLookup result = lookupCrl(cert, issuer, url, unavailableCrls);
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

    /** Status pela primeira LCR conclusiva do responder; qualquer outro resultado é inconclusivo. */
    private RevocationStatus checkOcspResponder(X509Certificate responder, X509Certificate issuer,
                                                Map<String, RevocationStatus> unavailableCrls) {
        List<String> crlUrls = CertificateParser.getCrlUrls(responder);
        if (crlUrls.isEmpty()) {
            return new RevocationStatus.NoDistributionPoints();
        }
        for (String url : crlUrls) {
            if (Thread.currentThread().isInterrupted()) {
                return new RevocationStatus.NoConnectivity();
            }
            RevocationStatus status = lookupCrl(responder, issuer, url, unavailableCrls).status();
            if (status.isConclusive()) {
                return status;
            }
        }
        return new RevocationStatus.CrlUnavailable();
    }

    /**
     * Consulta a LCR, salvo se a URL já ficou indisponível nesta chamada. Só a indisponibilidade é
     * lembrada, por ser da URL e não do certificado; {@code Malformed} pode depender do certificado
     * (escopo, DP), e uma LCR conclusiva já fica no cache do {@link CrlClient}.
     */
    private RevocationLookup lookupCrl(X509Certificate cert, X509Certificate issuer, String url,
                                       Map<String, RevocationStatus> unavailableCrls) {
        RevocationStatus unavailable = unavailableCrls.get(url);
        if (unavailable != null) {
            return RevocationLookup.inconclusive(unavailable);
        }
        RevocationLookup result = crlClient.lookup(cert, issuer, url);
        if (result.status() instanceof RevocationStatus.CrlUnavailable
                || result.status() instanceof RevocationStatus.NoConnectivity) {
            unavailableCrls.put(url, result.status());
        }
        return result;
    }
}
