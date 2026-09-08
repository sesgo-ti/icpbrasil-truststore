package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;

/**
 * Cliente CRL responsável por download, verificação de assinatura
 * e consulta de revogação em CRLs (Certificate Revocation Lists).
 */
@Slf4j
public class CrlClient {

    private final RevocationCache cache;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.RevocationConfig config;
    private final CertificateHttpTransport transport;
    private final DownloadPolicy downloadPolicy;

    /** Cria um cliente CRL com transporte sem redirects e limites durante o download. */
    public CrlClient(RevocationCache cache, RetryPolicy retryPolicy,
                     TrustStoreConfig trustStoreConfig, DownloadPolicy downloadPolicy) {
        this(cache, retryPolicy, trustStoreConfig.getRevocation(), HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(trustStoreConfig.getRevocation().getCrlTimeoutSeconds()))
                .build(), downloadPolicy);
    }

    /**
     * Usa um cliente pertencente ao chamador, sem alterar a política de download.
     * @throws IllegalArgumentException se o cliente não usar {@link HttpClient.Redirect#NEVER}
     */
    public CrlClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                     HttpClient httpClient, DownloadPolicy downloadPolicy) {
        this.cache = cache;
        this.retryPolicy = retryPolicy;
        this.config = config;
        this.transport = new CertificateHttpTransport(httpClient, downloadPolicy);
        this.downloadPolicy = downloadPolicy;
    }

    /**
     * Verifica revogação via CRL para a URL informada.
     * Consulta o cache antes de fazer a requisição HTTP.
     *
     * @param cert   certificado a verificar
     * @param issuer certificado do emissor (usado para verificar a assinatura da CRL)
     * @param url    URL do CRL Distribution Point
     * @return status de revogação obtido via CRL
     */
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer, String url) {
        Optional<byte[]> cached = cache.getCrl(url);
        if (cached.isPresent()) {
            log.debug("CRL encontrada no cache para {}", url);
            return parse(cached.get(), cert, issuer);
        }

        try {
            downloadPolicy.validateUrl(url);
        } catch (DownloadPolicyException e) {
            log.warn("URL CRL bloqueada pela política de download: {}", e.getMessage());
            return new RevocationStatus.CrlUnavailable();
        }

        try {
            byte[] crlBytes = retryPolicy.executeWithRetry(
                    "CRL " + url,
                    config.getMaxRetries(),
                    config.getRetryIntervalSeconds() * 1000L,
                    () -> download(url));

            downloadPolicy.validateCrlResponseSize(crlBytes, url);

            RevocationStatus result = parse(crlBytes, cert, issuer);
            if (result instanceof RevocationStatus.Good || result instanceof RevocationStatus.Revoked) {
                cache.putCrl(url, crlBytes);
            }
            return result;
        } catch (DownloadPolicyException e) {
            log.warn("Resposta CRL bloqueada pela política de download: {}", e.getMessage());
            return new RevocationStatus.CrlUnavailable();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Verificação CRL interrompida para {}", url);
            return new RevocationStatus.NoConnectivity();
        } catch (Exception e) {
            log.warn("CRL indisponível para {}: {}", url, e.getMessage());
            return new RevocationStatus.CrlUnavailable();
        }
    }

    private byte[] download(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(config.getCrlTimeoutSeconds()))
                .GET()
                .build();
        return transport.send(request, downloadPolicy.getMaxCrlResponseBytes());
    }

    /**
     * Parseia a CRL, verifica a assinatura com a chave do emissor e consulta
     * se o certificado está listado como revogado.
     */
    private RevocationStatus parse(byte[] crlBytes, X509Certificate cert, X509Certificate issuer) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlBytes));
            crl.verify(issuer.getPublicKey());
            if (crl.isRevoked(cert)) {
                return new RevocationStatus.Revoked("CRL");
            }
            return new RevocationStatus.Good("CRL", crlBytes);
        } catch (Exception e) {
            log.warn("Falha ao validar CRL: {}", e.getMessage());
            return new RevocationStatus.Malformed("CRL");
        }
    }
}
