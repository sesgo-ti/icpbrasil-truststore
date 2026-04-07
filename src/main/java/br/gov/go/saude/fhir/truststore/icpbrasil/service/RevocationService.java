package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Certificate revocation checking service using OCSP and CRL.
 *
 * <p>Verification strategy:</p>
 * <ol>
 *   <li>Tries OCSP if the certificate has an AIA extension with OCSP endpoints</li>
 *   <li>Falls back to CRL if OCSP is inconclusive and CRL Distribution Points exist</li>
 * </ol>
 *
 * <p>OCSP responses and CRLs are cached in memory via {@link RevocationCache}.
 * Operational parameters (timeouts, retries, TTLs) are read from
 * {@link TrustStoreConfig.RevocationConfig}.</p>
 */
@Slf4j
@Service
public class RevocationService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final RevocationCache cache;
    private final TrustStoreConfig.RevocationConfig config;
    private final HttpClient httpClient;

    public RevocationService(RevocationCache cache, TrustStoreConfig trustStoreConfig) {
        this.cache = cache;
        this.config = trustStoreConfig.getRevocation();
        httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Checks whether a certificate has been revoked by trying OCSP first, then CRL.
     *
     * @param cert   the certificate to verify
     * @param issuer the issuer certificate (required to build the OCSP request)
     * @return the revocation status — see {@link RevocationStatus} for possible outcomes
     */
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer) {
        List<String> ocspUrls = CertificateParser.getOcspUrls(cert);
        List<String> crlUrls = CertificateParser.getCrlUrls(cert);

        if (ocspUrls.isEmpty() && crlUrls.isEmpty()) {
            return new RevocationStatus.NoDistributionPoints();
        }

        for (String url : ocspUrls) {
            RevocationStatus result = tryOcsp(cert, issuer, url);
            if (isConclusive(result)) return result;
        }

        for (String url : crlUrls) {
            RevocationStatus result = tryCrl(cert, issuer, url);
            if (isConclusive(result)) return result;
        }

        return crlUrls.isEmpty()
                ? new RevocationStatus.OcspUnavailable()
                : new RevocationStatus.CrlUnavailable();
    }

    /**
     * Determines whether a result is conclusive (Good, Revoked, or Malformed)
     * or should fall through to the next verification mechanism.
     *
     * @param status the revocation status to evaluate
     * @return {@code true} if the status is final and no further checks are needed
     */
    private boolean isConclusive(RevocationStatus status) {
        return status instanceof RevocationStatus.Good
                || status instanceof RevocationStatus.Revoked
                || status instanceof RevocationStatus.Malformed;
    }

    /**
     * Attempts revocation checking via OCSP. Checks the cache before making an HTTP request.
     *
     * @param cert   the certificate to verify
     * @param issuer the issuer certificate
     * @param url    the OCSP responder URL
     * @return the revocation status from the OCSP check
     */
    private RevocationStatus tryOcsp(X509Certificate cert, X509Certificate issuer,
                                     String url) {
        String cacheKey = cert.getSerialNumber().toString(16) + "|" + cert.getIssuerX500Principal().getName();

        Optional<byte[]> cached = cache.getOcsp(cacheKey);
        if (cached.isPresent()) {
            log.debug("Resposta OCSP encontrada no cache para {}", cacheKey);
            return parseOcspResponse(cached.get(), cert, issuer);
        }

        try {
            byte[] responseBytes = executeWithRetry(config.getMaxRetries(), config.getRetryIntervalSeconds(), () -> {
                byte[] requestBytes = buildOcspRequest(cert, issuer);
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(config.getOcspTimeoutSeconds()))
                        .header("Content-Type", "application/ocsp-request")
                        .header("Accept", "application/ocsp-response")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(requestBytes))
                        .build();
                HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() != 200) {
                    throw new IOException("OCSP HTTP status: " + response.statusCode());
                }
                return response.body();
            });

            cache.putOcsp(cacheKey, responseBytes);
            return parseOcspResponse(responseBytes, cert, issuer);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Verificação OCSP interrompida para {}", url);
            return new RevocationStatus.NoConnectivity();
        } catch (Exception e) {
            log.warn("OCSP indisponível para {}: {}", url, e.getMessage());
            return new RevocationStatus.OcspUnavailable();
        }
    }

    /**
     * Builds a DER-encoded OCSP request for the given certificate.
     *
     * @param cert   the certificate to query
     * @param issuer the issuer certificate (used to compute the certificate ID)
     * @return the OCSP request as a DER-encoded byte array
     * @throws Exception if the request cannot be built
     */
    private byte[] buildOcspRequest(X509Certificate cert, X509Certificate issuer) throws Exception {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID certId = new CertificateID(
                digCalcProv.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuer),
                cert.getSerialNumber()
        );
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);
        return builder.build().getEncoded();
    }

    /**
     * Parses an OCSP response, verifies its signature and maps it to the corresponding
     * revocation status.
     *
     * @param responseBytes the raw OCSP response (DER-encoded)
     * @param cert          the certificate being checked
     * @param issuer        the issuer certificate (used to verify the response signature)
     * @return the revocation status derived from the OCSP response
     */
    private RevocationStatus parseOcspResponse(byte[] responseBytes, X509Certificate cert,
                                                X509Certificate issuer) {
        try {
            OCSPResp ocspResp = new OCSPResp(responseBytes);
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                log.warn("Resposta OCSP com status não-sucesso: {}", ocspResp.getStatus());
                return new RevocationStatus.Malformed("OCSP");
            }
            BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
            if (!verifyOcspSignature(basicResp, issuer)) {
                log.warn("Assinatura da resposta OCSP inválida para certificado serial {}",
                        cert.getSerialNumber().toString(16));
                return new RevocationStatus.Malformed("OCSP");
            }
            for (SingleResp singleResp : basicResp.getResponses()) {
                CertificateStatus status = singleResp.getCertStatus();
                if (status == CertificateStatus.GOOD) {
                    return new RevocationStatus.Good("OCSP", responseBytes);
                } else if (status instanceof RevokedStatus) {
                    return new RevocationStatus.Revoked("OCSP");
                } else if (status instanceof UnknownStatus) {
                    log.warn("OCSP retornou status unknown para certificado serial {}",
                            cert.getSerialNumber().toString(16));
                    return new RevocationStatus.Malformed("OCSP");
                }
            }
            return new RevocationStatus.Malformed("OCSP");
        } catch (Exception e) {
            log.warn("Falha ao processar resposta OCSP: {}", e.getMessage());
            return new RevocationStatus.Malformed("OCSP");
        }
    }

    /**
     * Verifies the OCSP response signature per RFC 6960 Section 3.2.
     * Accepts responses signed by the issuer CA directly or by a delegated responder
     * with {@code id-kp-OCSPSigning} EKU issued by the same CA.
     *
     * @param basicResp the parsed OCSP response
     * @param issuer    the CA that issued the certificate being checked
     * @return {@code true} if the signature is valid and the signer is authorized
     */
    private boolean verifyOcspSignature(BasicOCSPResp basicResp, X509Certificate issuer) {
        try {
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC")
                    .build(issuer.getPublicKey());
            if (basicResp.isSignatureValid(verifier)) {
                return true;
            }
        } catch (Exception e) {
            log.debug("Assinatura OCSP não confere com o emissor, tentando certificado delegado");
        }

        try {
            X509CertificateHolder[] certs = basicResp.getCerts();
            if (certs == null || certs.length == 0) {
                log.warn("Resposta OCSP não contém certificados do assinante");
                return false;
            }

            JcaX509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);

            for (var responderCert : certs) {
                if (isAuthorizedResponder(responderCert, issuerHolder, issuer)
                        && isOcspSignatureValid(basicResp, responderCert)) {
                    return true;
                }
            }
        } catch (Exception e) {
            log.warn("Falha ao verificar assinatura OCSP via certificado delegado: {}", e.getMessage());
        }

        return false;
    }

    /**
     * Checks whether a certificate is an authorized OCSP responder per RFC 6960 Section 3.2:
     * must be issued by the same CA and carry the {@code id-kp-OCSPSigning} EKU,
     * with a valid signature from the CA.
     */
    private boolean isAuthorizedResponder(X509CertificateHolder responderCert,
                                          JcaX509CertificateHolder issuerHolder,
                                          X509Certificate issuer) {
        try {
            if (!responderCert.getIssuer().equals(issuerHolder.getSubject())) {
                return false;
            }

            Extension ekuExt = responderCert.getExtension(Extension.extendedKeyUsage);
            if (ekuExt == null) {
                return false;
            }

            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuExt.getParsedValue());
            if (!eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning)) {
                return false;
            }

            ContentVerifierProvider issuerVerifier = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC")
                    .build(issuer.getPublicKey());
            return responderCert.isSignatureValid(issuerVerifier);
        } catch (Exception e) {
            log.debug("Certificado delegado OCSP inválido: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Verifies the OCSP response signature against the given signer certificate.
     *
     * @param basicResp the parsed OCSP response
     * @param signer    the candidate signer certificate
     * @return {@code true} if the signature is valid
     */
    private boolean isOcspSignatureValid(BasicOCSPResp basicResp, X509CertificateHolder signer) {
        try {
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC")
                    .build(signer);
            return basicResp.isSignatureValid(verifier);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Attempts revocation checking via CRL. Checks the cache before making an HTTP request.
     *
     * @param cert   the certificate to verify
     * @param issuer the issuer certificate (used to verify the CRL signature)
     * @param url    the CRL distribution point URL
     * @return the revocation status from the CRL check
     */
    private RevocationStatus tryCrl(X509Certificate cert, X509Certificate issuer, String url) {
        Optional<byte[]> cached = cache.getCrl(url);
        if (cached.isPresent()) {
            log.debug("CRL encontrada no cache para {}", url);
            return parseCrl(cached.get(), cert, issuer);
        }

        try {
            byte[] crlBytes = executeWithRetry(config.getMaxRetries(), config.getRetryIntervalSeconds(), () -> {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(config.getCrlTimeoutSeconds()))
                        .GET()
                        .build();
                HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() != 200) {
                    throw new IOException("CRL HTTP status: " + response.statusCode());
                }
                return response.body();
            });

            cache.putCrl(url, crlBytes);
            return parseCrl(crlBytes, cert, issuer);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Verificação CRL interrompida para {}", url);
            return new RevocationStatus.NoConnectivity();
        } catch (Exception e) {
            log.warn("CRL indisponível para {}: {}", url, e.getMessage());
            return new RevocationStatus.CrlUnavailable();
        }
    }

    /**
     * Parses a CRL, verifies its signature and checks whether the certificate
     * is listed as revoked.
     *
     * @param crlBytes the raw CRL data (DER-encoded)
     * @param cert     the certificate to look up in the CRL
     * @param issuer   the issuer certificate (used to verify the CRL signature)
     * @return {@link RevocationStatus.Good} if not revoked,
     *         {@link RevocationStatus.Revoked} if revoked,
     *         {@link RevocationStatus.Malformed} if the CRL cannot be parsed or the signature is invalid
     */
    private RevocationStatus parseCrl(byte[] crlBytes, X509Certificate cert, X509Certificate issuer) {
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

    /**
     * Executes an operation with automatic retries on failure.
     *
     * @param maxRetries      maximum number of retries (0 means no retry)
     * @param intervalSeconds interval between retries in seconds
     * @param supplier        the operation to execute
     * @param <T>             the return type of the operation
     * @return the result of the first successful execution
     * @throws Exception the exception from the last failed attempt if all retries are exhausted
     */
    private <T> T executeWithRetry(int maxRetries, int intervalSeconds,
                                   RetryableSupplier<T> supplier) throws Exception {
        Exception lastException = null;
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                return supplier.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw e;
            } catch (Exception e) {
                lastException = e;
                if (attempt < maxRetries) {
                    log.debug("Tentativa {}/{} falhou: {}. Aguardando {}s...",
                            attempt + 1, maxRetries, e.getMessage(), intervalSeconds);
                    Thread.sleep(intervalSeconds * 1000L);
                }
            }
        }
        throw lastException;
    }

    /**
     * Functional interface for operations that may throw checked exceptions.
     *
     * @param <T> the return type
     */
    @FunctionalInterface
    private interface RetryableSupplier<T> {
        T get() throws Exception;
    }
}
