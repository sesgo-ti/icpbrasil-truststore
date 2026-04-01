package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevocationService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final RevocationCache cache;
    private final TrustStoreConfig trustStoreConfig;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public RevocationStatus check(X509Certificate cert, X509Certificate issuer) {
        TrustStoreConfig.RevocationConfig config = trustStoreConfig.getRevocation();

        String ocspUrl = extractOcspUrl(cert);
        List<String> crlUrls = extractCrlUrls(cert);

        if (ocspUrl == null && crlUrls.isEmpty()) {
            return new RevocationStatus.NoDistributionPoints();
        }

        if (ocspUrl != null) {
            RevocationStatus result = tryOcsp(cert, issuer, ocspUrl, config);
            if (isConclusive(result)) return result;
        }

        for (String url : crlUrls) {
            RevocationStatus result = tryCrl(cert, url, config);
            if (isConclusive(result)) return result;
        }

        return crlUrls.isEmpty()
                ? new RevocationStatus.OcspUnavailable()
                : new RevocationStatus.CrlUnavailable();
    }

    private boolean isConclusive(RevocationStatus status) {
        return status instanceof RevocationStatus.Good
                || status instanceof RevocationStatus.Revoked
                || status instanceof RevocationStatus.Malformed;
    }

    String extractOcspUrl(X509Certificate cert) {
        try {
            AccessDescription[] descriptions = CertificateParser.getCertificateAuthorityInformationAccess(cert);
            for (AccessDescription desc : descriptions) {
                if (desc.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    GeneralName name = desc.getAccessLocation();
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return name.getName().toString();
                    }
                }
            }
        } catch (IllegalArgumentException e) {
            log.debug("Extensão AIA não encontrada no certificado: {}", e.getMessage());
        }
        return null;
    }

    List<String> extractCrlUrls(X509Certificate cert) {
        List<String> urls = new ArrayList<>();
        try {
            DistributionPoint[] dps = CertificateParser.getCrlDistributionPoints(cert);
            for (DistributionPoint dp : dps) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] names = GeneralNames.getInstance(dpn.getName()).getNames();
                    for (GeneralName name : names) {
                        if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            urls.add(name.getName().toString());
                        }
                    }
                }
            }
        } catch (IllegalArgumentException e) {
            log.debug("Extensão CRL Distribution Points não encontrada no certificado: {}", e.getMessage());
        }
        return urls;
    }

    private RevocationStatus tryOcsp(X509Certificate cert, X509Certificate issuer,
                                     String url, TrustStoreConfig.RevocationConfig config) {
        String cacheKey = cert.getSerialNumber().toString(16) + "|" + cert.getIssuerX500Principal().getName();

        Optional<byte[]> cached = cache.getOcsp(cacheKey, config.getOcspCacheTtlSeconds());
        if (cached.isPresent()) {
            log.debug("Resposta OCSP encontrada no cache para {}", cacheKey);
            return parseOcspResponse(cached.get(), cert);
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

            cache.putOcsp(cacheKey, responseBytes, config.getOcspCacheTtlSeconds());
            return parseOcspResponse(responseBytes, cert);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("OCSP verificação interrompida para {}", url);
            return new RevocationStatus.NoConnectivity();
        } catch (Exception e) {
            log.warn("OCSP indisponível para {}: {}", url, e.getMessage());
            return new RevocationStatus.OcspUnavailable();
        }
    }

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

    private RevocationStatus parseOcspResponse(byte[] responseBytes, X509Certificate cert) {
        try {
            OCSPResp ocspResp = new OCSPResp(responseBytes);
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                log.warn("Resposta OCSP com status não-sucesso: {}", ocspResp.getStatus());
                return new RevocationStatus.Malformed("OCSP");
            }
            BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
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
            log.warn("Erro ao parsear resposta OCSP: {}", e.getMessage());
            return new RevocationStatus.Malformed("OCSP");
        }
    }

    private RevocationStatus tryCrl(X509Certificate cert, String url, TrustStoreConfig.RevocationConfig config) {
        Optional<byte[]> cached = cache.getCrl(url, config.getCrlCacheTtlSeconds());
        if (cached.isPresent()) {
            log.debug("CRL encontrada no cache para {}", url);
            return parseCrl(cached.get(), cert);
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

            cache.putCrl(url, crlBytes, config.getCrlCacheTtlSeconds());
            return parseCrl(crlBytes, cert);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("CRL verificação interrompida para {}", url);
            return new RevocationStatus.NoConnectivity();
        } catch (Exception e) {
            log.warn("CRL indisponível para {}: {}", url, e.getMessage());
            return new RevocationStatus.CrlUnavailable();
        }
    }

    private RevocationStatus parseCrl(byte[] crlBytes, X509Certificate cert) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlBytes));
            if (crl.isRevoked(cert)) {
                return new RevocationStatus.Revoked("CRL");
            }
            return new RevocationStatus.Good("CRL", crlBytes);
        } catch (Exception e) {
            log.warn("Erro ao parsear CRL: {}", e.getMessage());
            return new RevocationStatus.Malformed("CRL");
        }
    }

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

    @FunctionalInterface
    private interface RetryableSupplier<T> {
        T get() throws Exception;
    }
}
