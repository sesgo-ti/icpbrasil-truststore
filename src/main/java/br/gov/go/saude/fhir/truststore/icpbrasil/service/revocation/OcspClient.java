package br.gov.go.saude.fhir.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;

/**
 * Cliente OCSP responsável por construir requisições, verificar assinaturas
 * e interpretar respostas OCSP conforme RFC 6960.
 *
 * <p>Verificação de assinatura segue a Section 3.2 do RFC 6960:
 * aceita respostas assinadas diretamente pela CA emissora ou por um
 * responder delegado com EKU {@code id-kp-OCSPSigning}.</p>
 */
@Slf4j
@Component
public class OcspClient {

    private final RevocationCache cache;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.RevocationConfig config;
    private final HttpClient httpClient;

    public OcspClient(RevocationCache cache, RetryPolicy retryPolicy,
                      TrustStoreConfig trustStoreConfig) {
        this.cache = cache;
        this.retryPolicy = retryPolicy;
        this.config = trustStoreConfig.getRevocation();
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Verifica revogação via OCSP para a URL informada.
     * Consulta o cache antes de fazer a requisição HTTP.
     *
     * @param cert   certificado a verificar
     * @param issuer certificado do emissor
     * @param url    URL do responder OCSP
     * @return status de revogação obtido via OCSP
     */
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer, String url) {
        String cacheKey = buildCacheKey(cert);

        Optional<byte[]> cached = cache.getOcsp(cacheKey);
        if (cached.isPresent()) {
            log.debug("Resposta OCSP encontrada no cache para {}", cacheKey);
            return parseResponse(cached.get(), cert, issuer);
        }

        try {
            byte[] responseBytes = retryPolicy.executeWithRetry(
                    "OCSP " + url,
                    config.getMaxRetries(),
                    config.getRetryIntervalSeconds() * 1000L,
                    () -> sendRequest(cert, issuer, url));

            RevocationStatus result = parseResponse(responseBytes, cert, issuer);
            if (result instanceof RevocationStatus.Good || result instanceof RevocationStatus.Revoked) {
                cache.putOcsp(cacheKey, responseBytes);
            }
            return result;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Verificação OCSP interrompida para {}", url);
            return new RevocationStatus.NoConnectivity();
        } catch (Exception e) {
            log.warn("OCSP indisponível para {}: {}", url, e.getMessage());
            return new RevocationStatus.OcspUnavailable();
        }
    }

    private String buildCacheKey(X509Certificate cert) {
        return cert.getSerialNumber().toString(16) + "|"
                + cert.getIssuerX500Principal().getName(X500Principal.RFC2253);
    }

    private byte[] sendRequest(X509Certificate cert, X509Certificate issuer,
                               String url) throws Exception {
        byte[] requestBytes = buildRequest(cert, issuer);
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
    }

    private byte[] buildRequest(X509Certificate cert, X509Certificate issuer) throws Exception {
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

    private RevocationStatus parseResponse(byte[] responseBytes, X509Certificate cert,
                                           X509Certificate issuer) {
        try {
            OCSPResp ocspResp = new OCSPResp(responseBytes);
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                log.warn("Resposta OCSP com status não-sucesso: {} ({})",
                        ocspResp.getStatus(), describeOcspResponseStatus(ocspResp.getStatus()));
                return new RevocationStatus.OcspUnavailable();
            }
            BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
            if (!verifySignature(basicResp, issuer)) {
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
                    log.warn("OCSP retornou status unknown para certificado serial {} — " +
                                    "o responder não reconhece este certificado",
                            cert.getSerialNumber().toString(16));
                    return new RevocationStatus.OcspUnavailable();
                }
            }
            return new RevocationStatus.Malformed("OCSP");
        } catch (Exception e) {
            log.warn("Falha ao processar resposta OCSP: {}", e.getMessage());
            return new RevocationStatus.Malformed("OCSP");
        }
    }

    private String describeOcspResponseStatus(int status) {
        return switch (status) {
            case OCSPResp.MALFORMED_REQUEST -> "malformedRequest";
            case OCSPResp.INTERNAL_ERROR -> "internalError";
            case OCSPResp.TRY_LATER -> "tryLater";
            case OCSPResp.SIG_REQUIRED -> "sigRequired";
            case OCSPResp.UNAUTHORIZED -> "unauthorized";
            default -> "desconhecido(" + status + ")";
        };
    }

    /**
     * Verifica a assinatura da resposta OCSP conforme RFC 6960 Section 3.2.
     * Aceita respostas assinadas pela CA emissora ou por responder delegado
     * com EKU {@code id-kp-OCSPSigning} emitido pela mesma CA.
     */
    private boolean verifySignature(BasicOCSPResp basicResp, X509Certificate issuer) {
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
                        && isSignatureValid(basicResp, responderCert)) {
                    return true;
                }
            }
        } catch (Exception e) {
            log.warn("Falha ao verificar assinatura OCSP via certificado delegado: {}", e.getMessage());
        }

        return false;
    }

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

    private boolean isSignatureValid(BasicOCSPResp basicResp, X509CertificateHolder signer) {
        try {
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC")
                    .build(signer);
            return basicResp.isSignatureValid(verifier);
        } catch (Exception e) {
            return false;
        }
    }
}
