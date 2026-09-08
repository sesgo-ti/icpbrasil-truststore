package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Cliente OCSP responsável por construir requisições, verificar assinaturas
 * e interpretar respostas OCSP conforme RFC 6960.
 *
 * <p>Consulta o presente, não valida assinaturas históricas ou uma cadeia PKIX.
 * O chamador deve estabelecer a confiança no emissor. Exige um único CertID
 * correspondente, assinatura e identidade do emissor ou delegado direto com EKU
 * {@code id-kp-OCSPSigning}, e evidência temporalmente válida em cada leitura.</p>
 *
 * <p>Hashes de CertID permitidos: SHA-1, SHA-224, SHA-256, SHA-384 e SHA-512,
 * calculados via Bouncy Castle conforme o algoritmo da resposta. SHA-1 aqui
 * identifica o emissor, não define o algoritmo de assinatura da resposta.</p>
 *
 * <p>Tolerância de 5 minutos para datas da resposta. Sem {@code nextUpdate},
 * a idade máxima de {@code thisUpdate} é 24 horas (mais a tolerância), independente
 * do TTL do cache. Exige {@code thisUpdate <= producedAt <= nextUpdate}, quando
 * presente, com tolerância; {@code nextUpdate >= thisUpdate} sem tolerância.
 * O delegado deve estar válido agora e em {@code producedAt}, sem tolerância;
 * sua revogação não é consultada. Extensões críticas de resposta não são suportadas.
 * No delegado, apenas basicConstraints (não CA), EKU e KeyUsage são processadas
 * quando críticas; outras são rejeitadas. KeyUsage, se presente, deve permitir
 * digitalSignature. Não há nonce; a janela temporal limita replay.</p>
 */
@Slf4j
public class OcspClient {

    private static final String BC_PROVIDER = "BC";
    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    private static final Duration MAX_AGE_WITHOUT_NEXT_UPDATE = Duration.ofHours(24);
    private static final Set<String> CERT_ID_HASH_ALGORITHMS = Set.of(
            OIWObjectIdentifiers.idSHA1.getId(), NISTObjectIdentifiers.id_sha224.getId(),
            NISTObjectIdentifiers.id_sha256.getId(), NISTObjectIdentifiers.id_sha384.getId(),
            NISTObjectIdentifiers.id_sha512.getId());

    private final RevocationCache cache;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.RevocationConfig config;
    private final CertificateHttpTransport transport;
    private final DownloadPolicy downloadPolicy;
    private final Clock clock;

    /** Cria um cliente OCSP com transporte sem redirects e limites durante o download. */
    public OcspClient(RevocationCache cache, RetryPolicy retryPolicy,
                      TrustStoreConfig trustStoreConfig, DownloadPolicy downloadPolicy) {
        this(cache, retryPolicy, trustStoreConfig.getRevocation(), HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(trustStoreConfig.getRevocation().getOcspTimeoutSeconds()))
                .build(), downloadPolicy);
    }

    /**
     * Usa um cliente pertencente ao chamador, sem alterar a política de download.
     * @throws IllegalArgumentException se o cliente não usar {@link HttpClient.Redirect#NEVER}
     */
    public OcspClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                      HttpClient httpClient, DownloadPolicy downloadPolicy) {
        this(cache, retryPolicy, config, httpClient, downloadPolicy, Clock.systemUTC());
    }

    /**
     * Usa transporte do chamador e relógio para o instante atual de cada validação,
     * inclusive no cache. Os demais construtores usam {@link Clock#systemUTC()}.
     *
     * @param cache cache de evidências DER, nunca de decisões definitivas
     * @param retryPolicy política de tentativas de transporte
     * @param config limites de tempo e tentativas OCSP
     * @param httpClient cliente do chamador com redirects desabilitados
     * @param downloadPolicy política de destinos e tamanhos
     * @param clock relógio não nulo representando o presente; não habilita validação histórica
     * @throws IllegalArgumentException se o cliente permitir redirects
     */
    public OcspClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                      HttpClient httpClient, DownloadPolicy downloadPolicy, Clock clock) {
        this.cache = cache;
        this.retryPolicy = retryPolicy;
        this.config = config;
        this.transport = new CertificateHttpTransport(httpClient, downloadPolicy);
        this.downloadPolicy = downloadPolicy;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Verifica revogação via OCSP para a URL informada.
     * Consulta o cache antes de fazer a requisição HTTP e revalida toda a evidência.
     * Evidência inválida, ambígua ou vencida resulta em {@code Malformed}, nunca
     * {@code Good}; um hit inválido não dispara nova requisição nesta chamada.
     * A chave usa SHA-256 do DER do alvo e do emissor, independente da URL;
     * hits inválidos permanecem inconclusivos até remoção por TTL/eviction.
     *
     * @param cert   certificado a verificar
     * @param issuer certificado do emissor cuja confiança foi estabelecida pelo chamador
     * @param url    URL do responder OCSP
     * @return status de revogação obtido via OCSP
     */
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer, String url) {
        String cacheKey;
        try {
            cacheKey = buildCacheKey(cert, issuer);
        } catch (Exception e) {
            return new RevocationStatus.Malformed("OCSP");
        }

        Optional<byte[]> cached = cache.getOcsp(cacheKey);
        if (cached.isPresent()) {
            log.debug("Resposta OCSP encontrada no cache para {}", cacheKey);
            return parseResponse(cached.get(), cert, issuer);
        }

        try {
            downloadPolicy.validateUrl(url);
        } catch (DownloadPolicyException e) {
            log.warn("URL OCSP bloqueada pela política de download: {}", e.getMessage());
            return new RevocationStatus.OcspUnavailable();
        }

        try {
            byte[] responseBytes = retryPolicy.executeWithRetry(
                    "OCSP " + url,
                    config.getMaxRetries(),
                    config.getRetryIntervalSeconds() * 1000L,
                    () -> sendRequest(cert, issuer, url));

            downloadPolicy.validateOcspResponseSize(responseBytes, url);

            RevocationStatus result = parseResponse(responseBytes, cert, issuer);
            if (result instanceof RevocationStatus.Good || result instanceof RevocationStatus.Revoked) {
                cache.putOcsp(cacheKey, responseBytes);
            }
            return result;
        } catch (DownloadPolicyException e) {
            log.warn("Resposta OCSP bloqueada pela política de download: {}", e.getMessage());
            return new RevocationStatus.OcspUnavailable();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Verificação OCSP interrompida para {}", url);
            return new RevocationStatus.NoConnectivity();
        } catch (Exception e) {
            log.warn("OCSP indisponível para {}: {}", url, e.getMessage());
            return new RevocationStatus.OcspUnavailable();
        }
    }

    private String buildCacheKey(X509Certificate cert, X509Certificate issuer) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(cert.getEncoded())) + "|"
                + HexFormat.of().formatHex(digest.digest(issuer.getEncoded()));
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
        return transport.send(request, downloadPolicy.getMaxOcspResponseBytes());
    }

    private byte[] buildRequest(X509Certificate cert, X509Certificate issuer) throws Exception {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BC_PROVIDER).build();
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
            Instant now = clock.instant();
            if (!(ocspResp.getResponseObject() instanceof BasicOCSPResp basicResp)
                    || !basicResp.getCriticalExtensionOIDs().isEmpty()) {
                return new RevocationStatus.Malformed("OCSP");
            }
            if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                return new RevocationStatus.Malformed("OCSP");
            }
            cert.verify(issuer.getPublicKey(), BC_PROVIDER);
            SingleResp matching = null;
            DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BC_PROVIDER).build();
            X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
            for (SingleResp singleResp : basicResp.getResponses()) {
                CertificateID id = singleResp.getCertID();
                if (!id.getSerialNumber().equals(cert.getSerialNumber())) {
                    continue;
                }
                if (!CERT_ID_HASH_ALGORITHMS.contains(id.getHashAlgOID().getId())) {
                    return new RevocationStatus.Malformed("OCSP");
                }
                if (id.matchesIssuer(issuerHolder, digests)) {
                    if (matching != null) {
                        return new RevocationStatus.Malformed("OCSP");
                    }
                    matching = singleResp;
                }
            }
            if (matching == null || !matching.getCriticalExtensionOIDs().isEmpty()
                    || !isCurrent(matching, basicResp.getProducedAt(), now)) {
                return new RevocationStatus.Malformed("OCSP");
            }
            if (!verifySignature(basicResp, issuerHolder, now)) {
                log.warn("Assinatura da resposta OCSP inválida para certificado serial {}",
                        cert.getSerialNumber().toString(16));
                return new RevocationStatus.Malformed("OCSP");
            }
            CertificateStatus status = matching.getCertStatus();
            if (status == CertificateStatus.GOOD) {
                return new RevocationStatus.Good("OCSP", responseBytes);
            } else if (status instanceof RevokedStatus) {
                return new RevocationStatus.Revoked("OCSP");
            } else if (status instanceof UnknownStatus) {
                log.warn("OCSP retornou status unknown para certificado serial {}: " +
                                "o responder não reconhece este certificado",
                        cert.getSerialNumber().toString(16));
                return new RevocationStatus.OcspUnavailable();
            }
            return new RevocationStatus.Malformed("OCSP");
        } catch (Exception e) {
            log.warn("Falha ao processar resposta OCSP: {}", e.getMessage());
            return new RevocationStatus.Malformed("OCSP");
        }
    }

    private boolean isCurrent(SingleResp response, Date producedAt, Instant now) {
        if (response.getThisUpdate() == null || producedAt == null) {
            return false;
        }
        Instant thisUpdate = response.getThisUpdate().toInstant();
        Instant produced = producedAt.toInstant();
        Instant nextUpdate = response.getNextUpdate() == null ? null : response.getNextUpdate().toInstant();
        if (thisUpdate.isAfter(now.plus(CLOCK_SKEW)) || produced.isAfter(now.plus(CLOCK_SKEW))
                || produced.isBefore(thisUpdate.minus(CLOCK_SKEW))) {
            return false;
        }
        if (nextUpdate == null) {
            return !now.isAfter(thisUpdate.plus(MAX_AGE_WITHOUT_NEXT_UPDATE).plus(CLOCK_SKEW));
        }
        return !nextUpdate.isBefore(thisUpdate) && !now.isAfter(nextUpdate.plus(CLOCK_SKEW))
                && !produced.isAfter(nextUpdate.plus(CLOCK_SKEW));
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

    private boolean verifySignature(BasicOCSPResp basicResp, X509CertificateHolder issuer, Instant now) {
        if (isSignatureValid(basicResp, issuer)) {
            return true;
        }

        try {
            X509CertificateHolder[] certs = basicResp.getCerts();
            if (certs == null || certs.length == 0) {
                log.warn("Resposta OCSP não contém certificados do assinante");
                return false;
            }

            for (var responderCert : certs) {
                if (isAuthorizedResponder(responderCert, issuer, now, basicResp.getProducedAt())
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
                                          X509CertificateHolder issuerHolder, Instant now, Date producedAt) {
        try {
            if (!responderCert.getIssuer().equals(issuerHolder.getSubject())
                    || !responderCert.isValidOn(Date.from(now)) || !responderCert.isValidOn(producedAt)) {
                return false;
            }
            for (Object oid : responderCert.getCriticalExtensionOIDs()) {
                if (!Set.of(Extension.basicConstraints, Extension.keyUsage, Extension.extendedKeyUsage)
                        .contains(oid)) {
                    return false;
                }
            }
            BasicConstraints constraints = BasicConstraints.fromExtensions(responderCert.getExtensions());
            KeyUsage usage = KeyUsage.fromExtensions(responderCert.getExtensions());
            if ((constraints != null && constraints.isCA())
                    || (usage != null && !usage.hasUsages(KeyUsage.digitalSignature))) {
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

            return responderCert.isSignatureValid(buildContentVerifier(issuerHolder));
        } catch (Exception e) {
            log.debug("Certificado delegado OCSP inválido: {}", e.getMessage());
            return false;
        }
    }

    private boolean isSignatureValid(BasicOCSPResp basicResp, X509CertificateHolder signer) {
        try {
            RespID byName = new RespID(signer.getSubject());
            RespID byKey = new RespID(signer.getSubjectPublicKeyInfo(),
                    new JcaDigestCalculatorProviderBuilder().setProvider(BC_PROVIDER).build()
                            .get(CertificateID.HASH_SHA1));
            return (basicResp.getResponderId().equals(byName) || basicResp.getResponderId().equals(byKey))
                    && basicResp.isSignatureValid(buildContentVerifier(signer));
        } catch (Exception e) {
            log.debug("Falha ao verificar assinatura OCSP com responder {}: {}", signer.getSubject(), e.getMessage());
            return false;
        }
    }

    private ContentVerifierProvider buildContentVerifier(X509CertificateHolder holder) throws Exception {
        return new JcaContentVerifierProviderBuilder().setProvider(BC_PROVIDER).build(holder);
    }
}
