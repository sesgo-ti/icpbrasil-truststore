package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.net.http.HttpClient;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
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
 * <p>Uma resposta só vira evidência ({@code Good} ou {@code Revoked}) se, no instante da
 * verificação, ela for do certificado consultado e estiver dentro do prazo declarado:</p>
 * <ul>
 *   <li>o ResponderID identifica o assinante, que é a CA emissora ou um responder delegado
 *       emitido por ela com EKU {@code id-kp-OCSPSigning} e dentro do período de validade
 *       (RFC 6960 3.2 e 4.2.2.2), e a assinatura confere com a chave desse assinante;</li>
 *   <li>exatamente um SingleResponse tem CertID (serial, issuerNameHash e issuerKeyHash)
 *       igual ao do certificado consultado; a posição na resposta não tem significado;</li>
 *   <li>producedAt, thisUpdate e nextUpdate respeitam a tolerância de relógio
 *       {@code MAX_CLOCK_SKEW} (RFC 6960 4.2.2.1).</li>
 * </ul>
 *
 * <p>Qualquer violação resulta em {@code Malformed}: a resposta existe, mas não serve como
 * evidência para este certificado neste instante. Respostas em cache passam pelas mesmas
 * verificações a cada uso; a entrada que deixa de passar é tratada como miss e substituída
 * pela próxima resposta válida do responder.</p>
 */
@Slf4j
public class OcspClient {

    private static final String BC_PROVIDER = "BC";
    private static final String OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request";
    private static final String OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response";
    private static final String CACHE_KEY_DIGEST = "SHA-256";

    /** Tolerância para diferença de relógio entre este host e o responder; ver {@link ClockSkew}. */
    private static final Duration MAX_CLOCK_SKEW = ClockSkew.MAX_CLOCK_SKEW;

    /**
     * Algoritmos aceitos no hashAlgorithm do CertID. Eles só servem para reconhecer o emissor
     * (nome e chave em hash) dentro do SingleResponse; a confiança vem da assinatura da
     * resposta, por isso SHA-1 continua aceitável neste papel.
     */
    private static final Set<ASN1ObjectIdentifier> CERT_ID_HASH_ALGORITHMS = Set.of(
            OIWObjectIdentifiers.idSHA1,
            NISTObjectIdentifiers.id_sha224,
            NISTObjectIdentifiers.id_sha256,
            NISTObjectIdentifiers.id_sha384,
            NISTObjectIdentifiers.id_sha512);

    private final RevocationCache cache;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.RevocationConfig config;
    private final CertificateHttpTransport transport;
    private final Clock clock;
    private final DigestCalculatorProvider digestCalculators = createDigestCalculators();

    /**
     * Construtor de produção: o transporte é compartilhado com os demais clientes de artefatos
     * X.509 e traz consigo a {@link DownloadPolicy} aplicada a cada requisição.
     */
    public OcspClient(RevocationCache cache, RetryPolicy retryPolicy,
                      TrustStoreConfig trustStoreConfig, CertificateHttpTransport transport) {
        this(cache, retryPolicy, trustStoreConfig.getRevocation(), transport, Clock.systemUTC());
    }

    public OcspClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                      HttpClient httpClient, DownloadPolicy downloadPolicy) {
        this(cache, retryPolicy, config, httpClient, downloadPolicy, Clock.systemUTC());
    }

    /**
     * Variante com relógio injetável: {@code clock} fornece o instante usado nas verificações
     * temporais da resposta e na validade do responder delegado.
     */
    public OcspClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                      HttpClient httpClient, DownloadPolicy downloadPolicy, Clock clock) {
        this(cache, retryPolicy, config, new CertificateHttpTransport(downloadPolicy, httpClient), clock);
    }

    private OcspClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                       CertificateHttpTransport transport, Clock clock) {
        this.cache = cache;
        this.retryPolicy = retryPolicy;
        this.config = config;
        this.transport = Objects.requireNonNull(transport, "transport");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Verifica revogação via OCSP para a URL informada.
     * Consulta o cache antes de fazer a requisição HTTP; uma resposta em cache passa pelas
     * mesmas verificações de correspondência e prazo de uma resposta recém-obtida e, se não
     * passar, a consulta segue como se não houvesse cache.
     *
     * @param cert   certificado a verificar
     * @param issuer certificado do emissor
     * @param url    URL do responder OCSP
     * @return status de revogação obtido via OCSP; {@code Malformed} quando a resposta não é
     *         evidência utilizável para este certificado neste instante
     */
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer, String url) {
        String cacheKey = buildCacheKey(cert, issuer);

        Optional<byte[]> cached = cache.getOcsp(cacheKey);
        if (cached.isPresent()) {
            ParsedResponse parsed = parseResponse(cached.get(), cert, issuer);
            if (parsed.status().isConclusive()) {
                log.debug("Resposta OCSP encontrada no cache para {}", cacheKey);
                return parsed.status();
            }
            // Uma entrada que venceu ou cujo delegado expirou não é erro do responder; devolver
            // Malformed aqui prenderia o resultado ao TTL do cache. O putOcsp da nova resposta a substitui.
            log.debug("Resposta OCSP em cache para {} não passou na revalidação; consultando o responder", cacheKey);
        }

        try {
            transport.policy().validateUrl(url);
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

            ParsedResponse parsed = parseResponse(responseBytes, cert, issuer);
            if (parsed.cacheable()) {
                cache.putOcsp(cacheKey, responseBytes);
            }
            return parsed.status();
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

    /**
     * Chave por emissor e serial. O emissor entra pelo hash do seu DER, e não pelo DN, porque
     * CAs distintas podem ter o mesmo nome e emitir seriais coincidentes.
     */
    private String buildCacheKey(X509Certificate cert, X509Certificate issuer) {
        try {
            byte[] issuerDigest = MessageDigest.getInstance(CACHE_KEY_DIGEST).digest(issuer.getEncoded());
            return HexFormat.of().formatHex(issuerDigest) + "|" + cert.getSerialNumber().toString(16);
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Falha ao derivar a chave de cache OCSP do emissor", e);
        }
    }

    private byte[] sendRequest(X509Certificate cert, X509Certificate issuer,
                               String url) throws Exception {
        byte[] requestBytes = buildRequest(cert, issuer);
        return transport.post(url, requestBytes, OCSP_REQUEST_CONTENT_TYPE, OCSP_RESPONSE_CONTENT_TYPE,
                transport.policy().getMaxOcspResponseBytes(), Duration.ofSeconds(config.getOcspTimeoutSeconds()));
    }

    private byte[] buildRequest(X509Certificate cert, X509Certificate issuer) throws Exception {
        CertificateID certId = new CertificateID(
                digestCalculators.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuer),
                cert.getSerialNumber()
        );
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);
        return builder.build().getEncoded();
    }

    /**
     * Resultado da interpretação de uma resposta. Só Good/Revoked com nextUpdate são cacheáveis:
     * sem nextUpdate o responder não declarou prazo, e a resposta deixaria de ser aceita já no
     * próximo hit, servindo apenas para provocar uma nova consulta.
     */
    private record ParsedResponse(RevocationStatus status, boolean cacheable) {

        static ParsedResponse malformed() {
            return new ParsedResponse(new RevocationStatus.Malformed("OCSP"), false);
        }

        static ParsedResponse unavailable() {
            return new ParsedResponse(new RevocationStatus.OcspUnavailable(), false);
        }
    }

    private ParsedResponse parseResponse(byte[] responseBytes, X509Certificate cert,
                                         X509Certificate issuer) {
        String serialHex = cert.getSerialNumber().toString(16);
        try {
            OCSPResp ocspResp = new OCSPResp(responseBytes);
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                log.warn("Resposta OCSP com status não-sucesso: {} ({})",
                        ocspResp.getStatus(), describeOcspResponseStatus(ocspResp.getStatus()));
                return ParsedResponse.unavailable();
            }
            BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
            X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
            Instant now = clock.instant();

            if (!isSignedByAuthorizedResponder(basicResp, issuerHolder, now)) {
                log.warn("Resposta OCSP sem assinatura válida de responder autorizado para certificado serial {}",
                        serialHex);
                return ParsedResponse.malformed();
            }

            SingleResp singleResp = selectSingleResponse(basicResp, issuerHolder, cert.getSerialNumber());
            if (singleResp == null) {
                log.warn("Resposta OCSP sem SingleResponse único para o certificado serial {}", serialHex);
                return ParsedResponse.malformed();
            }

            if (!isWithinValidityWindow(basicResp.getProducedAt(), singleResp, now)) {
                log.warn("Resposta OCSP fora da janela de validade para certificado serial {} " +
                                "(producedAt={}, thisUpdate={}, nextUpdate={})",
                        serialHex, basicResp.getProducedAt(), singleResp.getThisUpdate(), singleResp.getNextUpdate());
                return ParsedResponse.malformed();
            }

            boolean cacheable = singleResp.getNextUpdate() != null;
            CertificateStatus status = singleResp.getCertStatus();
            if (status == CertificateStatus.GOOD) {
                return new ParsedResponse(new RevocationStatus.Good("OCSP", responseBytes), cacheable);
            } else if (status instanceof RevokedStatus) {
                return new ParsedResponse(new RevocationStatus.Revoked("OCSP"), cacheable);
            } else if (status instanceof UnknownStatus) {
                log.warn("OCSP retornou status unknown para certificado serial {} — " +
                                "o responder não reconhece este certificado",
                        serialHex);
                return ParsedResponse.unavailable();
            }
            return ParsedResponse.malformed();
        } catch (Exception e) {
            log.warn("Falha ao processar resposta OCSP: {}", e.getMessage());
            return ParsedResponse.malformed();
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
     * Devolve o único SingleResponse cujo CertID identifica o certificado consultado, ou
     * {@code null} se nenhum ou mais de um corresponder. Dois SingleResponses para o mesmo
     * certificado poderiam divergir entre si, e não há critério para escolher um deles.
     */
    private SingleResp selectSingleResponse(BasicOCSPResp basicResp, X509CertificateHolder issuerHolder,
                                            BigInteger serial) throws OCSPException {
        SingleResp match = null;
        for (SingleResp candidate : basicResp.getResponses()) {
            if (!identifiesCertificate(candidate.getCertID(), issuerHolder, serial)) {
                continue;
            }
            if (match != null) {
                return null;
            }
            match = candidate;
        }
        return match;
    }

    /**
     * Recalcula o CertID com o algoritmo declarado pela própria resposta e exige igualdade de
     * serial, issuerNameHash e issuerKeyHash (RFC 6960 4.1.1).
     */
    private boolean identifiesCertificate(CertificateID certId, X509CertificateHolder issuerHolder,
                                          BigInteger serial) throws OCSPException {
        return CERT_ID_HASH_ALGORITHMS.contains(certId.getHashAlgOID())
                && serial.equals(certId.getSerialNumber())
                && certId.matchesIssuer(issuerHolder, digestCalculators);
    }

    /**
     * Janela de thisUpdate/nextUpdate alinhada ao OpenJDK: thisUpdate não pode passar de
     * {@code now + MAX_CLOCK_SKEW}, e {@code now - MAX_CLOCK_SKEW} não pode passar de nextUpdate.
     * Sem nextUpdate o responder não declarou até quando a informação vale (RFC 6960 4.2.2.1),
     * então thisUpdate assume esse papel e só uma resposta praticamente instantânea é aceita.
     * O OpenJDK ignora producedAt; aqui ele é rejeitado quando está no futuro além da tolerância,
     * pois um responder com relógio adiantado não produz prazos confiáveis.
     */
    private boolean isWithinValidityWindow(Date producedAt, SingleResp singleResp, Instant now) {
        Instant upperBound = now.plus(MAX_CLOCK_SKEW);
        Instant lowerBound = now.minus(MAX_CLOCK_SKEW);
        Instant thisUpdate = singleResp.getThisUpdate().toInstant();
        Date nextUpdate = singleResp.getNextUpdate();
        Instant validUntil = nextUpdate != null ? nextUpdate.toInstant() : thisUpdate;
        return !producedAt.toInstant().isAfter(upperBound)
                && !thisUpdate.isAfter(upperBound)
                && !lowerBound.isAfter(validUntil);
    }

    /**
     * Verifica a assinatura da resposta OCSP conforme RFC 6960 Section 3.2: o assinante,
     * identificado pelo ResponderID, deve ser a CA emissora ou um responder delegado
     * autorizado por ela, e a assinatura deve conferir com a chave desse assinante.
     */
    private boolean isSignedByAuthorizedResponder(BasicOCSPResp basicResp, X509CertificateHolder issuerHolder,
                                                  Instant now) {
        try {
            RespID responderId = basicResp.getResponderId();
            if (identifiesSigner(responderId, issuerHolder) && isSignatureValid(basicResp, issuerHolder)) {
                return true;
            }

            X509CertificateHolder[] certs = basicResp.getCerts();
            if (certs == null) {
                return false;
            }
            for (X509CertificateHolder candidate : certs) {
                if (identifiesSigner(responderId, candidate)
                        && isAuthorizedResponder(candidate, issuerHolder, now)
                        && isSignatureValid(basicResp, candidate)) {
                    return true;
                }
            }
        } catch (Exception e) {
            log.warn("Falha ao verificar assinatura OCSP: {}", e.getMessage());
        }
        return false;
    }

    /**
     * RFC 6960 4.2.1: {@code byName} é o subject do assinante; {@code byKey} é o SHA-1 do valor
     * de subjectPublicKey (sem tag e length), independentemente do SKI do certificado.
     */
    private boolean identifiesSigner(RespID responderId, X509CertificateHolder signer) throws Exception {
        X500Name byName = responderId.toASN1Primitive().getName();
        if (byName != null) {
            return byName.equals(signer.getSubject());
        }
        RespID byKey = new RespID(signer.getSubjectPublicKeyInfo(), digestCalculators.get(RespID.HASH_SHA1));
        return responderId.equals(byKey);
    }

    /**
     * Responder delegado (RFC 6960 4.2.2.2): emitido pela CA emissora do certificado consultado
     * (nome e assinatura), com EKU {@code id-kp-OCSPSigning} e dentro do período de validade no
     * instante da verificação. Um delegado expirado deixa de ser autorizado mesmo que a resposta
     * tenha sido assinada enquanto ele valia.
     */
    private boolean isAuthorizedResponder(X509CertificateHolder responderCert,
                                          X509CertificateHolder issuerHolder, Instant now) {
        try {
            if (!responderCert.getIssuer().equals(issuerHolder.getSubject())) {
                return false;
            }

            if (!responderCert.isValidOn(Date.from(now))) {
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
            return basicResp.isSignatureValid(buildContentVerifier(signer));
        } catch (Exception e) {
            log.debug("Falha ao verificar assinatura OCSP com responder {}: {}", signer.getSubject(), e.getMessage());
            return false;
        }
    }

    private ContentVerifierProvider buildContentVerifier(X509CertificateHolder holder) throws Exception {
        return new JcaContentVerifierProviderBuilder().setProvider(BC_PROVIDER).build(holder);
    }

    private static DigestCalculatorProvider createDigestCalculators() {
        try {
            return new JcaDigestCalculatorProviderBuilder().build();
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Falha ao inicializar os calculadores de digest", e);
        }
    }
}
