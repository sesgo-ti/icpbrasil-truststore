package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.net.http.HttpClient;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Cliente CRL responsável por download, verificação e consulta de revogação em CRLs
 * (Certificate Revocation Lists).
 *
 * <p>Uma CRL só vira evidência ({@code Good} ou {@code Revoked}) se, no instante da verificação,
 * ela comprovadamente cobre o certificado consultado (RFC 5280 6.3.3):</p>
 * <ul>
 *   <li>foi emitida pelo emissor do certificado: o issuer da CRL e o issuer do certificado são o
 *       subject do emissor, que é CA com cRLSign (se KeyUsage presente), e a assinatura confere
 *       com a chave dele;</li>
 *   <li>está no prazo: thisUpdate e nextUpdate presentes e o instante atual dentro da janela,
 *       com a tolerância {@link ClockSkew#MAX_CLOCK_SKEW};</li>
 *   <li>é uma CRL completa e direta para todos os motivos: sem deltaCRLIndicator, sem IDP
 *       indireta, parcial por motivos ou restrita a outra classe de certificado, e o nome do IDP,
 *       quando presente, inclui a URL consultada ou um nome do DP do certificado; o DP do
 *       certificado não restringe motivos nem delega a emissão (cRLIssuer);</li>
 *   <li>não há extensão crítica não processada na CRL nem na entrada do certificado, e a entrada
 *       não tem certificateIssuer nem reasonCode removeFromCRL.</li>
 * </ul>
 *
 * <p>Qualquer violação resulta em {@code Malformed}: a CRL existe, mas não serve como evidência
 * para este certificado neste instante. CRLs em cache passam pelas mesmas verificações a cada
 * uso; a que deixa de passar é tratada como miss e substituída pelo próximo download válido.</p>
 */
@Slf4j
public class CrlClient {

    private static final String BC_PROVIDER = "BC";

    /** Posição do bit cRLSign no array de {@link X509Certificate#getKeyUsage()}. */
    private static final int KEY_USAGE_CRL_SIGN = 6;

    private final RevocationCache cache;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.RevocationConfig config;
    private final CertificateHttpTransport transport;
    private final Clock clock;

    /**
     * Construtor de produção: o transporte é compartilhado com os demais clientes de artefatos
     * X.509 e traz consigo a {@link DownloadPolicy} aplicada a cada requisição.
     */
    public CrlClient(RevocationCache cache, RetryPolicy retryPolicy,
                     TrustStoreConfig trustStoreConfig, CertificateHttpTransport transport) {
        this(cache, retryPolicy, trustStoreConfig.getRevocation(), transport, Clock.systemUTC());
    }

    public CrlClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                     HttpClient httpClient, DownloadPolicy downloadPolicy) {
        this(cache, retryPolicy, config, httpClient, downloadPolicy, Clock.systemUTC());
    }

    /**
     * Variante com relógio injetável: {@code clock} fornece o instante usado nas verificações
     * temporais da CRL.
     */
    public CrlClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                     HttpClient httpClient, DownloadPolicy downloadPolicy, Clock clock) {
        this(cache, retryPolicy, config, new CertificateHttpTransport(downloadPolicy, httpClient), clock);
    }

    private CrlClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                      CertificateHttpTransport transport, Clock clock) {
        this.cache = cache;
        this.retryPolicy = retryPolicy;
        this.config = config;
        this.transport = Objects.requireNonNull(transport, "transport");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Verifica revogação via CRL para a URL informada, que deve ser um fullName URI da extensão
     * CRL Distribution Points do certificado. Consulta o cache antes de fazer a requisição HTTP;
     * uma CRL em cache passa pelas mesmas verificações de uma recém-obtida e, se não passar, a
     * consulta segue como se não houvesse cache.
     *
     * @param cert   certificado a verificar
     * @param issuer certificado do emissor (usado para verificar a assinatura da CRL)
     * @param url    URL do CRL Distribution Point
     * @return status de revogação obtido via CRL; {@code Malformed} quando a CRL não é evidência
     *         utilizável para este certificado neste instante
     */
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer, String url) {
        DistributionPoint point = CertificateParser.getCrlDistributionPoint(cert, url).orElse(null);
        // Sem o DP não há como conferir o escopo da CRL; com reasons ela cobre só parte dos motivos
        // e com cRLIssuer a emissão é delegada a outro emissor, cuja cadeia este cliente não valida.
        if (point == null || point.getReasons() != null || point.getCRLIssuer() != null) {
            log.warn("Certificado serial {} não aponta para {} em um CRL Distribution Point utilizável " +
                    "(ausente, com reasons ou com cRLIssuer)", cert.getSerialNumber().toString(16), url);
            return new RevocationStatus.Malformed("CRL");
        }

        Optional<byte[]> cached = cache.getCrl(url);
        if (cached.isPresent()) {
            RevocationStatus status = parse(cached.get(), cert, issuer, url, point);
            if (status.isConclusive()) {
                log.debug("CRL encontrada no cache para {}", url);
                return status;
            }
            // Uma CRL que venceu não é erro do emissor; devolver Malformed aqui prenderia o resultado
            // ao TTL do cache. O putCrl da nova CRL a substitui.
            log.debug("CRL em cache para {} não passou na revalidação; baixando novamente", url);
        }

        try {
            transport.policy().validateUrl(url);
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

            RevocationStatus result = parse(crlBytes, cert, issuer, url, point);
            if (result.isConclusive()) {
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

    private byte[] download(String url) throws IOException, InterruptedException {
        return transport.get(url, transport.policy().getMaxCrlResponseBytes(),
                Duration.ofSeconds(config.getCrlTimeoutSeconds()));
    }

    /**
     * Interpreta a CRL como evidência para o certificado: emissor, prazo e escopo são verificados
     * antes de consultar o serial, porque a ausência do serial só significa "não revogado" numa
     * lista completa, vigente e do emissor certo.
     */
    private RevocationStatus parse(byte[] crlBytes, X509Certificate cert, X509Certificate issuer,
                                   String url, DistributionPoint point) {
        String serialHex = cert.getSerialNumber().toString(16);
        try {
            X509CRLHolder crl = new X509CRLHolder(crlBytes);

            if (!isIssuedBy(crl, cert, issuer)) {
                log.warn("CRL de {} não foi emitida pelo emissor do certificado serial {}", url, serialHex);
                return new RevocationStatus.Malformed("CRL");
            }

            if (!isWithinValidityWindow(crl, clock.instant())) {
                log.warn("CRL de {} fora da janela de validade (thisUpdate={}, nextUpdate={})",
                        url, crl.getThisUpdate(), crl.getNextUpdate());
                return new RevocationStatus.Malformed("CRL");
            }

            if (!coversCertificate(crl, cert, url, point)) {
                log.warn("CRL de {} não comprova cobertura do certificado serial {}", url, serialHex);
                return new RevocationStatus.Malformed("CRL");
            }

            X509CRLEntryHolder entry = crl.getRevokedCertificate(cert.getSerialNumber());
            if (entry == null) {
                return new RevocationStatus.Good("CRL", crlBytes);
            }
            if (!isUsableEntry(entry)) {
                log.warn("Entrada da CRL de {} para o certificado serial {} tem extensão não processável",
                        url, serialHex);
                return new RevocationStatus.Malformed("CRL");
            }
            return new RevocationStatus.Revoked("CRL");
        } catch (Exception e) {
            log.warn("Falha ao validar CRL de {}: {}", url, e.getMessage());
            return new RevocationStatus.Malformed("CRL");
        }
    }

    /**
     * RFC 5280 6.3.3 (a) e (f): a CRL vale para o certificado quando o emissor dele é quem a
     * emitiu — mesmo DN nos dois lados — e esse emissor é CA autorizada a assinar CRLs e de fato
     * a assinou. A comparação de nomes usa a forma canônica de {@link X500Principal}, a mesma do
     * validador da JVM.
     */
    private boolean isIssuedBy(X509CRLHolder crl, X509Certificate cert, X509Certificate issuer) throws Exception {
        X500Principal issuerName = issuer.getSubjectX500Principal();
        if (!cert.getIssuerX500Principal().equals(issuerName)) {
            return false;
        }
        if (!new X500Principal(crl.getIssuer().getEncoded()).equals(issuerName)) {
            return false;
        }
        if (issuer.getBasicConstraints() == -1) {
            return false;
        }
        boolean[] keyUsage = issuer.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= KEY_USAGE_CRL_SIGN || !keyUsage[KEY_USAGE_CRL_SIGN])) {
            return false;
        }
        return crl.isSignatureValid(new JcaContentVerifierProviderBuilder()
                .setProvider(BC_PROVIDER)
                .build(new JcaX509CertificateHolder(issuer)));
    }

    /**
     * Janela alinhada ao X509CRLSelector do OpenJDK: thisUpdate não pode passar de
     * {@code now + MAX_CLOCK_SKEW} e {@code now - MAX_CLOCK_SKEW} não pode passar de nextUpdate.
     * nextUpdate é opcional no ASN.1, mas sem ele o emissor não declarou até quando a lista vale,
     * e a JVM também não a aceita como evidência.
     */
    private boolean isWithinValidityWindow(X509CRLHolder crl, Instant now) {
        Date nextUpdate = crl.getNextUpdate();
        if (nextUpdate == null) {
            return false;
        }
        Instant thisUpdate = crl.getThisUpdate().toInstant();
        return !thisUpdate.isAfter(now.plus(ClockSkew.MAX_CLOCK_SKEW))
                && !now.minus(ClockSkew.MAX_CLOCK_SKEW).isAfter(nextUpdate.toInstant());
    }

    /**
     * RFC 5280 6.3.3 (b): só uma CRL completa, direta e para todos os motivos, cujo escopo
     * declarado inclui o certificado, permite concluir Good pela ausência do serial. Delta CRLs e
     * CRLs indiretas exigiriam combinar outras listas ou validar outro emissor, o que este cliente
     * não faz; onlySomeReasons deixaria revogações fora da lista consultada. Uma extensão crítica
     * desconhecida pode alterar o escopo de formas que não sabemos interpretar.
     */
    private boolean coversCertificate(X509CRLHolder crl, X509Certificate cert, String url, DistributionPoint point) {
        if (crl.getExtension(Extension.deltaCRLIndicator) != null) {
            return false;
        }
        if (!hasOnlyProcessedCriticalExtensions(crl.getCriticalExtensionOIDs(), Extension.issuingDistributionPoint)) {
            return false;
        }

        Extension idpExtension = crl.getExtension(Extension.issuingDistributionPoint);
        if (idpExtension == null) {
            return true;
        }
        IssuingDistributionPoint idp = IssuingDistributionPoint.getInstance(idpExtension.getParsedValue());
        if (idp.isIndirectCRL() || idp.getOnlySomeReasons() != null || idp.onlyContainsAttributeCerts()) {
            return false;
        }
        boolean targetIsCa = cert.getBasicConstraints() != -1;
        if (idp.onlyContainsUserCerts() && targetIsCa) {
            return false;
        }
        if (idp.onlyContainsCACerts() && !targetIsCa) {
            return false;
        }
        DistributionPointName idpName = idp.getDistributionPoint();
        return idpName == null || idpNameCoversPoint(idpName, url, point);
    }

    /**
     * RFC 5280 6.3.3 (b)(1): quando o IDP nomeia o ponto de distribuição, um dos nomes deve ser o
     * do DP do certificado — aqui, a URL consultada ou qualquer nome do fullName do DP. Um IDP
     * com nameRelativeToCRLIssuer designa um nome de diretório e nunca corresponde a um DP de URLs.
     */
    private boolean idpNameCoversPoint(DistributionPointName idpName, String url, DistributionPoint point) {
        if (idpName.getType() != DistributionPointName.FULL_NAME) {
            return false;
        }
        Set<GeneralName> pointNames = new HashSet<>();
        pointNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, url));
        DistributionPointName pointName = point.getDistributionPoint();
        if (pointName != null && pointName.getType() == DistributionPointName.FULL_NAME) {
            pointNames.addAll(Arrays.asList(GeneralNames.getInstance(pointName.getName()).getNames()));
        }
        for (GeneralName name : GeneralNames.getInstance(idpName.getName()).getNames()) {
            if (pointNames.contains(name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * RFC 5280 5.3: certificateIssuer atribui a entrada a outro emissor (só faz sentido em CRL
     * indireta), removeFromCRL só existe em delta CRL, e uma extensão crítica desconhecida pode
     * mudar o significado da entrada; em qualquer desses casos não se sabe o que ela afirma.
     */
    private boolean isUsableEntry(X509CRLEntryHolder entry) {
        if (!entry.hasExtensions()) {
            return true;
        }
        if (entry.getExtension(Extension.certificateIssuer) != null) {
            return false;
        }
        if (!hasOnlyProcessedCriticalExtensions(entry.getCriticalExtensionOIDs(), Extension.reasonCode)) {
            return false;
        }
        Extension reasonCode = entry.getExtension(Extension.reasonCode);
        return reasonCode == null
                || CRLReason.getInstance(reasonCode.getParsedValue()).getValue().intValue() != CRLReason.removeFromCRL;
    }

    private boolean hasOnlyProcessedCriticalExtensions(Set<?> criticalOids, ASN1ObjectIdentifier... processed) {
        Set<Object> unresolved = new HashSet<>(criticalOids);
        unresolved.removeAll(Arrays.asList(processed));
        return unresolved.isEmpty();
    }
}
