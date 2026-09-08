package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.cert.CRLReason;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Consulta revogação no presente usando somente CRLs completas e diretas.
 * O chamador deve estabelecer confiança no emissor; não realiza validação PKIX,
 * validade do alvo/emissor ou validação histórica/LTV.
 *
 * <p>Exige vínculo do alvo com o emissor por DN e assinatura, emissor CA e
 * cRLSign se KeyUsage estiver presente, DN e assinatura da CRL e ambas as datas
 * thisUpdate/nextUpdate. Tolera 5 minutos de desvio em relação ao presente,
 * mas não nextUpdate anterior a thisUpdate. Rejeita delta, qualquer IDP,
 * DPs do alvo com reasons/cRLIssuer e extensões críticas de CRL/entradas.
 * Entradas com certificateIssuer ou removeFromCRL também não são suportadas.</p>
 */
@Slf4j
public class CrlClient {

    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);

    private final RevocationCache cache;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.RevocationConfig config;
    private final CertificateHttpTransport transport;
    private final DownloadPolicy downloadPolicy;
    private final Clock clock;

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
        this(cache, retryPolicy, config, httpClient, downloadPolicy, Clock.systemUTC());
    }

    /**
     * Usa transporte do chamador e relógio não nulo para revalidar cada evidência,
     * inclusive no cache. Não habilita validação histórica; os demais construtores
     * usam {@link Clock#systemUTC()}.
     *
     * @param cache cache de evidências, nunca de decisões definitivas
     * @param retryPolicy política de tentativas de transporte
     * @param config limites de tempo e tentativas CRL
     * @param httpClient cliente do chamador com redirects desabilitados
     * @param downloadPolicy política de destinos e tamanhos
     * @param clock relógio não nulo representando o presente
     * @throws IllegalArgumentException se o cliente permitir redirects
     */
    public CrlClient(RevocationCache cache, RetryPolicy retryPolicy, TrustStoreConfig.RevocationConfig config,
                     HttpClient httpClient, DownloadPolicy downloadPolicy, Clock clock) {
        this.cache = cache;
        this.retryPolicy = retryPolicy;
        this.config = config;
        this.transport = new CertificateHttpTransport(httpClient, downloadPolicy);
        this.downloadPolicy = downloadPolicy;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Verifica revogação via CRL para a URL informada.
     * Revalida identidade, autorização, cobertura, assinatura e datas inclusive
     * no cache por URL. Evidência inválida ou não suportada retorna Malformed.
     * Um hit inválido não dispara download e permanece inconclusivo até TTL/eviction.
     *
     * @param cert   certificado a verificar
     * @param issuer emissor cuja confiança foi estabelecida pelo chamador
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

    private RevocationStatus parse(byte[] crlBytes, X509Certificate cert, X509Certificate issuer) {
        try {
            Instant now = clock.instant();
            boolean[] keyUsage = issuer.getKeyUsage();
            if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                    || issuer.getBasicConstraints() < 0
                    || (keyUsage != null && (keyUsage.length <= 6 || !keyUsage[6]))) {
                return new RevocationStatus.Malformed("CRL");
            }
            cert.verify(issuer.getPublicKey());

            CRLDistPoint points = CRLDistPoint.fromExtensions(new JcaX509CertificateHolder(cert).getExtensions());
            if (points != null) {
                if (points.getDistributionPoints().length == 0) {
                    return new RevocationStatus.Malformed("CRL");
                }
                // Sem composição de escopos, nenhum DP restrito pode fundamentar cobertura completa.
                for (DistributionPoint point : points.getDistributionPoints()) {
                    if (point.getReasons() != null || point.getCRLIssuer() != null
                            || point.getDistributionPoint() == null) {
                        return new RevocationStatus.Malformed("CRL");
                    }
                }
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlBytes));
            if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                    || crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null
                    || crl.getExtensionValue(Extension.issuingDistributionPoint.getId()) != null
                    || (crl.getCriticalExtensionOIDs() != null && !crl.getCriticalExtensionOIDs().isEmpty())
                    || crl.getThisUpdate() == null || crl.getNextUpdate() == null) {
                return new RevocationStatus.Malformed("CRL");
            }
            Instant thisUpdate = crl.getThisUpdate().toInstant();
            Instant nextUpdate = crl.getNextUpdate().toInstant();
            if (thisUpdate.isAfter(now.plus(CLOCK_SKEW)) || nextUpdate.isBefore(thisUpdate)
                    || now.isAfter(nextUpdate.plus(CLOCK_SKEW))) {
                return new RevocationStatus.Malformed("CRL");
            }
            crl.verify(issuer.getPublicKey());
            Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
            if (entries != null) {
                // Uma entrada indireta pode alterar o emissor das seguintes, inclusive do serial alvo.
                for (X509CRLEntry entry : entries) {
                    if ((entry.getCriticalExtensionOIDs() != null && !entry.getCriticalExtensionOIDs().isEmpty())
                            || entry.getExtensionValue(Extension.certificateIssuer.getId()) != null
                            || entry.getRevocationReason() == CRLReason.REMOVE_FROM_CRL) {
                        return new RevocationStatus.Malformed("CRL");
                    }
                }
            }
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
