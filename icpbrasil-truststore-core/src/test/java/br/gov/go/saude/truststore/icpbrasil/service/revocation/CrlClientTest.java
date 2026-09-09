package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CrlClientTest {

    private static final String CRL_URL = "http://ca.example.com/crl.crl";
    private static final String MIRROR_URL = "http://mirror.example.com/crl.crl";
    private static final X500Name OTHER_CA_NAME = new X500Name("CN=Other CA, O=Test, C=BR");
    private static final ASN1ObjectIdentifier UNKNOWN_EXTENSION = new ASN1ObjectIdentifier("1.2.3.4.5");

    HttpClient mockHttpClient;
    DownloadPolicy downloadPolicy;
    RevocationCache cache;
    RetryPolicy retryPolicy;
    CrlClient client;

    KeyPairGenerator kpg;
    KeyPair rootKeyPair;
    KeyPair leafKeyPair;
    X509Certificate rootCert;
    X509Certificate leafCert;
    X500Name rootName;

    // Instante fixo, com precisão de segundos como o UTCTime das CRLs
    Instant now;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rootKeyPair = kpg.generateKeyPair();
        leafKeyPair = kpg.generateKeyPair();

        rootCert = generateRootCert(rootKeyPair);
        rootName = new JcaX509CertificateHolder(rootCert).getSubject();
        leafCert = generateCert(leafKeyPair, false, crlDistributionPoint(CRL_URL));

        now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        mockHttpClient = mock(HttpClient.class);
        when(mockHttpClient.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        downloadPolicy = mock(DownloadPolicy.class);
        when(downloadPolicy.getMaxCrlResponseBytes()).thenReturn(52_428_800L);
        cache = mock(RevocationCache.class);
        when(cache.getCrl(any())).thenReturn(Optional.empty());

        TrustStoreConfig.RevocationConfig revocationConfig = new TrustStoreConfig.RevocationConfig();
        revocationConfig.setCrlTimeoutSeconds(10);
        revocationConfig.setMaxRetries(0);
        revocationConfig.setRetryIntervalSeconds(0);

        TrustStoreConfig trustStoreConfig = new TrustStoreConfig();
        TrustStoreConfig.NetworkConfig networkConfig = new TrustStoreConfig.NetworkConfig();
        networkConfig.setDownloadTimeoutSeconds(30);
        networkConfig.setMaxRetries(1);
        networkConfig.setRetryIntervalSeconds(0);
        trustStoreConfig.setNetwork(networkConfig);

        retryPolicy = new RetryPolicy(trustStoreConfig);
        client = new CrlClient(cache, retryPolicy, revocationConfig, mockHttpClient, downloadPolicy,
                Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void testCheckUrlBloqueadaRetornaCrlUnavailable() {
        doThrow(new DownloadPolicyException("URL bloqueada: " + CRL_URL))
                .when(downloadPolicy).validateUrl(CRL_URL);

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.CrlUnavailable.class, status);
        verify(mockHttpClient, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeRetornaCrlUnavailable() {
        mockHttpFailure(new DownloadPolicyException("Resposta CRL muito grande"));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.CrlUnavailable.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeNaoRetenta() {
        TrustStoreConfig.RevocationConfig comRetries = new TrustStoreConfig.RevocationConfig();
        comRetries.setCrlTimeoutSeconds(10);
        comRetries.setMaxRetries(2);
        comRetries.setRetryIntervalSeconds(0);
        CrlClient clientComRetries =
                new CrlClient(cache, retryPolicy, comRetries, mockHttpClient, downloadPolicy);
        mockHttpFailure(new DownloadPolicyException("Resposta CRL muito grande"));

        clientComRetries.check(leafCert, rootCert, CRL_URL);

        // Violação de política não é transitória: uma única requisição mesmo com retries configurados
        verify(mockHttpClient, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    // --- Status do certificado ---

    @Test
    @SneakyThrows
    void testCheckSerialAusenteRetornaGoodECacheia() {
        byte[] crl = rootSigned(crlBuilder());
        mockHttpResponse(crl);

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        RevocationStatus.Good good = assertInstanceOf(RevocationStatus.Good.class, status);
        assertArrayEquals(crl, good.responseDer());
        assertArrayEquals(crl, cachedCrl().getEncoded());
    }

    @Test
    @SneakyThrows
    void testCheckSerialListadoRetornaRevokedECacheia() {
        byte[] crl = rootSigned(crlBuilder()
                .addCRLEntry(leafCert.getSerialNumber(), yesterday(), CRLReason.keyCompromise));
        mockHttpResponse(crl);

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Revoked.class, status);
        assertArrayEquals(crl, cachedCrl().getEncoded());
    }

    // --- Emissor ---

    @Test
    @SneakyThrows
    void testCheckIssuerDnDivergenteRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder(OTHER_CA_NAME, now.minus(1, ChronoUnit.HOURS), tomorrow())));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
        verify(cache, never()).putCrl(anyString(), any());
    }

    @Test
    @SneakyThrows
    void testCheckAssinaturaDeOutraChaveRetornaMalformed() {
        mockHttpResponse(signCrl(crlBuilder(), kpg.generateKeyPair()));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckEmissorSemCaRetornaMalformed() {
        KeyPair issuerKeyPair = kpg.generateKeyPair();
        X509Certificate issuerSemCa = generateIssuer(issuerKeyPair, rootName, basicConstraints(false));
        mockHttpResponse(signCrl(crlBuilder(), issuerKeyPair));

        RevocationStatus status = client.check(leafCert, issuerSemCa, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckEmissorSemCrlSignRetornaMalformed() {
        KeyPair issuerKeyPair = kpg.generateKeyPair();
        X509Certificate issuerSemCrlSign = generateIssuer(issuerKeyPair, rootName,
                basicConstraints(true), keyUsage(KeyUsage.keyCertSign));
        mockHttpResponse(signCrl(crlBuilder(), issuerKeyPair));

        RevocationStatus status = client.check(leafCert, issuerSemCrlSign, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckEmissorComCrlSignRetornaGood() {
        KeyPair issuerKeyPair = kpg.generateKeyPair();
        X509Certificate issuerComCrlSign = generateIssuer(issuerKeyPair, rootName,
                basicConstraints(true), keyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        mockHttpResponse(signCrl(crlBuilder(), issuerKeyPair));

        RevocationStatus status = client.check(leafCert, issuerComCrlSign, CRL_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckEmissorQueNaoEmitiuOCertificadoRetornaMalformed() {
        // CRL coerente com o emissor informado, mas o certificado consultado foi emitido por outro DN
        KeyPair outraCaKeyPair = kpg.generateKeyPair();
        X509Certificate outraCa = generateIssuer(outraCaKeyPair, OTHER_CA_NAME, basicConstraints(true));
        mockHttpResponse(signCrl(crlBuilder(OTHER_CA_NAME, now.minus(1, ChronoUnit.HOURS), tomorrow()), outraCaKeyPair));

        RevocationStatus status = client.check(leafCert, outraCa, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    // --- Janela temporal ---

    @Test
    @SneakyThrows
    void testCheckSemNextUpdateRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder(rootName, now.minus(1, ChronoUnit.HOURS), null)));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckNextUpdateVencidoRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder(rootName,
                now.minus(2, ChronoUnit.DAYS), now.minus(1, ChronoUnit.HOURS))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
        verify(cache, never()).putCrl(anyString(), any());
    }

    @Test
    @SneakyThrows
    void testCheckThisUpdateFuturoRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder(rootName,
                now.plus(1, ChronoUnit.HOURS), now.plus(2, ChronoUnit.DAYS))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckThisUpdateFuturoDentroDaToleranciaRetornaGood() {
        mockHttpResponse(rootSigned(crlBuilder(rootName, now.plus(10, ChronoUnit.MINUTES), tomorrow())));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    // --- Escopo: delta e IDP ---

    @Test
    @SneakyThrows
    void testCheckDeltaCrlRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder()
                .addExtension(Extension.deltaCRLIndicator, true, new ASN1Integer(1))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckIdpIndiretaRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder().addExtension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(null, false, false, null, true, false))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckIdpOnlySomeReasonsRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder().addExtension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(null, false, false, new ReasonFlags(ReasonFlags.keyCompromise),
                        false, false))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckIdpOnlyContainsCaCertsComAlvoFolhaRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder().addExtension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(null, false, true, null, false, false))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckIdpOnlyContainsUserCertsComAlvoCaRetornaMalformed() {
        X509Certificate subCa = generateCert(kpg.generateKeyPair(), true, crlDistributionPoint(CRL_URL));
        mockHttpResponse(rootSigned(crlBuilder().addExtension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(null, true, false, null, false, false))));

        RevocationStatus status = client.check(subCa, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckIdpOnlyContainsUserCertsComAlvoFolhaRetornaGood() {
        mockHttpResponse(rootSigned(crlBuilder().addExtension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(null, true, false, null, false, false))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckIdpFullNameNaoCobreUrlRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder().addExtension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(fullName(MIRROR_URL), false, false))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckIdpFullNameCobreUrlRetornaGood() {
        mockHttpResponse(rootSigned(crlBuilder().addExtension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(fullName(CRL_URL), false, false))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckIdpFullNameCobreOutraUriDoMesmoDpRetornaGood() {
        // O DP do certificado lista dois espelhos; o IDP nomeia só o que não foi consultado
        X509Certificate leafComEspelhos = generateCert(leafKeyPair, false,
                new DistributionPoint(fullName(CRL_URL, MIRROR_URL), null, null));
        mockHttpResponse(rootSigned(crlBuilder().addExtension(Extension.issuingDistributionPoint, true,
                new IssuingDistributionPoint(fullName(MIRROR_URL), false, false))));

        RevocationStatus status = client.check(leafComEspelhos, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    // --- Escopo: DP do certificado ---

    @Test
    void testCheckDpComReasonsRetornaMalformedSemHttp() {
        X509Certificate leafComReasons = generateCert(leafKeyPair, false,
                new DistributionPoint(fullName(CRL_URL), new ReasonFlags(ReasonFlags.keyCompromise), null));

        RevocationStatus status = client.check(leafComReasons, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
        verify(mockHttpClient, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void testCheckDpComCrlIssuerRetornaMalformedSemHttp() {
        X509Certificate leafComCrlIssuer = generateCert(leafKeyPair, false,
                new DistributionPoint(fullName(CRL_URL), null, new GeneralNames(new GeneralName(OTHER_CA_NAME))));

        RevocationStatus status = client.check(leafComCrlIssuer, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
        verify(mockHttpClient, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void testCheckUrlForaDosDistributionPointsRetornaMalformedSemHttp() {
        RevocationStatus status = client.check(leafCert, rootCert, MIRROR_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
        verify(mockHttpClient, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    // --- Extensões críticas ---

    @Test
    @SneakyThrows
    void testCheckExtensaoCriticaDesconhecidaRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder().addExtension(UNKNOWN_EXTENSION, true, DERNull.INSTANCE)));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckExtensaoNaoCriticaDesconhecidaRetornaGood() {
        mockHttpResponse(rootSigned(crlBuilder().addExtension(UNKNOWN_EXTENSION, false, DERNull.INSTANCE)));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckEntradaComCertificateIssuerRetornaMalformed() {
        Extension certificateIssuer = new Extension(Extension.certificateIssuer, true,
                new GeneralNames(new GeneralName(OTHER_CA_NAME)).getEncoded());
        mockHttpResponse(rootSigned(crlBuilder()
                .addCRLEntry(leafCert.getSerialNumber(), yesterday(), new Extensions(certificateIssuer))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    /**
     * A entrada com certificateIssuer precede a do alvo: pela regra de herança da RFC 5280 5.3.3 a
     * JVM atribui a revogação do alvo ao outro emissor e não a encontraria. A lista inteira deixa
     * de servir como evidência — nem Good nem Revoked.
     */
    @Test
    @SneakyThrows
    void testCheckEntradaComCertificateIssuerAntesDoAlvoRetornaMalformed() {
        Extension certificateIssuer = new Extension(Extension.certificateIssuer, true,
                new GeneralNames(new GeneralName(OTHER_CA_NAME)).getEncoded());
        mockHttpResponse(rootSigned(crlBuilder()
                .addCRLEntry(BigInteger.valueOf(999), yesterday(), new Extensions(certificateIssuer))
                .addCRLEntry(leafCert.getSerialNumber(), yesterday(), CRLReason.keyCompromise)));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
        verify(cache, never()).putCrl(anyString(), any());
    }

    @Test
    @SneakyThrows
    void testCheckEntradaRemoveFromCrlRetornaMalformed() {
        mockHttpResponse(rootSigned(crlBuilder()
                .addCRLEntry(leafCert.getSerialNumber(), yesterday(), CRLReason.removeFromCRL)));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckEntradaComExtensaoCriticaDesconhecidaRetornaMalformed() {
        Extension desconhecida = new Extension(UNKNOWN_EXTENSION, true, DERNull.INSTANCE.getEncoded());
        mockHttpResponse(rootSigned(crlBuilder()
                .addCRLEntry(leafCert.getSerialNumber(), yesterday(), new Extensions(desconhecida))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    // --- Cache ---

    @Test
    @SneakyThrows
    void testCheckHitDeCacheValidoRetornaGoodSemHttp() {
        when(cache.getCrl(CRL_URL)).thenReturn(Optional.of(decode(rootSigned(crlBuilder()))));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
        verify(mockHttpClient, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testCheckHitDeCacheVencidoRefazDownloadERefleteNovaCrl() {
        byte[] vencida = rootSigned(crlBuilder(rootName, now.minus(2, ChronoUnit.DAYS), now.minus(1, ChronoUnit.HOURS)));
        when(cache.getCrl(CRL_URL)).thenReturn(Optional.of(decode(vencida)));
        byte[] atual = rootSigned(crlBuilder()
                .addCRLEntry(leafCert.getSerialNumber(), yesterday(), CRLReason.keyCompromise));
        mockHttpResponse(atual);

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.Revoked.class, status);
        verify(mockHttpClient, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        assertArrayEquals(atual, cachedCrl().getEncoded());
    }

    // --- Helpers: cache ---

    /** A CRL que o cliente guardou no cache após um resultado conclusivo. */
    private X509CRL cachedCrl() {
        ArgumentCaptor<X509CRL> captor = ArgumentCaptor.forClass(X509CRL.class);
        verify(cache).putCrl(eq(CRL_URL), captor.capture());
        return captor.getValue();
    }

    @SneakyThrows
    private static X509CRL decode(byte[] crlBytes) {
        return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(crlBytes));
    }

    // --- Helpers: certificados ---

    /**
     * Certificado emitido pela raiz com os DPs informados; {@code ca} define basicConstraints,
     * que decide a classe do alvo frente a onlyContainsUserCerts/onlyContainsCACerts. O issuer
     * copia o subject DER da raiz, como uma AC real faz: reconstruí-lo a partir da string RFC 2253
     * inverteria a ordem dos RDNs e o nome deixaria de casar na comparação canônica.
     */
    @SneakyThrows
    private X509Certificate generateCert(KeyPair subjectKeyPair, boolean ca, DistributionPoint... points) {
        X500Name issuerName = X500Name.getInstance(rootCert.getSubjectX500Principal().getEncoded());
        X500Name subject = new X500Name(ca ? "CN=Test Sub CA, O=Test, C=BR" : "CN=Test Leaf, O=Test, C=BR");
        X509v3CertificateBuilder builder = createBuilder(issuerName, subject, ca ? 2 : 3, subjectKeyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        addSki(builder, subjectKeyPair);
        addAki(builder, rootKeyPair);
        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(points));
        return sign(builder, rootKeyPair);
    }

    /** CA auto-assinada com o subject e as extensões informadas (sem basicConstraints implícito). */
    @SneakyThrows
    private X509Certificate generateIssuer(KeyPair keyPair, X500Name subject, Extension... extensions) {
        X509v3CertificateBuilder builder = createBuilder(subject, subject, 1, keyPair);
        addSki(builder, keyPair);
        for (Extension extension : extensions) {
            builder.addExtension(extension);
        }
        return sign(builder, keyPair);
    }

    @SneakyThrows
    private static Extension basicConstraints(boolean ca) {
        return new Extension(Extension.basicConstraints, true, new BasicConstraints(ca).getEncoded());
    }

    @SneakyThrows
    private static Extension keyUsage(int usage) {
        return new Extension(Extension.keyUsage, true, new KeyUsage(usage).getEncoded());
    }

    private static DistributionPointName fullName(String... urls) {
        GeneralName[] names = new GeneralName[urls.length];
        for (int i = 0; i < urls.length; i++) {
            names[i] = new GeneralName(GeneralName.uniformResourceIdentifier, urls[i]);
        }
        return new DistributionPointName(new GeneralNames(names));
    }

    // --- Helpers: CRLs ---

    /** CRL da raiz emitida há uma hora e válida até amanhã. */
    private X509v2CRLBuilder crlBuilder() {
        return crlBuilder(rootName, now.minus(1, ChronoUnit.HOURS), tomorrow());
    }

    private X509v2CRLBuilder crlBuilder(X500Name issuer, Instant thisUpdate, Instant nextUpdate) {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, Date.from(thisUpdate));
        if (nextUpdate != null) {
            builder.setNextUpdate(Date.from(nextUpdate));
        }
        return builder;
    }

    private byte[] rootSigned(X509v2CRLBuilder builder) {
        return signCrl(builder, rootKeyPair);
    }

    @SneakyThrows
    private static byte[] signCrl(X509v2CRLBuilder builder, KeyPair signerKeyPair) {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(signerKeyPair.getPrivate());
        return builder.build(signer).getEncoded();
    }

    private Instant tomorrow() {
        return now.plus(1, ChronoUnit.DAYS);
    }

    private Date yesterday() {
        return Date.from(now.minus(1, ChronoUnit.DAYS));
    }

    // --- Helpers: HTTP mock ---

    /** Simula um 200 com o corpo informado; o transporte só consome status e corpo da resposta. */
    @SuppressWarnings("unchecked")
    private void mockHttpResponse(byte[] body) {
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(body);
        doReturn(CompletableFuture.completedFuture(response))
                .when(mockHttpClient).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    /**
     * Simula a falha assíncrona que o transporte observa: o cancelamento por excesso de
     * tamanho chega como future completado excepcionalmente.
     */
    @SuppressWarnings("unchecked")
    private void mockHttpFailure(Exception failure) {
        doReturn(CompletableFuture.failedFuture(failure))
                .when(mockHttpClient).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }
}
