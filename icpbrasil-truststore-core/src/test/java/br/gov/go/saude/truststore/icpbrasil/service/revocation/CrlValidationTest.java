package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.CompletableFuture;

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.createBuilder;
import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.sign;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CrlValidationTest {

    private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");
    private static final String URL = "http://crl.example.com/list.crl";
    private static final String OCSP_URL = "http://ocsp.example.com/status";
    private static final X500Name ISSUER_NAME = new X500Name("CN=Test Issuer");
    private static final ASN1ObjectIdentifier UNKNOWN = new ASN1ObjectIdentifier("1.2.3.4");
    private static final DistributionPointName DP_NAME = new DistributionPointName(
            new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, URL)));
    private static KeyPair issuerKey;
    private static KeyPair otherKey;
    private static X509Certificate issuer;

    private X509Certificate target;
    private X509v3CertificateBuilder targetBuilder;
    private X509v2CRLBuilder builder;
    private HttpClient http;
    private Clock clock;
    private RevocationCache cache;
    private CrlClient client;

    @BeforeAll
    @SneakyThrows
    static void setUpCertificates() {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        issuerKey = generator.generateKeyPair();
        otherKey = generator.generateKeyPair();
        X509v3CertificateBuilder root = createBuilder(ISSUER_NAME, ISSUER_NAME, 1, issuerKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400 * 365));
        root.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        root.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        issuer = sign(root, issuerKey);
    }

    @BeforeEach
    @SneakyThrows
    void setUp() {
        TrustStoreConfig config = new TrustStoreConfig();
        config.setRevocation(new TrustStoreConfig.RevocationConfig());
        config.getRevocation().setMaxRetries(0);
        cache = spy(new RevocationCache(config));
        http = mock(HttpClient.class);
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        clock = mock(Clock.class);
        when(clock.instant()).thenReturn(NOW);
        client = new CrlClient(cache, new RetryPolicy(config), config.getRevocation(),
                http, mock(DownloadPolicy.class), clock);
        targetBuilder = createBuilder(ISSUER_NAME, new X500Name("CN=Target"), 3, otherKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400));
        targetBuilder.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{new DistributionPoint(DP_NAME, null, null)}));
        targetBuilder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(new AccessDescription(AccessDescription.id_ad_ocsp,
                        new GeneralName(GeneralName.uniformResourceIdentifier, OCSP_URL))));
        target = sign(targetBuilder, issuerKey);
        builder = new X509v2CRLBuilder(ISSUER_NAME, Date.from(NOW.minusSeconds(600)));
        builder.setNextUpdate(Date.from(NOW.plusSeconds(3600)));
    }

    @Test
    @SneakyThrows
    void testGoodCompletaComEntradaDeOutroSerialCacheia() {
        builder.addCRLEntry(BigInteger.TEN, Date.from(NOW.minusSeconds(900)), 1);
        builder.addExtension(Extension.cRLNumber, false, new ASN1Integer(1));
        builder.addExtension(UNKNOWN, false, DERNull.INSTANCE);
        byte[] der = response(issuerKey);
        serve(der);
        RevocationStatus.Good good = assertInstanceOf(RevocationStatus.Good.class, check());
        assertEquals("CRL", good.source());
        assertArrayEquals(der, good.responseDer());
        assertInstanceOf(RevocationStatus.Good.class, check());
        verify(http, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        verify(cache, times(1)).putCrl(any(), any());
    }

    @Test
    void testRevokedCacheia() {
        builder.addCRLEntry(target.getSerialNumber(), Date.from(NOW.minusSeconds(900)), 1);
        serve(response(issuerKey));
        assertEquals(new RevocationStatus.Revoked("CRL"), check());
        assertEquals(new RevocationStatus.Revoked("CRL"), check());
        verify(http, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        verify(cache, times(1)).putCrl(any(), any());
    }

    @Test
    void testAssinaturaCrlIncorreta() {
        serve(response(otherKey));
        assertMalformed();
    }

    @Test
    void testDnCrlIncorretoMesmoComChaveCorreta() {
        builder = new X509v2CRLBuilder(new X500Name("CN=Other"), Date.from(NOW.minusSeconds(600)));
        builder.setNextUpdate(Date.from(NOW.plusSeconds(3600)));
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    void testAssinaturaAlvoIncorretaMesmoDn() {
        target = sign(targetBuilder, otherKey);
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    void testDnAlvoIncorretoMesmoComChaveCorreta() {
        target = sign(createBuilder(new X500Name("CN=Other"), new X500Name("CN=Target"), 3, otherKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400)), issuerKey);
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @CsvSource({"true, 6, true", "true, 2, true", "true, -1, true", "true, 4, false",
            "true, 128, false", "false, 2, false", "false, -1, false"})
    @SneakyThrows
    void testAutorizacaoIssuer(boolean ca, int usage, boolean valid) {
        X509v3CertificateBuilder root = createBuilder(ISSUER_NAME, ISSUER_NAME, 1, issuerKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400));
        root.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (usage >= 0) root.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        serve(response(issuerKey));
        RevocationStatus result = client.check(target, sign(root, issuerKey), URL);
        assertEquals(valid ? RevocationStatus.Good.class : RevocationStatus.Malformed.class, result.getClass());
        if (!valid) verify(cache, never()).putCrl(any(), any());
    }

    @Test
    void testIssuerSemBasicConstraints() {
        X509Certificate root = sign(createBuilder(ISSUER_NAME, ISSUER_NAME, 1, issuerKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400)), issuerKey);
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.Malformed.class, client.check(target, root, URL));
    }

    @ParameterizedTest
    @CsvSource({"-600, 3600, true", "300, 3600, true", "301, 3600, false",
            "-600, -300, true", "-600, -301, false", "0, 0, true", "0, -1, false"})
    void testJanelaTemporal(long thisOffset, long nextOffset, boolean valid) {
        builder = new X509v2CRLBuilder(ISSUER_NAME, Date.from(NOW.plusSeconds(thisOffset)));
        builder.setNextUpdate(Date.from(NOW.plusSeconds(nextOffset)));
        serve(response(issuerKey));
        assertEquals(valid ? RevocationStatus.Good.class : RevocationStatus.Malformed.class, check().getClass());
        if (!valid) verify(cache, never()).putCrl(any(), any());
    }

    @Test
    void testSemNextUpdateMesmoRecente() {
        builder = new X509v2CRLBuilder(ISSUER_NAME, Date.from(NOW));
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testCacheRevalidaDatasGoodERevoked(boolean revoked) {
        if (revoked) builder.addCRLEntry(target.getSerialNumber(), Date.from(NOW.minusSeconds(900)), 1);
        serve(response(issuerKey));
        assertEquals(revoked ? RevocationStatus.Revoked.class : RevocationStatus.Good.class, check().getClass());
        when(clock.instant()).thenReturn(NOW.plusSeconds(3901));
        assertInstanceOf(RevocationStatus.Malformed.class, check());
        verify(http, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        verify(cache, times(1)).putCrl(any(), any());
    }

    @Test
    @SneakyThrows
    void testCacheRevalidaAlvoEmissorECobertura() {
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.Good.class, check());
        X509v3CertificateBuilder otherIssuer = createBuilder(ISSUER_NAME, ISSUER_NAME, 4, otherKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400));
        otherIssuer.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate wrongIssuer = sign(otherIssuer, otherKey);
        assertInstanceOf(RevocationStatus.Malformed.class, client.check(target, wrongIssuer, URL));
        X509v3CertificateBuilder unauthorized = createBuilder(ISSUER_NAME, ISSUER_NAME, 1, issuerKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400));
        unauthorized.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        unauthorized.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        assertInstanceOf(RevocationStatus.Malformed.class,
                client.check(target, sign(unauthorized, issuerKey), URL));
        target = sign(targetBuilder, otherKey);
        assertInstanceOf(RevocationStatus.Malformed.class, check());
        restrictTarget(true);
        assertInstanceOf(RevocationStatus.Malformed.class, check());
        verify(http, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        verify(cache, times(1)).putCrl(any(), any());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @SneakyThrows
    void testDeltaIsoladaMesmoNaoCritica(boolean critical) {
        builder.addExtension(Extension.deltaCRLIndicator, critical, new ASN1Integer(1));
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @CsvSource({"full, false", "full, true", "reasons, false", "reasons, true",
            "user, true", "ca, true", "attribute, true", "indirect, false", "indirect, true", "name, false"})
    @SneakyThrows
    void testIdpNaoSuportado(String scope, boolean critical) {
        builder.addExtension(Extension.issuingDistributionPoint, critical,
                new IssuingDistributionPoint(scope.equals("name") ? DP_NAME : null,
                        scope.equals("user"), scope.equals("ca"),
                        scope.equals("reasons") ? new ReasonFlags(ReasonFlags.keyCompromise) : null,
                        scope.equals("indirect"), scope.equals("attribute")));
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    @SneakyThrows
    void testCriticaCrlDesconhecida() {
        builder.addExtension(UNKNOWN, true, DERNull.INSTANCE);
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @CsvSource({"false, false", "false, true", "true, false", "true, true"})
    @SneakyThrows
    void testCriticaEntradaAntesDeGoodOuRevoked(boolean matching, boolean known) {
        Extension extension = Extension.create(known ? Extension.reasonCode : UNKNOWN, true,
                known ? new ASN1Enumerated(1) : DERNull.INSTANCE);
        builder.addCRLEntry(matching ? target.getSerialNumber() : BigInteger.TEN,
                Date.from(NOW.minusSeconds(900)), new Extensions(extension));
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    @SneakyThrows
    void testEntradaCertificateIssuerNaoCritica() {
        builder.addCRLEntry(BigInteger.TEN, Date.from(NOW.minusSeconds(900)), new Extensions(
                Extension.create(Extension.certificateIssuer, false,
                        new GeneralNames(new GeneralName(ISSUER_NAME)))));
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    void testEntradaRemoveFromCrlSemDelta() {
        builder.addCRLEntry(target.getSerialNumber(), Date.from(NOW.minusSeconds(900)), 8);
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testDpRestritoMesmoComOutroCompleto(boolean reasons) {
        restrictTarget(reasons);
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    void testBytesInvalidos() {
        serve(new byte[]{1, 2, 3});
        assertMalformed();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testFallbackOcspMalformedSomenteCrlValidaProduzGood(boolean valid) {
        OcspClient ocsp = mock(OcspClient.class);
        when(ocsp.check(target, issuer, OCSP_URL)).thenReturn(new RevocationStatus.Malformed("OCSP"));
        if (!valid) builder.setNextUpdate(Date.from(NOW.minusSeconds(301)));
        serve(response(issuerKey));
        RevocationStatus result = new RevocationService(ocsp, client).check(target, issuer);
        assertEquals(valid ? RevocationStatus.Good.class : RevocationStatus.Malformed.class, result.getClass());
        if (!valid) verify(cache, never()).putCrl(any(), any());
    }

    @Test
    void testInterrupcaoOcspNaoIniciaFallbackCrl() {
        OcspClient ocsp = mock(OcspClient.class);
        when(ocsp.check(target, issuer, OCSP_URL)).thenAnswer(invocation -> {
            Thread.currentThread().interrupt();
            return new RevocationStatus.NoConnectivity();
        });
        try {
            assertInstanceOf(RevocationStatus.NoConnectivity.class,
                    new RevocationService(ocsp, client).check(target, issuer));
            assertTrue(Thread.currentThread().isInterrupted());
            verifyNoInteractions(cache);
            verify(http, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        } finally {
            Thread.interrupted();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"signature", "delta", "idp", "critical"})
    @SneakyThrows
    void testCacheInvalidoRevalidaSemDownload(String invalid) {
        switch (invalid) {
            case "delta" -> builder.addExtension(Extension.deltaCRLIndicator, false, new ASN1Integer(1));
            case "idp" -> builder.addExtension(Extension.issuingDistributionPoint, false,
                    new IssuingDistributionPoint(null, false, false, null, true, false));
            case "critical" -> builder.addExtension(UNKNOWN, true, DERNull.INSTANCE);
        }
        cache.putCrl(URL, response(invalid.equals("signature") ? otherKey : issuerKey));
        clearInvocations(cache);
        assertMalformed();
        verify(http, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    private RevocationStatus check() {
        return client.check(target, issuer, URL);
    }

    private void assertMalformed() {
        assertEquals(new RevocationStatus.Malformed("CRL"), check());
        verify(cache, never()).putCrl(any(), any());
    }

    @SneakyThrows
    private void restrictTarget(boolean reasons) {
        targetBuilder.replaceExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{new DistributionPoint(DP_NAME, null, null),
                        new DistributionPoint(DP_NAME,
                                reasons ? new ReasonFlags(ReasonFlags.keyCompromise) : null,
                                reasons ? null : new GeneralNames(new GeneralName(ISSUER_NAME)))}));
        target = sign(targetBuilder, issuerKey);
    }

    @SneakyThrows
    private byte[] response(KeyPair signer) {
        return builder.build(new JcaContentSignerBuilder("SHA256WithRSA").build(signer.getPrivate())).getEncoded();
    }

    @SuppressWarnings("unchecked")
    private void serve(byte[] der) {
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(der);
        when(http.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
    }
}
