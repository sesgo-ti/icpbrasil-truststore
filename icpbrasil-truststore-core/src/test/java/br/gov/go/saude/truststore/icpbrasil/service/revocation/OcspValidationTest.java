package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
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
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.createBuilder;
import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.sign;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OcspValidationTest {

    private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");
    private static final String URL = "http://ocsp.example.com/status";
    private static final X500Name ISSUER_NAME = new X500Name("CN=Test Issuer");
    private static KeyPair issuerKey;
    private static KeyPair responderKey;
    private static KeyPair otherKey;
    private static X509Certificate issuer;
    private static X509Certificate target;

    private HttpClient http;
    private Clock clock;
    private RevocationCache cache;
    private OcspClient client;
    private CertificateID targetId;
    private BasicOCSPRespBuilder builder;
    private Instant producedAt;

    @BeforeAll
    @SneakyThrows
    static void setUpCertificates() {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        issuerKey = generator.generateKeyPair();
        responderKey = generator.generateKeyPair();
        otherKey = generator.generateKeyPair();
        X509v3CertificateBuilder root = createBuilder(ISSUER_NAME, ISSUER_NAME, 1, issuerKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400 * 365));
        root.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        issuer = sign(root, issuerKey);
        target = sign(createBuilder(ISSUER_NAME, new X500Name("CN=Target"), 3, otherKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400)), issuerKey);
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
        client = new OcspClient(cache, new RetryPolicy(config), config.getRevocation(),
                http, mock(DownloadPolicy.class), clock);
        targetId = id(issuer, target.getSerialNumber(), CertificateID.HASH_SHA1);
        builder = new BasicOCSPRespBuilder(new RespID(ISSUER_NAME));
        producedAt = NOW;
    }

    @ParameterizedTest
    @ValueSource(strings = {"1.3.14.3.2.26", "2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.1",
            "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3"})
    @SneakyThrows
    void testGoodCorrelacionaAlgoritmoCertId(String oid) {
        targetId = id(issuer, target.getSerialNumber(), new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid)));
        add(targetId, CertificateStatus.GOOD);
        byte[] der = response(issuerKey);
        serve(der);
        RevocationStatus.Good good = assertInstanceOf(RevocationStatus.Good.class, check());
        assertEquals("OCSP", good.source());
        assertArrayEquals(der, good.responseDer());
        assertInstanceOf(RevocationStatus.Good.class, check());
        verify(http, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        verify(cache, times(1)).putOcsp(any(), any());
    }

    @Test
    void testRevoked() {
        add(targetId, new RevokedStatus(Date.from(NOW.minusSeconds(600)), 1));
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.Revoked.class, check());
    }

    @Test
    void testUnknownInconclusivoNaoCacheia() {
        add(targetId, new UnknownStatus());
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.OcspUnavailable.class, check());
        verify(cache, never()).putOcsp(any(), any());
    }

    @Test
    void testAssinaturaIncorreta() {
        add(targetId, CertificateStatus.GOOD);
        serve(response(otherKey));
        assertMalformed();
        verify(cache, never()).putOcsp(any(), any());
    }

    @Test
    void testSerialDiferente() {
        add(CertificateID.deriveCertificateID(targetId, BigInteger.TEN), CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testHashIssuerIncorreto(boolean nameHash) {
        CertID original = targetId.toASN1Primitive();
        targetId = new CertificateID(new CertID(original.getHashAlgorithm(),
                nameHash ? new DEROctetString(new byte[20]) : original.getIssuerNameHash(),
                nameHash ? original.getIssuerKeyHash() : new DEROctetString(new byte[20]),
                original.getSerialNumber()));
        add(targetId, CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    void testAlgoritmoCertIdNaoPermitido() {
        CertID original = targetId.toASN1Primitive();
        targetId = new CertificateID(new CertID(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")),
                original.getIssuerNameHash(), original.getIssuerKeyHash(), original.getSerialNumber()));
        add(targetId, CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testSelecionaSegundoTargetNaoPrimeiro(boolean revoked) {
        add(CertificateID.deriveCertificateID(targetId, BigInteger.TEN),
                revoked ? CertificateStatus.GOOD : new RevokedStatus(Date.from(NOW.minusSeconds(600)), 1));
        add(targetId, revoked ? new RevokedStatus(Date.from(NOW.minusSeconds(600)), 1) : CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertEquals(revoked ? RevocationStatus.Revoked.class : RevocationStatus.Good.class, check().getClass());
    }

    @Test
    void testSemSingleResp() {
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testTargetDuplicadoMesmoStatusOuConflitante(boolean sameStatus) {
        add(targetId, CertificateStatus.GOOD);
        add(targetId, sameStatus ? CertificateStatus.GOOD : new RevokedStatus(Date.from(NOW), 1));
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    void testTargetDuplicadoAlgoritmosDiferentes() {
        add(targetId, CertificateStatus.GOOD);
        add(id(issuer, target.getSerialNumber(), new AlgorithmIdentifier(
                new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"))), CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertMalformed();
    }

    @ParameterizedTest
    @CsvSource({
            "-3600, -301, -600, false",
            "301, 3600, 0, false",
            "-60, 3600, 301, false",
            "-60, 3600, -361, false",
            "-3600, -600, 0, false",
            "-60, -61, 0, false",
            "-3600, -300, -600, true",
            "300, 3600, 300, true",
            "-60, 3600, 300, true",
            "-60, 3600, -360, true",
            "-600, -300, 0, true"
    })
    void testJanelaTemporalComTolerancia(long thisOffset, long nextOffset, long producedOffset, boolean valid) {
        builder.addResponse(targetId, CertificateStatus.GOOD, Date.from(NOW.plusSeconds(thisOffset)),
                Date.from(NOW.plusSeconds(nextOffset)), null);
        producedAt = NOW.plusSeconds(producedOffset);
        serve(response(issuerKey));
        assertEquals(valid ? RevocationStatus.Good.class : RevocationStatus.Malformed.class, check().getClass());
    }

    @ParameterizedTest
    @CsvSource({"-60, true", "-86700, true", "-86701, false"})
    void testSemNextUpdateRecenciaMaxima(long thisOffset, boolean valid) {
        builder.addResponse(targetId, CertificateStatus.GOOD, Date.from(NOW.plusSeconds(thisOffset)), null, null);
        serve(response(issuerKey));
        assertEquals(valid ? RevocationStatus.Good.class : RevocationStatus.Malformed.class, check().getClass());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testCacheRevalidaExpiracaoSemRenovarEvidencia(boolean nextUpdate) {
        builder.addResponse(targetId, CertificateStatus.GOOD, Date.from(NOW),
                nextUpdate ? Date.from(NOW.plusSeconds(60)) : null, null);
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.Good.class, check());
        when(clock.instant()).thenReturn(NOW.plusSeconds(nextUpdate ? 360 : 86700));
        assertInstanceOf(RevocationStatus.Good.class, check());
        when(clock.instant()).thenReturn(NOW.plusSeconds(nextUpdate ? 361 : 86701));
        assertMalformed();
        verify(http, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        verify(cache, times(1)).putOcsp(any(), any());
    }

    @Test
    void testCacheRevalidaAssinatura() {
        add(targetId, CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.Good.class, check());
        doReturn(Optional.of(response(otherKey))).when(cache).getOcsp(any());
        assertMalformed();
    }

    @Test
    @SneakyThrows
    void testCacheSeparaIssuerMesmoDnSerialEChaveDiferente() {
        add(targetId, CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.Good.class, check());
        X509Certificate otherIssuer = sign(createBuilder(ISSUER_NAME, ISSUER_NAME, 1, otherKey,
                NOW.minusSeconds(86400), NOW.plusSeconds(86400)), otherKey);
        assertInstanceOf(RevocationStatus.Malformed.class, client.check(target, otherIssuer, URL));
        verify(http, times(2)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testCacheSeparaTargetMesmoDnSerial() {
        add(targetId, CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.Good.class, check());
        X509Certificate otherTarget = sign(createBuilder(ISSUER_NAME, new X500Name("CN=Target"), 3,
                responderKey, NOW.minusSeconds(86400), NOW.plusSeconds(86400)), issuerKey);
        assertInstanceOf(RevocationStatus.Good.class, client.check(otherTarget, issuer, URL));
        verify(http, times(2)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testResponderIdIssuerNomeOuHashIncorreto(boolean byKey) {
        builder = new BasicOCSPRespBuilder(responderId(target, byKey));
        add(targetId, CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertMalformed();
    }

    @Test
    void testResponderIdIssuerPorHash() {
        builder = new BasicOCSPRespBuilder(responderId(issuer, true));
        add(targetId, CertificateStatus.GOOD);
        serve(response(issuerKey));
        assertInstanceOf(RevocationStatus.Good.class, check());
    }

    @ParameterizedTest
    @ValueSource(strings = {"valid", "byKey", "noKeyUsage", "expired", "future", "notValidAtProduction",
            "noEku", "wrongEku", "wrongKeyUsage", "wrongIssuerSignature", "wrongIssuerName",
            "criticalUnknown", "criticalNameConstraints", "ca", "wrongResponderName", "wrongResponderKey"})
    @SneakyThrows
    void testDelegadoAutorizacaoIdentidadeValidade(String scenario) {
        X509v3CertificateBuilder delegated = createBuilder(
                scenario.equals("wrongIssuerName") ? new X500Name("CN=Other") : ISSUER_NAME,
                new X500Name("CN=Responder"), 4, responderKey,
                scenario.equals("future") ? NOW.plusSeconds(1) :
                        scenario.equals("notValidAtProduction") ? NOW.minusSeconds(10) : NOW.minusSeconds(86400),
                scenario.equals("expired") ? NOW.minusSeconds(1) : NOW.plusSeconds(86400));
        delegated.addExtension(Extension.basicConstraints, true, new BasicConstraints(scenario.equals("ca")));
        if (!scenario.equals("noEku")) {
            delegated.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(
                    scenario.equals("wrongEku") ? KeyPurposeId.id_kp_serverAuth : KeyPurposeId.id_kp_OCSPSigning));
        }
        if (!scenario.equals("noKeyUsage")) {
            delegated.addExtension(Extension.keyUsage, true, new KeyUsage(
                    scenario.equals("wrongKeyUsage") ? KeyUsage.keyEncipherment : KeyUsage.digitalSignature));
        }
        if (scenario.equals("criticalUnknown")) {
            delegated.addExtension(new ASN1ObjectIdentifier("1.2.3.4"), true, DERNull.INSTANCE);
        }
        if (scenario.equals("criticalNameConstraints")) {
            delegated.addExtension(Extension.nameConstraints, true, new NameConstraints(
                    new GeneralSubtree[]{new GeneralSubtree(new GeneralName(GeneralName.dNSName, "example.com"))},
                    null));
        }
        X509Certificate signer = sign(delegated, scenario.equals("wrongIssuerSignature") ? otherKey : issuerKey);
        boolean wrongId = scenario.startsWith("wrongResponder");
        builder = new BasicOCSPRespBuilder(responderId(wrongId ? issuer : signer,
                scenario.equals("byKey") || scenario.equals("wrongResponderKey")));
        add(targetId, CertificateStatus.GOOD);
        producedAt = NOW.minusSeconds(30);
        serve(response(responderKey, signer));
        boolean valid = scenario.equals("valid") || scenario.equals("byKey") || scenario.equals("noKeyUsage");
        assertEquals(valid ? RevocationStatus.Good.class : RevocationStatus.Malformed.class, check().getClass());
    }

    @Test
    @SneakyThrows
    void testCacheRevalidaValidadeDelegado() {
        X509v3CertificateBuilder delegated = createBuilder(ISSUER_NAME, new X500Name("CN=Responder"), 4,
                responderKey, NOW.minusSeconds(86400), NOW.plusSeconds(30));
        delegated.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        X509Certificate signer = sign(delegated, issuerKey);
        builder = new BasicOCSPRespBuilder(responderId(signer, true));
        add(targetId, CertificateStatus.GOOD);
        serve(response(responderKey, signer));
        assertInstanceOf(RevocationStatus.Good.class, check());
        when(clock.instant()).thenReturn(NOW.plusSeconds(31));
        assertMalformed();
        verify(http, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    @SneakyThrows
    void testExtensaoCriticaRespostaOuSingleResp(boolean responseExtension) {
        Extensions extensions = new Extensions(new Extension(new ASN1ObjectIdentifier("1.2.3.4"),
                true, DERNull.INSTANCE.getEncoded()));
        if (responseExtension) {
            builder.setResponseExtensions(extensions);
        }
        builder.addResponse(targetId, CertificateStatus.GOOD, Date.from(NOW.minusSeconds(60)),
                Date.from(NOW.plusSeconds(3600)), responseExtension ? null : extensions);
        serve(response(issuerKey));
        assertMalformed();
    }

    private RevocationStatus check() {
        return client.check(target, issuer, URL);
    }

    private void assertMalformed() {
        assertInstanceOf(RevocationStatus.Malformed.class, check());
    }

    private void add(CertificateID id, CertificateStatus status) {
        builder.addResponse(id, status, Date.from(NOW.minusSeconds(60)), Date.from(NOW.plusSeconds(3600)), null);
    }

    @SneakyThrows
    private CertificateID id(X509Certificate cert, BigInteger serial, AlgorithmIdentifier algorithm) {
        return new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(algorithm),
                new JcaX509CertificateHolder(cert), serial);
    }

    @SneakyThrows
    private RespID responderId(X509Certificate signer, boolean byKey) {
        X509CertificateHolder holder = new JcaX509CertificateHolder(signer);
        return byKey ? new RespID(holder.getSubjectPublicKeyInfo(),
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1))
                : new RespID(holder.getSubject());
    }

    @SneakyThrows
    private byte[] response(KeyPair signingKey, X509Certificate... embedded) {
        X509CertificateHolder[] holders = new X509CertificateHolder[embedded.length];
        for (int i = 0; i < embedded.length; i++) {
            holders[i] = new JcaX509CertificateHolder(embedded[i]);
        }
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signingKey.getPrivate()),
                holders, Date.from(producedAt))).getEncoded();
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
