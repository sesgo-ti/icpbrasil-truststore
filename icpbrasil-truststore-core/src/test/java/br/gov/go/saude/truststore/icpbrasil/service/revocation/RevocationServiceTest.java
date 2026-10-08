package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestChain;
import com.sun.net.httpserver.HttpServer;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Slf4j
class RevocationServiceTest {

    private static final String OCSP_URL = "http://ocsp.teste.example/status";
    private static final String CRL_URL = "http://crl.teste.example/ac-teste.crl";

    private OcspClient ocspClient;
    private CrlClient crlClient;
    private RevocationService revocationService;

    private KeyPair caKeyPair;
    private KeyPair leafKeyPair;
    private X509Certificate leafCert;
    private X509Certificate issuerCert;

    /** Servidor local dos testes com clientes reais; iniciado sob demanda por {@link #realChain}. */
    private HttpServer server;
    private final Map<String, byte[]> responses = new ConcurrentHashMap<>();
    private final Map<String, Integer> statuses = new ConcurrentHashMap<>();
    private final Map<String, Integer> requests = new ConcurrentHashMap<>();

    @SneakyThrows
    @BeforeEach
    void setUp() {
        ocspClient = mock(OcspClient.class);
        crlClient = mock(CrlClient.class);
        revocationService = new RevocationService(ocspClient, crlClient);

        // O par precisa de CRL DPs e AIA sem OCSP: o fluxo testado consulta essas extensões
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        caKeyPair = kpg.generateKeyPair();
        leafKeyPair = kpg.generateKeyPair();
        issuerCert = TestCertificateFactory.generateIcpBrasilTestCa(caKeyPair);
        leafCert = TestCertificateFactory.generateIcpBrasilPersonCert(leafKeyPair, caKeyPair, issuerCert);
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void testCheck_ComCrlRetornandoGood_DeveRetornarGood() {
        // Given - OCSP retorna inconclusivo; CRL retorna Good
        List<String> crlUrls = CertificateParser.getCrlUrls(leafCert);
        assertFalse(crlUrls.isEmpty());

        List<String> ocspUrls = CertificateParser.getOcspUrls(leafCert);
        for (String url : ocspUrls) {
            when(ocspClient.lookup(eq(leafCert), eq(issuerCert), eq(url), any()))
                    .thenReturn(RevocationLookup.inconclusive(new RevocationStatus.OcspUnavailable()));
        }
        when(crlClient.lookup(leafCert, issuerCert, crlUrls.get(0)))
                .thenReturn(crlGood());

        // When
        RevocationStatus status = revocationService.check(leafCert, issuerCert);

        // Then
        assertInstanceOf(RevocationStatus.Good.class, status);
        RevocationStatus.Good good = (RevocationStatus.Good) status;
        assertEquals("CRL", good.source());
    }

    @Test
    void testCheck_OcspMalformedECrlGood_DeveRetornarGood() {
        X509Certificate cert = generateCertComOcspECrl();
        when(ocspClient.lookup(eq(cert), eq(issuerCert), eq(OCSP_URL), any()))
                .thenReturn(RevocationLookup.inconclusive(new RevocationStatus.Malformed("OCSP")));
        when(crlClient.lookup(cert, issuerCert, CRL_URL)).thenReturn(crlGood());

        RevocationStatus status = revocationService.check(cert, issuerCert);

        RevocationStatus.Good good = assertInstanceOf(RevocationStatus.Good.class, status);
        assertEquals("CRL", good.source());
    }

    @Test
    void testCheck_TudoInconclusivoComNoConnectivity_DeveRetornarNoConnectivity() {
        X509Certificate cert = generateCertComOcspECrl();
        when(ocspClient.lookup(eq(cert), eq(issuerCert), eq(OCSP_URL), any()))
                .thenReturn(RevocationLookup.inconclusive(new RevocationStatus.NoConnectivity()));
        when(crlClient.lookup(cert, issuerCert, CRL_URL))
                .thenReturn(RevocationLookup.inconclusive(new RevocationStatus.Malformed("CRL")));

        RevocationStatus status = revocationService.check(cert, issuerCert);

        assertInstanceOf(RevocationStatus.NoConnectivity.class, status);
    }

    @Test
    void testCheck_ThreadInterrompida_DeveEncerrarTentativas() {
        List<String> crlUrls = CertificateParser.getCrlUrls(leafCert);
        assertEquals(2, crlUrls.size());
        when(crlClient.lookup(leafCert, issuerCert, crlUrls.get(0))).thenAnswer(invocation -> {
            Thread.currentThread().interrupt();
            return RevocationLookup.inconclusive(new RevocationStatus.NoConnectivity());
        });

        try {
            RevocationStatus status = revocationService.check(leafCert, issuerCert);

            assertInstanceOf(RevocationStatus.NoConnectivity.class, status);
            verify(crlClient, never()).lookup(leafCert, issuerCert, crlUrls.get(1));
        } finally {
            // O serviço deve preservar a flag; limpá-la aqui evita contaminar os testes seguintes
            assertTrue(Thread.interrupted());
        }
    }

    @Test
    void testCheck_CertificadoSemDistributionPoints_DeveRetornarNoDistributionPoints() {
        // Given - certificado auto-assinado sem AIA e sem CRL DP
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X500Principal("CN=Test Root"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 86400000L));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 86400000L));
        certGen.setSubjectDN(new X500Principal("CN=Test Root"));
        certGen.setPublicKey(kp.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSA");

        X509Certificate selfSigned;
        try {
            @SuppressWarnings("deprecation")
            X509Certificate generated = certGen.generate(kp.getPrivate());
            selfSigned = generated;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // When
        RevocationStatus status = revocationService.check(selfSigned, selfSigned);

        // Then
        assertInstanceOf(RevocationStatus.NoDistributionPoints.class, status);
    }

    @Test
    void testRevocationConfig_ValoresPadrao_DeveEstarConfigurada() {
        // Given - RevocationConfig com valores padrão (sem binding de properties)
        TrustStoreConfig.RevocationConfig config = new TrustStoreConfig.RevocationConfig();

        // Then - os defaults declarados na classe devem estar corretos
        assertEquals(10, config.getOcspTimeoutSeconds());
        assertEquals(10, config.getCrlTimeoutSeconds());
        assertEquals(2, config.getMaxRetries());
        assertEquals(3, config.getRetryIntervalSeconds());
        assertEquals(3600, config.getOcspCacheTtlSeconds());
        assertEquals(3600, config.getCrlCacheTtlSeconds());
    }

    // --- Responder OCSP delegado, com OcspClient e CrlClient reais ---

    @Test
    @SneakyThrows
    void testLookup_DelegadoComOcspNoCheck_GoodPorOcspSemConsultarCrl() {
        TestChain chain = realChain();
        TestChain.Responder responder = chain.delegatedResponder(new TestChain.Endpoints(url("/intermediate.crl"), null),
                new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE.getEncoded()));
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        responses.put("/intermediate-ocsp", chain.delegatedOcsp(responder, now, CertificateStatus.GOOD));

        RevocationLookup lookup = realService(now).lookup(chain.leaf(), chain.intermediate());

        assertEquals("OCSP", assertInstanceOf(RevocationStatus.Good.class, lookup.status()).source());
        assertEquals(Map.of("/intermediate-ocsp", 1), requests);
    }

    @Test
    void testLookup_DelegadoSemOcspNoCheckNaoRevogadoNaCrlDaAc_GoodPorOcsp() {
        TestChain chain = realChain();
        TestChain.Responder responder = chain.delegatedResponder(new TestChain.Endpoints(url("/intermediate.crl"), null));
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        responses.put("/intermediate-ocsp", chain.delegatedOcsp(responder, now, CertificateStatus.GOOD));
        responses.put("/intermediate.crl", chain.intermediateCrl(now, Map.of()));

        RevocationLookup lookup = realService(now).lookup(chain.leaf(), chain.intermediate());

        assertEquals("OCSP", assertInstanceOf(RevocationStatus.Good.class, lookup.status()).source());
        assertInstanceOf(RevocationEvidence.OcspResponse.class, lookup.evidence());
    }

    @Test
    void testLookup_DelegadoSemOcspNoCheckRevogadoNaCrlDaAc_StatusDaFolhaVemDaCrl() {
        TestChain chain = realChain();
        TestChain.Responder responder = chain.delegatedResponder(new TestChain.Endpoints(url("/intermediate.crl"), null));
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        // Chave do responder vazada: ele atesta "good" para uma folha que a AC já revogou
        responses.put("/intermediate-ocsp", chain.delegatedOcsp(responder, now, CertificateStatus.GOOD));
        responses.put("/intermediate.crl", chain.intermediateCrl(now, Map.of(
                responder.certificate().getSerialNumber(), now.minus(1, ChronoUnit.HOURS),
                chain.leaf().getSerialNumber(), now.minus(1, ChronoUnit.HOURS))));

        RevocationLookup lookup = realService(now).lookup(chain.leaf(), chain.intermediate());

        assertEquals("CRL", assertInstanceOf(RevocationStatus.Revoked.class, lookup.status()).source());
        assertInstanceOf(RevocationEvidence.Crl.class, lookup.evidence());
    }

    @Test
    void testLookup_DelegadoSemOcspNoCheckRevogadoEFolhaNaoRevogada_GoodPorCrl() {
        TestChain chain = realChain();
        TestChain.Responder responder = chain.delegatedResponder(new TestChain.Endpoints(url("/intermediate.crl"), null));
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        responses.put("/intermediate-ocsp", chain.delegatedOcsp(responder, now, CertificateStatus.GOOD));
        responses.put("/intermediate.crl", chain.intermediateCrl(now, Map.of(
                responder.certificate().getSerialNumber(), now.minus(1, ChronoUnit.HOURS))));

        RevocationLookup lookup = realService(now).lookup(chain.leaf(), chain.intermediate());

        assertEquals("CRL", assertInstanceOf(RevocationStatus.Good.class, lookup.status()).source());
    }

    @Test
    void testLookup_DelegadoSemOcspNoCheckCrlDaAcIndisponivel_Inconclusivo() {
        TestChain chain = realChain();
        TestChain.Responder responder = chain.delegatedResponder(new TestChain.Endpoints(url("/intermediate.crl"), null));
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        responses.put("/intermediate-ocsp", chain.delegatedOcsp(responder, now, CertificateStatus.GOOD));
        statuses.put("/intermediate.crl", 500);

        RevocationLookup lookup = realService(now).lookup(chain.leaf(), chain.intermediate());

        assertInstanceOf(RevocationStatus.CrlUnavailable.class, lookup.status());
        // A mesma LCR serve ao responder e ao fallback da folha: uma falha não se repete na consulta
        assertEquals(1, requests.get("/intermediate.crl"));
    }

    @Test
    void testLookup_DelegadoSemOcspNoCheckESemCrlDp_Inconclusivo() {
        TestChain chain = realChain();
        TestChain.Responder responder = chain.delegatedResponder(TestChain.Endpoints.none());
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        responses.put("/intermediate-ocsp", chain.delegatedOcsp(responder, now, CertificateStatus.GOOD));
        statuses.put("/intermediate.crl", 500);

        RevocationLookup lookup = realService(now).lookup(chain.leaf(), chain.intermediate());

        assertInstanceOf(RevocationStatus.CrlUnavailable.class, lookup.status());
    }

    @Test
    void testLookup_RespostaAssinadaPelaAc_GoodPorOcspSemConsultarCrl() {
        TestChain chain = realChain();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        responses.put("/intermediate-ocsp", chain.intermediateOcsp(now, CertificateStatus.GOOD));

        RevocationLookup lookup = realService(now).lookup(chain.leaf(), chain.intermediate());

        assertEquals("OCSP", assertInstanceOf(RevocationStatus.Good.class, lookup.status()).source());
        assertEquals(Map.of("/intermediate-ocsp", 1), requests);
    }

    /** Cadeia cujos endpoints de revogação apontam para o servidor local. */
    @SneakyThrows
    private TestChain realChain() {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            requests.merge(path, 1, Integer::sum);
            exchange.getRequestBody().readAllBytes();
            byte[] body = responses.getOrDefault(path, new byte[0]);
            exchange.sendResponseHeaders(statuses.getOrDefault(path, 200), body.length == 0 ? -1 : body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        return TestChain.create(new TestChain.Endpoints(url("/root.crl"), url("/root-ocsp")),
                new TestChain.Endpoints(url("/intermediate.crl"), url("/intermediate-ocsp")));
    }

    private String url(String path) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    /** Serviço com clientes reais e relógio fixo; a política de download libera o loopback do teste. */
    private static RevocationService realService(Instant now) {
        DownloadPolicy policy = mock(DownloadPolicy.class);
        when(policy.getMaxOcspResponseBytes()).thenReturn(1_048_576L);
        when(policy.getMaxCrlResponseBytes()).thenReturn(52_428_800L);
        HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        TrustStoreConfig config = new TrustStoreConfig();
        config.getRevocation().setMaxRetries(0);
        config.getRevocation().setRetryIntervalSeconds(0);
        RetryPolicy retryPolicy = new RetryPolicy(config);
        RevocationCache cache = new RevocationCache(config);
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        return new RevocationService(
                new OcspClient(cache, retryPolicy, config.getRevocation(), httpClient, policy, clock),
                new CrlClient(cache, retryPolicy, config.getRevocation(), httpClient, policy, clock));
    }

    /** Good por CRL com uma evidência qualquer: o serviço só repassa o que o cliente devolveu. */
    private static RevocationLookup crlGood() {
        return new RevocationLookup(new RevocationStatus.Good("CRL", new byte[0]),
                new RevocationEvidence.Crl(mock(X509CRL.class)));
    }

    /** Folha emitida pela AC de teste com um responder OCSP na AIA e um único CRL DP. */
    @SneakyThrows
    private X509Certificate generateCertComOcspECrl() {
        X500Name issuerName = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());
        X509v3CertificateBuilder builder = TestCertificateFactory.createBuilder(
                issuerName, new X500Name("CN=Test Leaf, O=Test, C=BR"), 12, leafKeyPair);
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        TestCertificateFactory.addSki(builder, leafKeyPair);
        TestCertificateFactory.addAki(builder, caKeyPair);
        builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, OCSP_URL)));
        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(
                new DistributionPoint[]{TestCertificateFactory.crlDistributionPoint(CRL_URL)}));
        return TestCertificateFactory.sign(builder, caKeyPair);
    }
}
