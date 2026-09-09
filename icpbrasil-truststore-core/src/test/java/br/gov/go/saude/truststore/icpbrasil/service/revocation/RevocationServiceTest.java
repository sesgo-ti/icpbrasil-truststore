package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
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

    @Test
    void testCheck_ComCrlRetornandoGood_DeveRetornarGood() {
        // Given - OCSP retorna inconclusivo; CRL retorna Good
        List<String> crlUrls = CertificateParser.getCrlUrls(leafCert);
        assertFalse(crlUrls.isEmpty());

        List<String> ocspUrls = CertificateParser.getOcspUrls(leafCert);
        for (String url : ocspUrls) {
            when(ocspClient.lookup(leafCert, issuerCert, url))
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
        when(ocspClient.lookup(cert, issuerCert, OCSP_URL))
                .thenReturn(RevocationLookup.inconclusive(new RevocationStatus.Malformed("OCSP")));
        when(crlClient.lookup(cert, issuerCert, CRL_URL)).thenReturn(crlGood());

        RevocationStatus status = revocationService.check(cert, issuerCert);

        RevocationStatus.Good good = assertInstanceOf(RevocationStatus.Good.class, status);
        assertEquals("CRL", good.source());
    }

    @Test
    void testCheck_TudoInconclusivoComNoConnectivity_DeveRetornarNoConnectivity() {
        X509Certificate cert = generateCertComOcspECrl();
        when(ocspClient.lookup(cert, issuerCert, OCSP_URL))
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
