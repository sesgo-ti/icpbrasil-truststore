package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@Slf4j
class RevocationServiceTest {

    private OcspClient ocspClient;
    private CrlClient crlClient;
    private RevocationService revocationService;

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
        var caKeyPair = kpg.generateKeyPair();
        var leafKeyPair = kpg.generateKeyPair();
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
            when(ocspClient.check(leafCert, issuerCert, url))
                    .thenReturn(new RevocationStatus.OcspUnavailable());
        }
        when(crlClient.check(leafCert, issuerCert, crlUrls.get(0)))
                .thenReturn(new RevocationStatus.Good("CRL", null));

        // When
        RevocationStatus status = revocationService.check(leafCert, issuerCert);

        // Then
        assertInstanceOf(RevocationStatus.Good.class, status);
        RevocationStatus.Good good = (RevocationStatus.Good) status;
        assertEquals("CRL", good.source());
    }

    @Test
    void testCheckMalformedNaoViraIndisponibilidade() {
        List<String> urls = CertificateParser.getCrlUrls(leafCert);
        when(crlClient.check(leafCert, issuerCert, urls.get(0)))
                .thenReturn(new RevocationStatus.Malformed("CRL"));
        when(crlClient.check(leafCert, issuerCert, urls.get(1)))
                .thenReturn(new RevocationStatus.CrlUnavailable());

        assertEquals(new RevocationStatus.Malformed("CRL"), revocationService.check(leafCert, issuerCert));
    }

    @Test
    void testCheckMalformedPermiteProximaEvidenciaConclusiva() {
        List<String> urls = CertificateParser.getCrlUrls(leafCert);
        when(crlClient.check(leafCert, issuerCert, urls.get(0)))
                .thenReturn(new RevocationStatus.Malformed("CRL"));
        when(crlClient.check(leafCert, issuerCert, urls.get(1)))
                .thenReturn(new RevocationStatus.Revoked("CRL"));

        assertEquals(new RevocationStatus.Revoked("CRL"), revocationService.check(leafCert, issuerCert));
    }

    @Test
    void testCheckPreservaNoConnectivitySemFlagDeInterrupcao() {
        List<String> urls = CertificateParser.getCrlUrls(leafCert);
        when(crlClient.check(leafCert, issuerCert, urls.get(0)))
                .thenReturn(new RevocationStatus.NoConnectivity());
        when(crlClient.check(leafCert, issuerCert, urls.get(1)))
                .thenReturn(new RevocationStatus.Malformed("CRL"));

        assertInstanceOf(RevocationStatus.NoConnectivity.class, revocationService.check(leafCert, issuerCert));
        verify(crlClient).check(leafCert, issuerCert, urls.get(1));
    }

    @Test
    void testCheckInterrupcaoEncerraLoopCrl() {
        List<String> urls = CertificateParser.getCrlUrls(leafCert);
        when(crlClient.check(leafCert, issuerCert, urls.get(0))).thenAnswer(invocation -> {
            Thread.currentThread().interrupt();
            return new RevocationStatus.NoConnectivity();
        });
        try {
            assertInstanceOf(RevocationStatus.NoConnectivity.class, revocationService.check(leafCert, issuerCert));
            assertTrue(Thread.currentThread().isInterrupted());
            verify(crlClient, never()).check(leafCert, issuerCert, urls.get(1));
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void testCheckThreadJaInterrompidaNaoConsultaClientes() {
        Thread.currentThread().interrupt();
        try {
            assertInstanceOf(RevocationStatus.NoConnectivity.class, revocationService.check(leafCert, issuerCert));
            assertTrue(Thread.currentThread().isInterrupted());
            verifyNoInteractions(ocspClient, crlClient);
        } finally {
            Thread.interrupted();
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
}
