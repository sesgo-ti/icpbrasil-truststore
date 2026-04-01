package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.fhir.truststore.icpbrasil.util.Util;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@SpringBootTest
class RevocationServiceTest {

    @Autowired
    RevocationService revocationService;

    @Autowired
    RevocationCache revocationCache;

    @Autowired
    TrustStoreConfig trustStoreConfig;

    @Autowired
    Util util;

    X509Certificate leafCert;
    X509Certificate issuerCert;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        leafCert = CertificateParser.parse(util.getResource("DANIEL_NOGUEIRA_DA_COSTA-02057377148.cer"));
        issuerCert = CertificateParser.parse(util.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testExtractOcspUrl_CertificadoSemOcsp_DeveRetornarNull() {
        // O certificado DANIEL não possui OCSP na extensão AIA
        String ocspUrl = revocationService.extractOcspUrl(leafCert);

        assertNull(ocspUrl);
    }

    @Test
    void testExtractCrlUrls_CertificadoComCrl_DeveRetornarUrls() {
        List<String> crlUrls = revocationService.extractCrlUrls(leafCert);

        assertNotNull(crlUrls);
        assertEquals(2, crlUrls.size());
        assertTrue(crlUrls.get(0).contains("acsoluti.com.br"));
        assertTrue(crlUrls.get(1).contains("acsoluti.com.br"));
    }

    @Test
    void testExtractCrlUrls_CertificadoIntermediario_DeveRetornarUrls() {
        List<String> crlUrls = revocationService.extractCrlUrls(issuerCert);

        assertNotNull(crlUrls);
        assertFalse(crlUrls.isEmpty());
    }

    @Test
    void testCheck_ComCrlNoCache_DeveRetornarGood() throws Exception {
        // Given - baixa a CRL real e coloca no cache antes de chamar check
        List<String> crlUrls = revocationService.extractCrlUrls(leafCert);
        assertFalse(crlUrls.isEmpty());

        String crlUrl = crlUrls.get(0);
        byte[] crlBytes = downloadCrl(crlUrl);
        revocationCache.putCrl(crlUrl, crlBytes, 3600);

        // When
        RevocationStatus status = revocationService.check(leafCert, issuerCert);

        // Then
        assertInstanceOf(RevocationStatus.Good.class, status);
        RevocationStatus.Good good = (RevocationStatus.Good) status;
        assertEquals("CRL", good.source());
    }

    @Test
    void testCheck_CertificadoSemDistributionPoints_DeveRetornarNoDistributionPoints() throws Exception {
        // Given - certificado auto-assinado sem AIA e sem CRL DP
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();

        org.bouncycastle.x509.X509V3CertificateGenerator certGen = new org.bouncycastle.x509.X509V3CertificateGenerator();
        certGen.setSerialNumber(java.math.BigInteger.valueOf(1));
        certGen.setIssuerDN(new javax.security.auth.x500.X500Principal("CN=Test Root"));
        certGen.setNotBefore(new java.util.Date(System.currentTimeMillis() - 86400000L));
        certGen.setNotAfter(new java.util.Date(System.currentTimeMillis() + 86400000L));
        certGen.setSubjectDN(new javax.security.auth.x500.X500Principal("CN=Test Root"));
        certGen.setPublicKey(kp.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSA");

        @SuppressWarnings("deprecation")
        X509Certificate selfSigned = certGen.generate(kp.getPrivate());

        // When
        RevocationStatus status = revocationService.check(selfSigned, selfSigned);

        // Then
        assertInstanceOf(RevocationStatus.NoDistributionPoints.class, status);
    }

    @Test
    void testRevocationConfig_DeveEstarConfigurada() {
        TrustStoreConfig.RevocationConfig config = trustStoreConfig.getRevocation();

        assertNotNull(config);
        assertEquals(10, config.getOcspTimeoutSeconds());
        assertEquals(10, config.getCrlTimeoutSeconds());
        assertEquals(2, config.getMaxRetries());
        assertEquals(3, config.getRetryIntervalSeconds());
        assertEquals(3600, config.getOcspCacheTtlSeconds());
        assertEquals(3600, config.getCrlCacheTtlSeconds());
    }

    private byte[] downloadCrl(String url) throws Exception {
        java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                .followRedirects(java.net.http.HttpClient.Redirect.NORMAL)
                .build();
        java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .timeout(java.time.Duration.ofSeconds(30))
                .GET()
                .build();
        java.net.http.HttpResponse<byte[]> response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Falha ao baixar CRL: HTTP " + response.statusCode());
        }
        return response.body();
    }
}
