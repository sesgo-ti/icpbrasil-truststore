package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
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

    X509Certificate leafCert;
    X509Certificate issuerCert;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        leafCert = CertificateParser.parse(TestResourceLoader.getResource("DANIEL_NOGUEIRA_DA_COSTA-02057377148.cer"));
        issuerCert = CertificateParser.parse(TestResourceLoader.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testCheck_ComCrlNoCache_DeveRetornarGood() throws Exception {
        // Given - baixa a CRL real e coloca no cache antes de chamar check
        List<String> crlUrls = CertificateParser.getCrlUrls(leafCert);
        assertFalse(crlUrls.isEmpty());

        String crlUrl = crlUrls.get(0);
        byte[] crlBytes = downloadCrl(crlUrl);
        revocationCache.putCrl(crlUrl, crlBytes);

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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
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
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Falha ao baixar CRL: HTTP " + response.statusCode());
        }
        return response.body();
    }
}
