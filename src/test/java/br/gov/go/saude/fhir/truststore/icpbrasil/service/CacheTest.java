package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.fhir.truststore.icpbrasil.util.Downloader;
import br.gov.go.saude.fhir.truststore.icpbrasil.util.Util;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.cert.X509Certificate;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@Slf4j
@SpringBootTest
class CacheTest {
    @Autowired
    TrustStoreConfig trustStoreConfig;

    @MockitoBean
    Downloader downloader;

    @Autowired
    Util util;

    @Autowired
    TrustStoreRepository trustStoreRepository;

    X509Certificate testCertificate;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        // Configurar o mock do downloader para retornar os recursos locais
        byte[] zipBytes = util.getResource("ACcompactado.zip").readAllBytes();
        String hashContent = new String(util.getResource("hashsha512.txt").readAllBytes());

        when(downloader.downloadBytes(trustStoreConfig.getCertificateUrl())).thenReturn(zipBytes);
        when(downloader.downloadText(trustStoreConfig.getHashUrl())).thenReturn(hashContent);

        var icpBrasilCertificateProvider = new IcpBrasilCertificateProvider(
                trustStoreConfig,
                downloader,
                trustStoreRepository
        );
        Cache.setCacheValid(true);
        Cache.refreshCache(icpBrasilCertificateProvider.getCertificates());

        testCertificate = CertificateParser.parse(util.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testGetCertificateBySki() {
        String testSki = CertificateParser.getSubjectKeyIdentifier(testCertificate);

        assertEquals(testCertificate, Cache.getCertificateBySki(testSki));
    }

    @Test
    void testGetAllCertificates() {
        Map<String, X509Certificate> all = Cache.getAllCertificates();

        assertFalse(all.isEmpty());

        String testSki = CertificateParser.getSubjectKeyIdentifier(testCertificate);
        assertEquals(testCertificate, all.get(testSki));
    }

    @Test
    void testGetRootCertificates() {
        Map<String, X509Certificate> roots = Cache.getRootCertificates();

        assertFalse(roots.isEmpty());
        // Quantidade de roots atualmente
        assertEquals(5, roots.size());

        roots.values().forEach(cert -> {
            assertEquals(cert.getSubjectX500Principal(), cert.getIssuerX500Principal());
            assertDoesNotThrow(() -> cert.verify(cert.getPublicKey()));
        });
    }

    @Test
    void testGetRootCertificatesNaoContemIntermediarios() {
        Map<String, X509Certificate> roots = Cache.getRootCertificates();
        String testSki = CertificateParser.getSubjectKeyIdentifier(testCertificate);

        assertNotEquals(
                testCertificate.getSubjectX500Principal(),
                testCertificate.getIssuerX500Principal()
        );
        assertFalse(roots.containsKey(testSki));
    }

    @Test
    void testGetAllCertificatesRetornaCopiaDefensiva() {
        Map<String, X509Certificate> all = Cache.getAllCertificates();
        int originalSize = all.size();

        all.clear();

        assertEquals(originalSize, Cache.getAllCertificates().size());
    }

}
