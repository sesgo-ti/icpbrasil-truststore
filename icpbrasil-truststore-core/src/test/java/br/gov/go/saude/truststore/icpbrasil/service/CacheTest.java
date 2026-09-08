package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Slf4j
class CacheTest {

    Cache cache;
    TrustStoreConfig trustStoreConfig;
    Downloader downloader;
    TrustStoreRepository trustStoreRepository;
    X509Certificate testCertificate;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        trustStoreConfig = buildTrustStoreConfig();
        trustStoreRepository = new FilesystemTrustStoreRepository(trustStoreConfig);
        downloader = mock(Downloader.class);

        byte[] zipBytes = TestResourceLoader.getResource("ACcompactado.zip").readAllBytes();
        String hashContent = new String(TestResourceLoader.getResource("hashsha512.txt").readAllBytes());

        when(downloader.downloadBytes(trustStoreConfig.getCertificateUrl())).thenReturn(zipBytes);
        when(downloader.downloadText(trustStoreConfig.getHashUrl())).thenReturn(hashContent);

        var icpBrasilCertificateProvider = new IcpBrasilCertificateProvider(
                trustStoreConfig,
                downloader,
                trustStoreRepository
        );
        // Instância isolada por teste — escrita acessível por estar no mesmo pacote do pipeline
        cache = new Cache();
        cache.publish(icpBrasilCertificateProvider.parseSnapshot(zipBytes, hashContent.strip().split("\\s+")[0]),
                Instant.now(), 3600000, cache.version(), () -> {});

        testCertificate = CertificateParser.parse(TestResourceLoader.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testGetCertificateBySki() {
        String testSki = CertificateParser.getSubjectKeyIdentifier(testCertificate);

        assertEquals(testCertificate, cache.getCertificateBySki(testSki));
    }

    @Test
    void testGetAllCertificates() {
        Map<String, X509Certificate> all = cache.getAllCertificates();

        assertFalse(all.isEmpty());

        String testSki = CertificateParser.getSubjectKeyIdentifier(testCertificate);
        assertEquals(testCertificate, all.get(testSki));
    }

    @Test
    void testGetRootCertificates() {
        Map<String, X509Certificate> roots = cache.getRootCertificates();

        assertFalse(roots.isEmpty());
        assertEquals(5, roots.size());

        roots.values().forEach(cert -> {
            assertEquals(cert.getSubjectX500Principal(), cert.getIssuerX500Principal());
            assertDoesNotThrow(() -> cert.verify(cert.getPublicKey()));
        });
    }

    @Test
    void testGetRootCertificatesNaoContemIntermediarios() {
        Map<String, X509Certificate> roots = cache.getRootCertificates();
        String testSki = CertificateParser.getSubjectKeyIdentifier(testCertificate);

        assertNotEquals(
                testCertificate.getSubjectX500Principal(),
                testCertificate.getIssuerX500Principal()
        );
        assertFalse(roots.containsKey(testSki));
    }

    @Test
    void testGetAllCertificatesRetornaCopiaDefensiva() {
        Map<String, X509Certificate> all = cache.getAllCertificates();
        int originalSize = all.size();

        all.clear();

        assertEquals(originalSize, cache.getAllCertificates().size());
    }

    private TrustStoreConfig buildTrustStoreConfig() {
        TrustStoreConfig config = new TrustStoreConfig();
        config.setCertificateUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip");
        config.setHashUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt");

        TrustStoreConfig.NetworkConfig network = new TrustStoreConfig.NetworkConfig();
        network.setDownloadTimeoutSeconds(30);
        network.setMaxRetries(3);
        network.setRetryIntervalSeconds(30);
        config.setNetwork(network);

        TrustStoreConfig.StorageConfig storage = new TrustStoreConfig.StorageConfig();
        storage.setType("filesystem");
        storage.setTruststoreArchivePath("ACcompactado.zip");
        storage.setHashFilePath("hash.txt");
        storage.setConfirmationFilePath("ultima_confirmacao.txt");
        config.setStorage(storage);

        TrustStoreConfig.FilesystemConfig filesystem = new TrustStoreConfig.FilesystemConfig();
        filesystem.setBaseDir("target/test-cache-data");
        config.setFilesystem(filesystem);

        return config;
    }
}
