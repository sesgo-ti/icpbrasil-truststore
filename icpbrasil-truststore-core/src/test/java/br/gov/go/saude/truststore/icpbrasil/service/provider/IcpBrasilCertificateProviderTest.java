package br.gov.go.saude.truststore.icpbrasil.service.provider;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Slf4j
public class IcpBrasilCertificateProviderTest {

    private IcpBrasilCertificateProvider icpBrasilCertificateProvider;
    private TrustStoreConfig trustStoreConfig;
    private Downloader downloader;
    private TrustStoreRepository trustStoreRepository;
    private X509Certificate testCertificate;

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

        icpBrasilCertificateProvider = new IcpBrasilCertificateProvider(
                trustStoreConfig,
                downloader,
                trustStoreRepository
        );

        testCertificate = CertificateParser.parse(TestResourceLoader.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testGetCertificates() {
        List<X509Certificate> certificates = icpBrasilCertificateProvider.getCertificates();

        assertFalse(certificates.isEmpty());
        assertTrue(certificates.contains(testCertificate));
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
        filesystem.setBaseDir("target/test-provider-data");
        config.setFilesystem(filesystem);

        return config;
    }
}
