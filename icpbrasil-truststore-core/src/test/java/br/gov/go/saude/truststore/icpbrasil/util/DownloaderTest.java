package br.gov.go.saude.truststore.icpbrasil.util;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.TrustStoreManager;
import br.gov.go.saude.truststore.icpbrasil.service.provider.TrustedCertsProvider;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Teste de integração: depende de conectividade real com o site do ITI
 * (acraiz.icpbrasil.gov.br). Excluído da execução padrão do build; para
 * executá-lo use o perfil {@code integration-tests}:
 * {@code ./mvnw verify -Pintegration-tests}.
 */
@Tag("integration")
class DownloaderTest {

    private static final Path PRODUCTION_REGISTRY = Path.of("src/main/resources/registries/certificates");

    private Downloader downloader;
    private TrustStoreConfig trustStoreConfig;

    @BeforeEach
    void setUp() {
        trustStoreConfig = buildTrustStoreConfig();

        // Registro de produção: o teste deve falhar se ele deixar de cobrir o TLS atual do ITI
        List<byte[]> docs;
        try (Stream<Path> files = Files.list(PRODUCTION_REGISTRY)) {
            docs = files.filter(file -> file.toString().endsWith(".json"))
                    .sorted()
                    .map(file -> {
                        try {
                            return Files.readAllBytes(file);
                        } catch (IOException e) {
                            throw new UncheckedIOException("Erro ao ler registro: " + file, e);
                        }
                    })
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("Erro ao listar registro: " + PRODUCTION_REGISTRY, e);
        }

        TrustedCertsProvider trustedCertsProvider = new TrustedCertsProvider(docs);
        TrustStoreManager trustStoreManager = new TrustStoreManager(trustedCertsProvider);
        RetryPolicy retryPolicy = new RetryPolicy(trustStoreConfig);
        downloader = new Downloader(
                Downloader.transporteAcervoIti(trustStoreManager.getSslContext(), trustStoreConfig),
                retryPolicy, trustStoreConfig);
    }

    @SneakyThrows
    @Test
    void testDownloadBytesRetornaConteudoNaoVazio() {
        byte[] bytes = downloader.downloadBytes(trustStoreConfig.getCertificateUrl());

        assertTrue(bytes.length > 0);
        assertNotNull(bytes);
    }

    @SneakyThrows
    @Test
    void testDownloadTextExtraiHash() {
        String text = downloader.downloadText(trustStoreConfig.getHashUrl());

        assertNotNull(text);
        String[] parts = text.split("  ");
        assertEquals("ACcompactado.zip", parts[1].trim());
    }

    private TrustStoreConfig buildTrustStoreConfig() {
        TrustStoreConfig config = new TrustStoreConfig();
        config.setCertificateUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip");
        config.setHashUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt");

        TrustStoreConfig.NetworkConfig network = new TrustStoreConfig.NetworkConfig();
        network.setDownloadTimeoutSeconds(60);
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
        filesystem.setBaseDir("target/test-downloader-data");
        config.setFilesystem(filesystem);

        return config;
    }
}
