package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FilesystemCertificateProviderTest {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    @Test
    void getCertificates_comClasspath_deveRetornarCertificados() {
        // Given - usa o classpath com o ISRG Root X1
        TrustStoreConfig config = createConfig("classpath:registries/certificates");
        FilesystemCertificateProvider provider = new FilesystemCertificateProvider(config);
        provider.validate();

        // When
        List<X509Certificate> certificates = provider.getCertificates();

        // Then
        assertNotNull(certificates);
        assertFalse(certificates.isEmpty());

        X509Certificate cert = certificates.get(0);
        assertTrue(cert.getSubjectX500Principal().getName().contains("ISRG Root X1"));
    }

    @Test
    void getCertificates_comFilesystem_deveRetornarCertificados() {
        // Given - usa o diretório filesystem de teste
        TrustStoreConfig config = createConfig("src/test/resources/registries/certificates");
        FilesystemCertificateProvider provider = new FilesystemCertificateProvider(config);
        provider.validate();

        // When
        List<X509Certificate> certificates = provider.getCertificates();

        // Then
        assertNotNull(certificates);
        assertFalse(certificates.isEmpty());
        assertEquals(3, certificates.size());
    }

    @Test
    void getCertificates_comDiretorioVazio_deveRetornarListaVazia(@TempDir Path tempDir) {
        // Given
        TrustStoreConfig config = createConfig(tempDir.toString());
        FilesystemCertificateProvider provider = new FilesystemCertificateProvider(config);
        provider.validate();

        // When
        List<X509Certificate> certificates = provider.getCertificates();

        // Then
        assertNotNull(certificates);
        assertTrue(certificates.isEmpty());
    }

    @Test
    void validate_comDiretorioInexistente_deveLancarExcecao() {
        // Given
        TrustStoreConfig config = createConfig("/caminho/que/nao/existe");
        FilesystemCertificateProvider provider = new FilesystemCertificateProvider(config);

        // When & Then
        assertThrows(IllegalStateException.class, provider::validate);
    }

    @Test
    void getCertificates_comJsonInvalido_deveLancarExcecao(@TempDir Path tempDir) throws Exception {
        // Given
        Files.writeString(tempDir.resolve("invalid.json"), "{ json invalido }");
        TrustStoreConfig config = createConfig(tempDir.toString());
        FilesystemCertificateProvider provider = new FilesystemCertificateProvider(config);
        provider.validate();

        // When & Then
        assertThrows(RuntimeException.class, provider::getCertificates);
    }

    private TrustStoreConfig createConfig(String dir) {
        TrustStoreConfig config = new TrustStoreConfig();
        TrustStoreConfig.TrustedCertsConfig trustedCerts = new TrustStoreConfig.TrustedCertsConfig();
        trustedCerts.setDir(dir);
        config.setTrustedCerts(trustedCerts);
        return config;
    }
}
