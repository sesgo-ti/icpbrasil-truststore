package br.gov.go.saude.truststore.icpbrasil.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TrustStoreConfigTest {

    @Test
    void testDefaults_SemSpring_ValidosAntesDaValidacao() {
        TrustStoreConfig config = new TrustStoreConfig();
        assertEquals("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip",
                config.getCertificateUrl());
        assertEquals("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt",
                config.getHashUrl());
        assertEquals(60, config.getNetwork().getDownloadTimeoutSeconds());
        assertEquals(3, config.getNetwork().getMaxRetries());
        assertEquals(30, config.getNetwork().getRetryIntervalSeconds());
        assertEquals(2, config.getRefreshIntervalHours());
        assertEquals(72, config.getCacheTtlCriticalHours());
        assertEquals(168, config.getCacheTtlMaxHours());
        assertEquals("filesystem", config.getStorage().getType());
        assertEquals("ACcompactado.zip", config.getStorage().getTruststoreArchivePath());
        assertEquals("hash.txt", config.getStorage().getHashFilePath());
        assertEquals("ultima_confirmacao.txt", config.getStorage().getConfirmationFilePath());
        assertEquals(".data/icpbrasil-truststore", config.getFilesystem().getBaseDir());
        assertEquals("classpath:registries/certificates", config.getTrustedCerts().getDir());
        assertNotNull(config.getRevocation());
        assertNotNull(config.getChain());
        assertNotNull(config.getDownloadPolicy());
        assertTrue(config.getBootstrap().isEnabled());
        assertTrue(config.getBootstrap().isFailFast());
        assertDoesNotThrow(config::validateProperties);
    }
}
