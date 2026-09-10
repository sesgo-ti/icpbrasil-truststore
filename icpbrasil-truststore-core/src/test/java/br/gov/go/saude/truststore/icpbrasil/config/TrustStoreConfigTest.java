package br.gov.go.saude.truststore.icpbrasil.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Os defaults do POJO são o contrato da configuração mínima da biblioteca: com apenas o
 * diretório base informado, a validação precisa passar e os valores documentados valer.
 */
class TrustStoreConfigTest {

    @Test
    void testValidateProperties_ApenasBaseDirInformado_PassaComDefaults() {
        TrustStoreConfig config = new TrustStoreConfig();
        config.getFilesystem().setBaseDir("target/test-config");

        assertDoesNotThrow(config::validateProperties);

        assertEquals(IcpBrasilEndpoints.BUNDLE_ZIP_URL, config.getCertificateUrl());
        assertEquals(IcpBrasilEndpoints.BUNDLE_HASH_URL, config.getHashUrl());
        assertTrue(IcpBrasilEndpoints.BUNDLE_ZIP_URL.startsWith("https://acraiz.icpbrasil.gov.br/"));
        assertEquals("filesystem", config.getStorage().getType());
        assertEquals("ACcompactado.zip", config.getStorage().getTruststoreArchivePath());
        assertEquals("hash.txt", config.getStorage().getHashFilePath());
        assertEquals("ultima_confirmacao.txt", config.getStorage().getConfirmationFilePath());
        assertEquals("classpath:registries/certificates", config.getTrustedCerts().getDir());
        assertEquals(2, config.getRefreshIntervalHours());
        assertEquals(72, config.getCacheTtlCriticalHours());
        assertEquals(168, config.getCacheTtlMaxHours());
        assertEquals(60, config.getNetwork().getDownloadTimeoutSeconds());
        assertEquals(3, config.getNetwork().getMaxRetries());
        assertEquals(30, config.getNetwork().getRetryIntervalSeconds());
    }

    @Test
    void testValidateProperties_SemBaseDir_FalhaApontandoPropriedade() {
        TrustStoreConfig config = new TrustStoreConfig();

        IllegalStateException erro = assertThrows(IllegalStateException.class, config::validateProperties);

        assertTrue(erro.getMessage().contains("icpbrasil-truststore.filesystem.base-dir"));
    }

    @Test
    void testValidateProperties_DefaultSobrescritoComValorInvalido_Falha() {
        TrustStoreConfig config = new TrustStoreConfig();
        config.getFilesystem().setBaseDir("target/test-config");
        config.setRefreshIntervalHours(0);

        IllegalStateException erro = assertThrows(IllegalStateException.class, config::validateProperties);

        assertTrue(erro.getMessage().contains("icpbrasil-truststore.refresh-interval-hours"));
    }
}
