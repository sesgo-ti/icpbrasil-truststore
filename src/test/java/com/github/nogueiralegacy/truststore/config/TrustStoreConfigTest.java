package com.github.nogueiralegacy.truststore.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.yaml")
class TrustStoreConfigTest {

    // Válid
    @Autowired
    private TrustStoreConfig trustStoreConfig;


    private TrustStoreConfig testTrustStoreConfig;

    @BeforeEach
    void setUp() {
        // Valid
        testTrustStoreConfig = new TrustStoreConfig();
        testTrustStoreConfig.setCertificateUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip");
        testTrustStoreConfig.setHashUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt");

        TrustStoreConfig.NetworkConfig networkConfig = new TrustStoreConfig.NetworkConfig();
        networkConfig.setDownloadTimeoutSeconds(30);
        networkConfig.setMaxRetries(5);
        networkConfig.setRetryIntervalSeconds(10);

        testTrustStoreConfig.setNetwork(networkConfig);

        testTrustStoreConfig.setCacheTtlHours(24);
        testTrustStoreConfig.setRefreshIntervalHours(1);
    }

    @Test
    void testValidateProperties_ComConfiguracoesValidas_DevePassar() {
        // When & Then - não deve lançar exceção
        assertDoesNotThrow(() -> trustStoreConfig.validateProperties());
    }

    @Test
    void testValidateUrls_ComCertificateUrlVazia_DeveLancarExcecao() {
        // Given
        TrustStoreConfig invalidConfig = new TrustStoreConfig();
        invalidConfig.setCertificateUrl("");
        invalidConfig.setHashUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt");

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                invalidConfig::validateProperties);

        assertTrue(exception.getMessage().contains("URL do certificado ICP-Brasil não pode ser null ou vazia"));
    }

    @Test
    void testValidateUrls_ComHashUrlVazia_DeveLancarExcecao() {
        // Given
        TrustStoreConfig invalidConfig = new TrustStoreConfig();
        invalidConfig.setCertificateUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip");
        invalidConfig.setHashUrl("");

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                invalidConfig::validateProperties);

        assertTrue(exception.getMessage().contains("URL do hash do certificado ICP-Brasil não pode ser null ou vazia"));
    }

    @Test
    void testValidateUrls_ComProtocoloHTTP_DeveLancarExcecao() {
        // Given
        TrustStoreConfig invalidConfig = new TrustStoreConfig();
        invalidConfig.setCertificateUrl("http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip");
        invalidConfig.setHashUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt");

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                invalidConfig::validateProperties);

        assertTrue(exception.getMessage().contains("deve usar protocolo HTTPS por segurança"));
    }

    @Test
    void testValidateUrls_ComURLMalformada_DeveLancarExcecao() {
        // Given
        TrustStoreConfig invalidConfig = new TrustStoreConfig();
        invalidConfig.setCertificateUrl("url-invalida");
        invalidConfig.setHashUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt");

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                invalidConfig::validateProperties);

        assertTrue(exception.getMessage().contains("é inválida"));
    }

    @Test
    void testValidateNetworkConfig_ComTimeoutInvalido_DeveLancarExcecao() {
        // Given
        TrustStoreConfig invalidConfig = new TrustStoreConfig();
        invalidConfig.setCertificateUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip");
        invalidConfig.setHashUrl("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt");
        
        TrustStoreConfig.NetworkConfig networkConfig = new TrustStoreConfig.NetworkConfig();
        networkConfig.setDownloadTimeoutSeconds(20); // Menor que 30
        invalidConfig.setNetwork(networkConfig);

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                invalidConfig::validateProperties);

        assertTrue(exception.getMessage().contains("Timeout de download deve estar entre 30 e 300 segundos"));
    }

    @Test
    void testValidateNetworkConfig_ComMaxRetriesInvalido_DeveLancarExcecao() {
        // Given
        // Valor inválido
        testTrustStoreConfig.getNetwork().setMaxRetries(15); // Maior do que 10

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                testTrustStoreConfig::validateProperties);

        assertTrue(exception.getMessage().contains("Número máximo de tentativas deve estar entre 1 e 10"));
    }

    @Test
    void testValidateNetworkConfig_ComRetryIntervalInvalido_DeveLancarExcecao() {
        // Given
        // Valor inválido
        testTrustStoreConfig.getNetwork().setRetryIntervalSeconds(5); // Menor que 10
        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                testTrustStoreConfig::validateProperties);

        assertTrue(exception.getMessage().contains("Intervalo entre tentativas deve estar entre 10 e 300 segundos"));
    }

    @Test
    void testValidateCacheConfig_ComCacheTtlInvalido_DeveLancarExcecao() {
        // Given
        // Valor inválido
        testTrustStoreConfig.setCacheTtlHours(200); // Maior que 168

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                testTrustStoreConfig::validateProperties);

        assertTrue(exception.getMessage().contains("TTL do cache deve estar entre 1 e 168 horas"));
    }

    @Test
    void testValidateCacheConfig_ComRefreshIntervalInvalido_DeveLancarExcecao() {
        // Given
        // Valor inválido
        testTrustStoreConfig.setRefreshIntervalHours(-1); // Valor negativo

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                testTrustStoreConfig::validateProperties);

        assertTrue(exception.getMessage().contains("Intervalo de refresh deve ser pelo menos 1 hora"));
    }

    @Test
    void testGetDownloadTimeoutMillis_DeveRetornarValorCorreto() {
        // When
        long timeoutMillis = trustStoreConfig.getNetwork().getDownloadTimeoutMillis();

        // Then
        assertEquals(60000L, timeoutMillis); // 60 segundos = 60000 milissegundos
    }

    @Test
    void testGetRetryIntervalMillis_DeveRetornarValorCorreto() {
        // When
        long retryIntervalMillis = trustStoreConfig.getNetwork().getRetryIntervalMillis();

        // Then
        assertEquals(30000L, retryIntervalMillis); // 30 segundos = 30000 milissegundos
    }

    @Test
    void testGetCacheTtlMillis_DeveRetornarValorCorreto() {
        // When
        long cacheTtlMillis = trustStoreConfig.getCacheTtlMillis();

        // Then
        assertEquals(86400000L, cacheTtlMillis); // 24 horas = 86400000 milissegundos
    }

    @Test
    void testGetRefreshIntervalMillis_DeveRetornarValorCorreto() {
        // When
        long refreshIntervalMillis = trustStoreConfig.getRefreshIntervalMillis();

        // Then
        assertEquals(7200000L, refreshIntervalMillis); // 2 horas = 7200000 milissegundos
    }

    @Test
    void testTrustStoreConfig_DeveCarregarPropriedadesDoArquivoTeste() {
        // When & Then
        assertNotNull(trustStoreConfig.getCertificateUrl());
        assertNotNull(trustStoreConfig.getHashUrl());
        assertNotNull(trustStoreConfig.getNetwork());
        
        assertEquals("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip", 
                    trustStoreConfig.getCertificateUrl());
        assertEquals("https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt", 
                    trustStoreConfig.getHashUrl());
        assertEquals(60, trustStoreConfig.getNetwork().getDownloadTimeoutSeconds());
        assertEquals(3, trustStoreConfig.getNetwork().getMaxRetries());
        assertEquals(30, trustStoreConfig.getNetwork().getRetryIntervalSeconds());
        assertEquals(24, trustStoreConfig.getCacheTtlHours());
        assertEquals(2, trustStoreConfig.getRefreshIntervalHours());
    }
}