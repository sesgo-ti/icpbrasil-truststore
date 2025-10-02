package com.github.nogueiralegacy.truststore.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
class LetsEncryptPropertiesTest {

    @Autowired
    private LetsEncryptProperties letsEncryptProperties;

    @Test
    void testValidateProperties_ComURLsVazias_DeveLancarExcecao() {
        // Given
        LetsEncryptProperties invalidProperties = new LetsEncryptProperties();
        
        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                invalidProperties::validateProperties);

        assertTrue(exception.getMessage().contains("Nenhuma URL de certificado Let's Encrypt foi configurada"));
    }

    @Test
    void testLetsEncryptProperties_DeveCarregarTodasAsURLs() {
        // When
        String[] urls = letsEncryptProperties.getCertificateUrls();

        // Then
        assertNotNull(urls);
        assertEquals(4, urls.length);

        // Verificar se todas as URLs esperadas estão presentes
        assertTrue(containsUrl(urls, "https://letsencrypt.org/certs/isrgrootx1.pem"));
        assertTrue(containsUrl(urls, "https://letsencrypt.org/certs/lets-encrypt-r3.pem"));
        assertTrue(containsUrl(urls, "https://letsencrypt.org/certs/2024/e5.pem"));
        assertTrue(containsUrl(urls, "https://letsencrypt.org/certs/2024/e6.pem"));
    }

    @Test
    void testGetCertificateUrl_DeveRetornarURLEspecifica() {
        // When & Then
        assertEquals("https://letsencrypt.org/certs/isrgrootx1.pem",
                    letsEncryptProperties.getCertificateUrl("isrg-root-x1"));
        assertEquals("https://letsencrypt.org/certs/lets-encrypt-r3.pem",
                    letsEncryptProperties.getCertificateUrl("lets-encrypt-r3"));
        assertEquals("https://letsencrypt.org/certs/2024/e5.pem",
                    letsEncryptProperties.getCertificateUrl("lets-encrypt-e5"));
        assertEquals("https://letsencrypt.org/certs/2024/e6.pem",
                    letsEncryptProperties.getCertificateUrl("lets-encrypt-e6"));
    }

    @Test
    void testGetCertificateUrl_ChaveInexistente_DeveRetornarNull() {
        // When & Then
        assertNull(letsEncryptProperties.getCertificateUrl("chave-inexistente"));
    }
    
    @Test
    void testGetCertificateUrl_ComNomeInvalido_DeveLancarExcecao() {
        // When & Then
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
            () -> letsEncryptProperties.getCertificateUrl(null));

        assertEquals("Nome do certificado não pode ser null ou vazio", exception.getMessage());

        // Teste com string vazia
        exception = assertThrows(IllegalArgumentException.class,
            () -> letsEncryptProperties.getCertificateUrl(""));
        
        assertEquals("Nome do certificado não pode ser null ou vazio", exception.getMessage());
    }

    @Test
    void testHasCertificate_ComNomeValido_DeveRetornarTrue() {
        // When & Then
        assertTrue(letsEncryptProperties.hasCertificate("isrg-root-x1"));
    }
    
    @Test
    void testHasCertificate_ComNomeInvalido_DeveRetornarFalse() {
        // When & Then
        assertFalse(letsEncryptProperties.hasCertificate(null));
        assertFalse(letsEncryptProperties.hasCertificate(""));
        assertFalse(letsEncryptProperties.hasCertificate("certificado-inexistente"));
    }
    
    @Test
    void testGetCertificateCount_DeveRetornarNumeroCorreto() {
        // When
        int count = letsEncryptProperties.getCertificateCount();
        
        // Then
        assertEquals(4, count);
    }

    private boolean containsUrl(String[] urls, String expectedUrl) {
        for (String url : urls) {
            if (expectedUrl.equals(url)) {
                return true;
            }
        }
        return false;
    }
}