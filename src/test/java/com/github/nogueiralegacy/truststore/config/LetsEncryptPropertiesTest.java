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
    void testLetsEncryptProperties_DeveCarregarTodasAsURLs() {
        // When
        String[] urls = letsEncryptProperties.getCertificateUrls();

        // Then
        assertNotNull(urls);
        assertEquals(2, urls.length);

        // Verificar se todas as URLs esperadas estão presentes
        assertTrue(containsUrl(urls, "https://letsencrypt.org/certs/2024/e6.pem"));
    }

    @Test
    void testGetCertificateUrl_DeveRetornarURLEspecifica() {
        // When & Then
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
        assertTrue(letsEncryptProperties.hasCertificate("lets-encrypt-e6"));
    }
    
    @Test
    void testHasCertificate_ComNomeInvalido_DeveRetornarFalse() {
        // When & Then
        assertFalse(letsEncryptProperties.hasCertificate(null));
        assertFalse(letsEncryptProperties.hasCertificate(""));
        assertFalse(letsEncryptProperties.hasCertificate("certificado-inexistente"));
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