package br.gov.go.saude.truststore.icpbrasil.util;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Teste de integração: depende de conectividade real com o site do ITI
 * (acraiz.icpbrasil.gov.br). Excluído da execução padrão do build; para
 * executá-lo use o perfil {@code integration-tests}:
 * {@code ./mvnw verify -Pintegration-tests}.
 */
@Tag("integration")
@SpringBootTest
class DownloaderTest {
    @Autowired
    Downloader downloader;

    @Autowired
    TrustStoreConfig trustStoreConfig;

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
}
