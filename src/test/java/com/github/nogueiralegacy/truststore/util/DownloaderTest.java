package com.github.nogueiralegacy.truststore.util;

import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
public class DownloaderTest {
    @Autowired
    Downloader downloader;

    @Autowired
    TrustStoreConfig trustStoreConfig;

    @SneakyThrows
    @Test
    void testDownlaodBytes() {
        byte[] bytes = downloader.downloadBytes(trustStoreConfig.getCertificateUrl());

        assertTrue(bytes.length > 0);
        assertNotNull(bytes);
    }

    @SneakyThrows
    @Test
    void testDownloadText() {
        String text = downloader.downloadText(trustStoreConfig.getHashUrl());

        assertNotNull(text);
        String[] parts = text.split("  ");
        assertEquals("ACcompactado.zip", parts[1].trim());
    }
}
