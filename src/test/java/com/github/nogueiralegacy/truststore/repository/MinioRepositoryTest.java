package com.github.nogueiralegacy.truststore.repository;

import com.github.nogueiralegacy.truststore.util.Util;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@SpringBootTest
@ActiveProfiles("test")
public class MinioRepositoryTest {
    @MockitoBean
    TrustStoreRepository trustStoreRepository;

    @Autowired
    Util util;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        InputStream zipInputStream = util.getResource("ACcompactado.zip");
        InputStream hashInputStream = util.getResource("hashsha512.txt");
        InputStream ultimaConfirmacaoInputStream = util.getResource("ultima_confirmacao.txt");

        String hashContent = new String(hashInputStream.readAllBytes(), StandardCharsets.UTF_8);
        String ultimaConfirmacaoString = new String(
                ultimaConfirmacaoInputStream.readAllBytes(),
                StandardCharsets.UTF_8
        );

        when(trustStoreRepository.recuperarZip())
                .thenReturn(zipInputStream);
        when(trustStoreRepository.recuperarHash())
                .thenReturn(hashContent.split("  ")[0].trim());
        when(trustStoreRepository.recuperarUltimaConfirmacao())
                .thenReturn(Instant.parse(ultimaConfirmacaoString));
    }


    @Test
    void testRecuperarZip() {
        try (InputStream is = trustStoreRepository.recuperarZip()) {
            assert is != null;
            byte[] bytes = is.readAllBytes();
            assert bytes.length > 0;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void testRecuperarHash() {
        String hash = trustStoreRepository.recuperarHash();

        assertEquals("bbc9703e33df4be5b23e900177a3672191ca2f9c5dc68eaf129562ea43f90b89a6525b61b427212dce0b8026ec26ef2ca06ffe491ab911d0bac9722faefdfde2", hash);
    }

    @Test
    void testRecuperarUltimaConfirmacao() {
        Instant ultimaConfirmacao = trustStoreRepository.recuperarUltimaConfirmacao();

        assertEquals(Instant.parse("2025-10-08T02:10:54.784822Z"), ultimaConfirmacao);
    }
}
