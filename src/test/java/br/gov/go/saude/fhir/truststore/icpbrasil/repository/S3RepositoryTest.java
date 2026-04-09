package br.gov.go.saude.fhir.truststore.icpbrasil.repository;

import br.gov.go.saude.fhir.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

import org.apache.commons.compress.utils.IOUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class S3RepositoryTest {

    TrustStoreRepository trustStoreRepository = mock(TrustStoreRepository.class);

    @SneakyThrows
    @BeforeEach
    void setUp() {
        byte[] zipBytes = IOUtils.toByteArray(TestResourceLoader.getResource("ACcompactado.zip"));
        String hashContent = new String(
                IOUtils.toByteArray(TestResourceLoader.getResource("hashsha512.txt")),
                StandardCharsets.UTF_8
        );
        String ultimaConfirmacaoString = new String(
                IOUtils.toByteArray(TestResourceLoader.getResource("ultima_confirmacao.txt")),
                StandardCharsets.UTF_8
        );

        when(trustStoreRepository.recuperarZip())
                .thenReturn(Optional.of(zipBytes));
        when(trustStoreRepository.recuperarHash())
                .thenReturn(Optional.of(hashContent.split("  ")[0].trim()));
        when(trustStoreRepository.recuperarUltimaConfirmacao())
                .thenReturn(Optional.of(Instant.parse(ultimaConfirmacaoString)));
    }


    @Test
    void testRecuperarZip() {
        byte[] bytes = trustStoreRepository.recuperarZip().orElseThrow();
        assert bytes.length > 0;
    }

    @Test
    void testRecuperarHash() {
        String hash = trustStoreRepository.recuperarHash().orElseThrow();

        assertEquals("bbc9703e33df4be5b23e900177a3672191ca2f9c5dc68eaf129562ea43f90b89a6525b61b427212dce0b8026ec26ef2ca06ffe491ab911d0bac9722faefdfde2", hash);
    }

    @Test
    void testRecuperarUltimaConfirmacao() {
        Instant ultimaConfirmacao = trustStoreRepository.recuperarUltimaConfirmacao().orElseThrow();

        assertEquals(Instant.parse("2025-10-08T02:10:54.784822Z"), ultimaConfirmacao);
    }
}
