package com.github.nogueiralegacy.truststore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.yaml")
class TrustStoreTest {

    @Autowired
    private TrustStore trustStore;
    
    @TempDir
    Path tempDir;

    @Test
    void testDownloadCertificate_DownloadBemSucedido_DeveSalvarArquivo() throws Exception {
        // Given - usando uma URL real que retorna conteúdo pequeno
        String url = "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip";
        String dir = tempDir.toString();

        // When
        trustStore.downloadCertificate(url, dir);

        // Then
        Path arquivoSalvo = Paths.get(dir, "ACcompactado.zip");
        assertTrue(Files.exists(arquivoSalvo));
        
        // Verificar se o arquivo tem conteúdo (arquivo ZIP é binário)
        long tamanhoArquivo = Files.size(arquivoSalvo);
        assertTrue(tamanhoArquivo > 0, "O arquivo deve ter conteúdo");
    }

}