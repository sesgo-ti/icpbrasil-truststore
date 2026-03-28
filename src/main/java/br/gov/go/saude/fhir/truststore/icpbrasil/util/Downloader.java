package br.gov.go.saude.fhir.truststore.icpbrasil.util;

import br.gov.go.saude.fhir.truststore.icpbrasil.http.HttpClientFactory;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.RetryPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;

/**
 * Serviço responsável por downloads HTTP/HTTPS seguros
 * Utiliza injeção de dependência para SSL Context e políticas de retry
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class Downloader {

    private final HttpClientFactory httpClientFactory;
    private final RetryPolicy retryPolicy;

    /**
     * Faz download de dados binários com retry automático
     *
     * @param url URL para download
     * @return Array de bytes com os dados baixados
     * @throws IOException se o download falhar após todas as tentativas
     */
    public byte[] downloadBytes(String url) throws IOException {
        log.debug("Iniciando download: {}", url);
        
        return retryPolicy.executeWithRetry(url, () -> {
            try {
                return performDownload(url);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Executa o download real dos bytes
     */
    private byte[] performDownload(String url) throws IOException {
        HttpURLConnection connection = null;
        try {
            connection = httpClientFactory.createConnection(url);
            
            // Verifica código de resposta antes de tentar ler
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Falha no download: HTTP " + responseCode + 
                                    " para URL: " + url);
            }
            
            // Usa try-with-resources para gerenciar streams automaticamente
            try (InputStream inputStream = connection.getInputStream();
                 ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                
                log.debug("Download concluído com sucesso: {} bytes baixados de {}", 
                         outputStream.size(), url);
                return outputStream.toByteArray();
            }
        } finally {
            // Garante que a conexão seja fechada
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Faz download de texto
     *
     * @param url URL para download
     * @return String com o conteúdo baixado
     * @throws IOException se o download falhar
     */
    public String downloadText(String url) throws IOException {
        byte[] data = downloadBytes(url);
        return new String(data, StandardCharsets.UTF_8);
    }
}
