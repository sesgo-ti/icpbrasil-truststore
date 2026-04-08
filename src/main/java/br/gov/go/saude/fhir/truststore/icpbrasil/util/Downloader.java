package br.gov.go.saude.fhir.truststore.icpbrasil.util;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.TrustStoreManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Serviço responsável por downloads HTTP/HTTPS seguros do bundle ICP-Brasil.
 * Utiliza SSLContext customizado via {@link TrustStoreManager} e retry via {@link RetryPolicy}.
 */
@Slf4j
@Component
public class Downloader {

    private final TrustStoreManager trustStoreManager;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.NetworkConfig networkConfig;

    public Downloader(TrustStoreManager trustStoreManager, RetryPolicy retryPolicy,
                      TrustStoreConfig trustStoreConfig) {
        this.trustStoreManager = trustStoreManager;
        this.retryPolicy = retryPolicy;
        this.networkConfig = trustStoreConfig.getNetwork();
    }

    /**
     * Faz download de dados binários com retry automático.
     *
     * @param url URL para download (deve ser HTTPS)
     * @return Array de bytes com os dados baixados
     * @throws IOException se o download falhar após todas as tentativas
     */
    public byte[] downloadBytes(String url) throws IOException {
        log.debug("Iniciando download: {}", url);

        try {
            return retryPolicy.executeWithRetry(
                    url,
                    networkConfig.getMaxRetries() - 1,
                    networkConfig.getRetryIntervalMillis(),
                    () -> performDownload(url));
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Download falhou após " + networkConfig.getMaxRetries()
                    + " tentativas: " + url, e);
        }
    }

    /**
     * Faz download de texto.
     *
     * @param url URL para download
     * @return String com o conteúdo baixado
     * @throws IOException se o download falhar
     */
    public String downloadText(String url) throws IOException {
        byte[] data = downloadBytes(url);
        return new String(data, StandardCharsets.UTF_8);
    }

    private byte[] performDownload(String url) throws IOException {
        HttpURLConnection connection = null;
        try {
            connection = createConnection(url);

            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Falha no download: HTTP " + responseCode
                        + " para URL: " + url);
            }

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
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private HttpURLConnection createConnection(String url) throws IOException {
        URL targetUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();

        connection.setConnectTimeout(networkConfig.getDownloadTimeoutMillis());
        connection.setReadTimeout(networkConfig.getDownloadTimeoutMillis());
        connection.setRequestMethod("GET");
        connection.setInstanceFollowRedirects(true);
        connection.setRequestProperty("User-Agent", "TrustStore-Downloader/1.0");
        connection.setRequestProperty("Accept", "*/*");
        connection.setRequestProperty("Connection", "close");

        if (connection instanceof HttpsURLConnection httpsConnection) {
            httpsConnection.setSSLSocketFactory(trustStoreManager.getSslContext().getSocketFactory());
        } else {
            throw new IOException("URL deve usar HTTPS: " + url);
        }

        return connection;
    }
}
