package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Downloads HTTPS do bundle ICP-Brasil e do seu hash, publicados pelo ITI.
 *
 * <p>Usa o {@code SSLContext} dedicado de {@link TrustStoreManager} (confiança apenas nas CAs
 * embutidas) e retentativas de {@link RetryPolicy}. Cada tentativa segue um contrato fechado:
 * redirecionamentos não são seguidos, qualquer status diferente de 200 falha sem ler o corpo e
 * o corpo é limitado durante o recebimento ({@code MAX_BINARY_BYTES} ou {@code MAX_TEXT_BYTES}).
 * Como {@link HttpURLConnection} só oferece timeouts por operação, {@code download-timeout-seconds}
 * é aplicado também como prazo total da tentativa, conferido a cada leitura do corpo.</p>
 *
 * <p>Não aplica {@link DownloadPolicy}: o destino é o host administrativo configurado, não
 * uma URL extraída de certificado de terceiros.</p>
 */
@Slf4j
public class Downloader {

    /** Limite do corpo em {@link #downloadBytes}; o bundle real tem ~300 KB. */
    static final int MAX_BINARY_BYTES = 64 * 1024 * 1024;
    /** Limite do corpo em {@link #downloadText}; o arquivo de hash tem ~150 bytes. */
    static final int MAX_TEXT_BYTES = 4 * 1024;

    private static final int CHUNK_SIZE = 8192;

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
     * @return Array de bytes com os dados baixados, com no máximo {@code MAX_BINARY_BYTES}
     * @throws IOException se o download falhar após todas as tentativas
     */
    public byte[] downloadBytes(String url) throws IOException {
        return downloadWithRetry(url, MAX_BINARY_BYTES);
    }

    /**
     * Faz download de texto UTF-8.
     *
     * @param url URL para download (deve ser HTTPS)
     * @return String com o conteúdo baixado, com no máximo {@code MAX_TEXT_BYTES} bytes
     * @throws IOException se o download falhar após todas as tentativas
     */
    public String downloadText(String url) throws IOException {
        return new String(downloadWithRetry(url, MAX_TEXT_BYTES), StandardCharsets.UTF_8);
    }

    private byte[] downloadWithRetry(String url, int maxBytes) throws IOException {
        log.debug("Iniciando download: {}", url);
        try {
            return retryPolicy.executeWithRetry(
                    url,
                    networkConfig.getMaxRetries() - 1,
                    networkConfig.getRetryIntervalMillis(),
                    () -> performDownload(url, maxBytes));
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Download falhou após " + networkConfig.getMaxRetries()
                    + " tentativas: " + url, e);
        }
    }

    private byte[] performDownload(String url, int maxBytes) throws IOException {
        long timeoutMillis = networkConfig.getDownloadTimeoutMillis();
        long deadlineNanos = System.nanoTime() + timeoutMillis * 1_000_000L;
        HttpURLConnection connection = null;
        try {
            connection = createConnection(url);

            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Falha no download: HTTP " + responseCode + " para URL: " + url);
            }

            try (InputStream inputStream = connection.getInputStream()) {
                byte[] body = readLimited(inputStream, maxBytes, deadlineNanos);
                log.debug("Download concluído com sucesso: {} bytes baixados de {}", body.length, url);
                return body;
            }
        } finally {
            // Encerra o socket também quando a leitura é abortada por limite ou prazo.
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Lê o corpo até o fim, acumulando em um único array que cresce até {@code maxBytes}.
     *
     * <p>O prazo é conferido antes de cada leitura: um servidor que goteje bytes dentro do
     * {@code readTimeout} não consegue prolongar a tentativa indefinidamente. A capacidade
     * nunca é reservada a partir de Content-Length, que é controlado pelo servidor.</p>
     *
     * @throws IOException            se o corpo exceder {@code maxBytes}
     * @throws SocketTimeoutException se o prazo total for atingido antes do fim do corpo
     */
    static byte[] readLimited(InputStream inputStream, int maxBytes, long deadlineNanos) throws IOException {
        byte[] buffer = new byte[Math.min(CHUNK_SIZE, maxBytes)];
        byte[] chunk = new byte[CHUNK_SIZE];
        int size = 0;
        while (true) {
            if (System.nanoTime() - deadlineNanos >= 0) {
                throw new SocketTimeoutException("Prazo total do download excedido após " + size + " bytes");
            }
            int read = inputStream.read(chunk);
            if (read == -1) {
                break;
            }
            if (read > maxBytes - size) {
                throw new IOException("Corpo da resposta excede o limite de " + maxBytes + " bytes");
            }
            if (size + read > buffer.length) {
                buffer = Arrays.copyOf(buffer, Math.min(maxBytes, Math.max(buffer.length * 2, size + read)));
            }
            System.arraycopy(chunk, 0, buffer, size, read);
            size += read;
        }
        return size == buffer.length ? buffer : Arrays.copyOf(buffer, size);
    }

    private HttpURLConnection createConnection(String url) throws IOException {
        // URI.create + toURL substitui o construtor new URL(String), deprecado desde o Java 20
        URL targetUrl = URI.create(url).toURL();
        HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();

        connection.setConnectTimeout(networkConfig.getDownloadTimeoutMillis());
        connection.setReadTimeout(networkConfig.getDownloadTimeoutMillis());
        connection.setRequestMethod("GET");
        // Um redirect trocaria o destino validado pela configuração por um escolhido pelo servidor.
        connection.setInstanceFollowRedirects(false);
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
