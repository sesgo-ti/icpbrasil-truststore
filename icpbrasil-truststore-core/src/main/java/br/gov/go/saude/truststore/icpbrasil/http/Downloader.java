package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

/**
 * Downloads HTTPS do bundle ICP-Brasil e do seu hash, publicados pelo ITI.
 *
 * <p>Usa um {@link CertificateHttpTransport} próprio do canal (SSLContext dedicado e
 * {@link DownloadPolicy#acervoIti()}) e as retentativas de {@link RetryPolicy}. Cada tentativa
 * herda o contrato do transporte: sem redirect, status diferente de 200 falha e o corpo é limitado
 * durante o recebimento. Violações de política ({@link DownloadPolicyException}) não são
 * repetidas nem encapsuladas.</p>
 */
@Slf4j
public class Downloader {

    /** Limite do corpo em {@link #downloadBytes}; o bundle real tem ~300 KB. */
    static final int MAX_BINARY_BYTES = 64 * 1024 * 1024;
    /** Limite do corpo em {@link #downloadText}; o arquivo de hash tem ~150 bytes. */
    static final int MAX_TEXT_BYTES = 4 * 1024;

    private final CertificateHttpTransport transport;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.NetworkConfig networkConfig;

    public Downloader(CertificateHttpTransport transport, RetryPolicy retryPolicy,
                      TrustStoreConfig trustStoreConfig) {
        this.transport = Objects.requireNonNull(transport, "transport");
        this.retryPolicy = retryPolicy;
        this.networkConfig = trustStoreConfig.getNetwork();
    }

    /**
     * Cria o transporte do canal do acervo: {@code sslContext} do canal, sem redirect e
     * restrito ao host do ITI por {@link DownloadPolicy#acervoIti()}.
     */
    public static CertificateHttpTransport transporteAcervoIti(SSLContext sslContext, TrustStoreConfig config) {
        HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofMillis(config.getNetwork().getDownloadTimeoutMillis()))
                .build();
        return new CertificateHttpTransport(DownloadPolicy.acervoIti(), httpClient);
    }

    /**
     * Faz download de dados binários com retry automático.
     *
     * @param url URL para download (deve ser HTTPS)
     * @return Array de bytes com os dados baixados, com no máximo {@code MAX_BINARY_BYTES}
     * @throws IOException             se o download falhar após todas as tentativas
     * @throws DownloadPolicyException se a política bloquear a URL, houver redirect ou o corpo exceder o limite
     */
    public byte[] downloadBytes(String url) throws IOException {
        return downloadWithRetry(url, MAX_BINARY_BYTES);
    }

    /**
     * Faz download de texto UTF-8.
     *
     * @param url URL para download (deve ser HTTPS)
     * @return String com o conteúdo baixado, com no máximo {@code MAX_TEXT_BYTES} bytes
     * @throws IOException             se o download falhar após todas as tentativas
     * @throws DownloadPolicyException se a política bloquear a URL, houver redirect ou o corpo exceder o limite
     */
    public String downloadText(String url) throws IOException {
        return new String(downloadWithRetry(url, MAX_TEXT_BYTES), StandardCharsets.UTF_8);
    }

    private byte[] downloadWithRetry(String url, int maxBytes) throws IOException {
        if (!"https".equalsIgnoreCase(URI.create(url).getScheme())) {
            throw new IOException("URL deve usar HTTPS: " + url);
        }
        log.debug("Iniciando download: {}", url);
        Duration timeout = Duration.ofMillis(networkConfig.getDownloadTimeoutMillis());
        try {
            return retryPolicy.executeWithRetry(
                    url,
                    networkConfig.getMaxRetries() - 1,
                    networkConfig.getRetryIntervalMillis(),
                    () -> transport.get(url, maxBytes, timeout));
        } catch (IOException | DownloadPolicyException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Download interrompido: " + url, e);
        } catch (Exception e) {
            throw new IOException("Download falhou após " + networkConfig.getMaxRetries()
                    + " tentativas: " + url, e);
        }
    }
}
