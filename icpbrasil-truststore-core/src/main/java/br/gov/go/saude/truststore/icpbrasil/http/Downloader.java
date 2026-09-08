package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/** Downloads HTTPS do acervo com TLS dedicado, sem redirects e com orcamentos por tentativa. */
public class Downloader {
    private final HttpClient client;
    private final RetryPolicy retryPolicy;
    private final int attempts;
    private final long retryMillis;
    private final Duration timeout;
    private final int maxZipBytes;
    private final int maxHashBytes;

    /** O SSLContext da JVM nao e alterado; somente o cliente do acervo recebe a confianca dedicada. */
    public Downloader(TrustStoreManager trustStoreManager, RetryPolicy retryPolicy, TrustStoreConfig config) {
        this(HttpClient.newBuilder().sslContext(trustStoreManager.getSslContext())
                .followRedirects(HttpClient.Redirect.NEVER).build(), retryPolicy, config);
    }

    Downloader(HttpClient client, RetryPolicy retryPolicy, TrustStoreConfig config) {
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("Downloads do acervo exigem Redirect.NEVER");
        }
        config.getBundle().validate();
        TrustStoreConfig.NetworkConfig network = config.getNetwork();
        if (network.getDownloadTimeoutSeconds() < 1 || network.getDownloadTimeoutSeconds() > 300
                || network.getMaxRetries() < 1 || network.getMaxRetries() > 10
                || network.getRetryIntervalSeconds() < 0 || network.getRetryIntervalSeconds() > 300) {
            throw new IllegalArgumentException("Configuracao de rede invalida para download do acervo");
        }
        this.client = client;
        this.retryPolicy = retryPolicy;
        this.attempts = network.getMaxRetries();
        this.retryMillis = network.getRetryIntervalMillis();
        this.timeout = Duration.ofSeconds(network.getDownloadTimeoutSeconds());
        this.maxZipBytes = config.getBundle().getMaxCompressedBytes();
        this.maxHashBytes = config.getBundle().getMaxHashBytes();
    }

    /** Recebe o ZIP dentro do limite compressed; o prazo inclui o corpo completo em cada tentativa. */
    public byte[] downloadBytes(String url) throws IOException {
        return download(url, maxZipBytes);
    }

    /** Recebe texto UTF-8 dentro do limite de hash, independente do limite do ZIP. */
    public String downloadText(String url) throws IOException {
        return new String(download(url, maxHashBytes), StandardCharsets.UTF_8);
    }

    private byte[] download(String url, int maxBytes) throws IOException {
        URI uri = URI.create(url);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null) {
            throw new IOException("URL do acervo deve usar HTTPS com host e sem credenciais");
        }
        HttpRequest request = HttpRequest.newBuilder(uri).timeout(timeout)
                .header("User-Agent", "TrustStore-Downloader/1.0").GET().build();
        try {
            return retryPolicy.executeWithRetry(url, attempts - 1, retryMillis,
                    () -> CertificateHttpTransport.sendBounded(client, request, maxBytes));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Download interrompido", e);
        } catch (IOException | DownloadPolicyException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Falha no download do acervo", e);
        }
    }
}
