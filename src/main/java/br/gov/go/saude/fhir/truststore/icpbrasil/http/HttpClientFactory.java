package br.gov.go.saude.fhir.truststore.icpbrasil.http;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Factory responsável por criar e configurar conexões HTTP/HTTPS
 * seguindo melhores práticas de segurança e performance
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HttpClientFactory {

    private final TrustStoreManager trustStoreManager;
    private final TrustStoreConfig trustStoreConfig;

    /**
     * Cria uma conexão HTTP configurada com timeouts e SSL context apropriados
     */
    public HttpURLConnection createConnection(String url) throws ConnectionCreationException {
        try {
            URL targetUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();

            configureConnection(connection);
            configureSSL(connection);

            log.debug("Conexão HTTP criada para: {}", url);
            return connection;

        } catch (IOException e) {
            log.error("Erro ao criar conexão para {}: {}", url, e.getMessage());
            throw new ConnectionCreationException("Falha ao criar conexão HTTP", e);
        }
    }

    private void configureConnection(HttpURLConnection connection) throws IOException {
        TrustStoreConfig.NetworkConfig networkConfig = trustStoreConfig.getNetwork();

        connection.setConnectTimeout(networkConfig.getDownloadTimeoutMillis());
        connection.setReadTimeout(networkConfig.getDownloadTimeoutMillis());
        connection.setRequestMethod("GET");
        connection.setInstanceFollowRedirects(true);

        connection.setRequestProperty("User-Agent", "TrustStore-Downloader/1.0");
        connection.setRequestProperty("Accept", "*/*");
        connection.setRequestProperty("Connection", "close");
    }

    private void configureSSL(HttpURLConnection connection) throws ConnectionCreationException {
        if (connection instanceof HttpsURLConnection httpsConnection) {
            httpsConnection.setSSLSocketFactory(trustStoreManager.getSslContext().getSocketFactory());
            log.debug("SSL Context configurado para conexão HTTPS");
            return;
        }
        log.error("Conexão não é HTTPS, SSL Context não aplicado");
        throw new RuntimeException("Conexão não é HTTPS", null);
    }

    /**
     * Exceção específica para falhas na criação de conexões
     */
    public static class ConnectionCreationException extends RuntimeException {
        public ConnectionCreationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
