package com.github.nogueiralegacy.truststore.util;

import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

@Component
public class Downloader {
    private final int timeout;
    private final int maxRetries;

//    private SSLContext sslContext;

    public Downloader(TrustStoreConfig trustStoreConfig) {
        this.timeout = trustStoreConfig.getNetwork().getDownloadTimeoutMillis();
        this.maxRetries = trustStoreConfig.getNetwork().getMaxRetries();

//        this.sslContext = sslContext;

    }

    public InputStream download(String url) {
        return null;
    }

    /**
     * Cria uma conexão HTTPS segura usando o SSLContext customizado
     */
    private HttpURLConnection createSecureConnection(String urlString, SSLContext sslContext) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        if (connection instanceof HttpsURLConnection httpsConnection) {
            httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
            httpsConnection.setConnectTimeout(timeout);
            httpsConnection.setReadTimeout(timeout);
        }

        return connection;
    }

    /**
     * Extrai o nome do arquivo da URL
     *
     * @param url URL do arquivo
     * @return Nome do arquivo extraído da URL
     */
    private String extractFileNameFromUrl(String url) {
        String fileName = url.substring(url.lastIndexOf('/') + 1);

        // Se não conseguir extrair um nome válido, usa um nome padrão
        if (!fileName.contains(".")) {
            fileName = "certificate.crt";
        }

        return fileName;
    }
}
