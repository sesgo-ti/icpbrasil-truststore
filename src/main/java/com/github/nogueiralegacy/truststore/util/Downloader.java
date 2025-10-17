package com.github.nogueiralegacy.truststore.util;

import com.github.nogueiralegacy.truststore.config.LetsEncryptProperties;
import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

@Slf4j
@Component
public class Downloader {
    private final int maxRetries;
    private final int retryIntervalMillis;
    private final int timeoutMillis;
    private final LetsEncryptProperties letsEncryptProperties;

    public Downloader(TrustStoreConfig trustStoreConfig, LetsEncryptProperties letsEncryptProperties) {
        this.maxRetries = trustStoreConfig.getNetwork().getMaxRetries();
        this.retryIntervalMillis = trustStoreConfig.getNetwork().getRetryIntervalMillis();
        this.timeoutMillis = trustStoreConfig.getNetwork().getDownloadTimeoutMillis();
        this.letsEncryptProperties = letsEncryptProperties;
        
        try {
            if (!letsEncryptProperties.getCertificates().isEmpty()) {
                SSLContext sslContext = createSSLContextWithLetsEncrypt();
                HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            }
        } catch (Exception e) {
            log.error("Erro ao criar SSL context: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao inicializar SSL context", e);
        }
    }

    /**
     * Faz download de dados binários com retry simples
     *
     * @param url URL para download
     * @return Array de bytes com os dados baixados
     * @throws IOException se o download falhar após todas as tentativas
     */
    public byte[] downloadBytes(String url) throws IOException {
        log.debug("Iniciando download: {}", url);
        
        for (int tentativa = 1; tentativa <= maxRetries; tentativa++) {
            try {
                HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
                connection.setConnectTimeout(timeoutMillis);
                connection.setReadTimeout(timeoutMillis);
                connection.setRequestMethod("GET");
                
                int responseCode = connection.getResponseCode();
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    try (InputStream inputStream = connection.getInputStream()) {
                        byte[] data = inputStream.readAllBytes();
                        log.debug("Download concluído: {} bytes de {}", data.length, url);
                        return data;
                    }
                } else {
                    throw new IOException("HTTP " + responseCode + " para " + url);
                }
                
            } catch (Exception e) {
                log.warn("Tentativa {}/{} falhou para {}: {}", tentativa, maxRetries, url, e.getMessage());
                
                if (tentativa == maxRetries) {
                    throw new IOException("Falha no download após " + maxRetries + " tentativas: " + url, e);
                }
                
                try {
                    Thread.sleep(retryIntervalMillis);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Download interrompido", ie);
                }
            }
        }
        
        throw new IOException("Download falhou: " + url);
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

    /**
     * Cria SSL context com certificados Let's Encrypt
     */
    private SSLContext createSSLContextWithLetsEncrypt() throws Exception {
        log.debug("Criando SSL context com certificados Let's Encrypt");
        
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        
        // Adiciona certificados Let's Encrypt
        addLetsEncryptCertificates(trustStore);
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        
        return sslContext;
    }

    /**
     * Adiciona certificados Let's Encrypt ao truststore
     */
    private void addLetsEncryptCertificates(KeyStore trustStore) throws Exception {
        log.debug("Adicionando certificados Let's Encrypt");
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        
        for (String certUrl : letsEncryptProperties.getCertificateUrls()) {
            try {
                log.debug("Baixando certificado Let's Encrypt: {}", certUrl);
                
                byte[] certData = downloadBytes(certUrl);
                Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certData));
                String certName = extractCertName(certUrl);
                trustStore.setCertificateEntry(certName, cert);
                log.debug("Certificado Let's Encrypt adicionado: {}", certName);
                
            } catch (Exception e) {
                log.warn("Falha ao baixar certificado Let's Encrypt de {}: {}", certUrl, e.getMessage());
                // Continua com outros certificados mesmo se um falhar
            }
        }
    }

    /**
     * Extrai nome do certificado da URL
     */
    private String extractCertName(String url) {
        String fileName = url.substring(url.lastIndexOf('/') + 1);
        if (fileName.isEmpty()) {
            fileName = "certificate";
        }
        return "letsencrypt-" + fileName.replaceAll("\\.[^.]+$", "");
    }
}
