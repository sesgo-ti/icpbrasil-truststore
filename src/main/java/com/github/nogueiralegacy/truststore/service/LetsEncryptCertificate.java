package com.github.nogueiralegacy.truststore.service;

import com.github.nogueiralegacy.truststore.config.LetsEncryptProperties;
import com.github.nogueiralegacy.truststore.util.Downloader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Service
public class LetsEncryptCertificate {
    private final Downloader downloader;
    private final LetsEncryptProperties letsEncryptProperties;

    public LetsEncryptCertificate(Downloader downloader, LetsEncryptProperties letsEncryptProperties) {
        this.downloader = downloader;
        this.letsEncryptProperties = letsEncryptProperties;
    }

    private InputStream downloadCertificate(String url) throws Exception {
        return downloader.download(url);
    }

    /**
     * Adiciona certificados Let's Encrypt ao truststore
     */
    private void addLetsEncryptCertificates(KeyStore trustStore) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        for (String certUrl : letsEncryptProperties.getCertificateUrls()) {
            try {
                System.out.println("Baixando certificado Let's Encrypt: " + certUrl);

                // Baixar certificado usando conexão HTTP simples
                URL url = new URL(certUrl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(10000);
                connection.setReadTimeout(10000);

                try (InputStream certStream = connection.getInputStream()) {
                    Certificate cert = cf.generateCertificate(certStream);

                    if (cert instanceof X509Certificate) {
                        X509Certificate x509 = (X509Certificate) cert;
                        String alias = extractFileNameFromUrl(certUrl);
                        trustStore.setCertificateEntry(alias, x509);
                        System.out.println("Certificado adicionado: " + alias);
                    }
                }

            } catch (Exception e) {
                System.out.println("Falha ao baixar certificado " + certUrl + ": " + e.getMessage());
                // Continua com os outros certificados
            }
        }
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
