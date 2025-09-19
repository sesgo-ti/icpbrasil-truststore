package com.github.nogueiralegacy.truststore;

import com.github.nogueiralegacy.truststore.config.LetsEncryptProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Component
@RequiredArgsConstructor
public class TrustStore {

    private final LetsEncryptProperties letsEncryptProperties;

    /**
     * Cria um SSLContext que inclui os certificados Let's Encrypt necessários
     */
    private SSLContext createSSLContextWithLetsEncrypt() throws Exception {
        String javaHome = System.getProperty("java.home");
        String cacertsPath = javaHome + "/lib/security/cacerts";

        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(cacertsPath)) {
            trustStore.load(fis, "changeit".toCharArray());
        }

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
                        String alias = extractCertName(certUrl);
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
     * Extrai nome do certificado da URL para usar como alias
     */
    private String extractCertName(String url) {
        String fileName = url.substring(url.lastIndexOf('/') + 1);
        return fileName.replace(".pem", "");
    }

    /**
     * Cria uma conexão HTTPS segura usando o SSLContext customizado
     */
    private HttpURLConnection createSecureConnection(String urlString, SSLContext sslContext) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        if (connection instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
            httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
            httpsConnection.setConnectTimeout(30000);
            httpsConnection.setReadTimeout(60000);
        }

        return connection;
    }

    /**
     * Baixa o arquivo fornecido pela URL e salva no diretório informado
     *
     * @param url URL do certificado a ser baixado
     * @param dir Diretório onde o certificado será salvo
     * @throws IllegalArgumentException se a URL ou diretório forem inválidos
     * @throws Exception se ocorrer erro durante o download, configuração SSL ou escrita do arquivo
     */
    public void downloadCertificate(String url, String dir) throws Exception {
        // Validação dos parâmetros de entrada
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL não pode ser nula ou vazia");
        }
        
        if (dir == null || dir.trim().isEmpty()) {
            throw new IllegalArgumentException("Diretório não pode ser nulo ou vazio");
        }

        try {
            // Criar SSLContext com certificados Let's Encrypt
            SSLContext sslContext = createSSLContextWithLetsEncrypt();
            
            // Criação do diretório de destino se não existir
            Path directoryPath = Paths.get(dir);
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
            }
            
            // Extração do nome do arquivo da URL
            String fileName = extractFileNameFromUrl(url);
            Path filePath = directoryPath.resolve(fileName);
            
            // Criar conexão segura
            HttpURLConnection connection = createSecureConnection(url, sslContext);
            connection.setRequestMethod("GET");
            
            // Verificação do código de resposta
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Falha no download. Código de resposta HTTP: " + responseCode);
            }
            
            // Download do arquivo usando InputStream
            try (InputStream inputStream = connection.getInputStream()) {
                Files.copy(inputStream, filePath, StandardCopyOption.REPLACE_EXISTING);
            }
            
            System.out.println("Certificado baixado com sucesso: " + filePath.toString());
            
        } catch (Exception e) {
            throw new IOException("Erro ao baixar o certificado: " + e.getMessage(), e);
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
        if (fileName.isEmpty() || !fileName.contains(".")) {
            fileName = "certificate.crt";
        }
        
        return fileName;
    }
}
