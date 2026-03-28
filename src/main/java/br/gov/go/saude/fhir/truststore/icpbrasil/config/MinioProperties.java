package br.gov.go.saude.fhir.truststore.icpbrasil.config;

import io.minio.MinioClient;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Configuração do cliente MinIO com suporte a TLS via CA dedicada.
 *
 * <p>Quando {@code ca-cert-path} é definido, o OkHttpClient é construído com um
 * KeyStore exclusivo contendo apenas aquele certificado — isolando a confiança do MinIO
 * do SSLContext principal da aplicação.</p>
 *
 * <p>Quando {@code ca-cert-path} é omitido, o trustManager global é utilizado.</p>
 */
@Slf4j
@Getter
@Setter
@Validated
@Configuration
@ConditionalOnProperty(name = "truststore-icpbrasil.storage.type", havingValue = "minio")
@ConfigurationProperties(prefix = "truststore-icpbrasil.minio")
public class MinioProperties {

    @NotBlank(message = "MinIO Endpoint must be provided")
    private String endpoint;

    @NotBlank(message = "MinIO Access Key must be provided")
    private String accessKey;

    @NotBlank(message = "MinIO Secret Key must be provided")
    private String secretKey;

    /**
     * Caminho para o certificado PEM da CA usada pelo servidor MinIO.
     * Suporta prefixos classpath: e file:.
     * Quando não definido, o trustManager global é utilizado.
     * Exemplo: classpath:infra/k8s-ca.pem
     */
    private String caCertPath;

    @Bean
    public MinioClient minioClient(SSLContext sslContext, X509TrustManager trustManager) {
        OkHttpClient httpClient = buildHttpClient(sslContext, trustManager);

        return MinioClient.builder()
                .endpoint(endpoint)
                .credentials(accessKey, secretKey)
                .httpClient(httpClient)
                .build();
    }

    /**
     * Constrói o OkHttpClient com a estratégia de TLS adequada:
     * - ca-cert-path definido → KeyStore dedicado só com o cert da CA do MinIO
     * - ca-cert-path ausente  → usa o trustManager global (certs do classpath/filesystem)
     */
    private OkHttpClient buildHttpClient(SSLContext sslContext, X509TrustManager trustManager) {
        if (StringUtils.hasText(caCertPath)) {
            log.info("MinIO: usando CA dedicada para TLS: {}", caCertPath);
            return buildHttpClientWithDedicatedTrust(caCertPath);
        }
        log.info("MinIO: usando trustManager global para TLS");
        return new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                .build();
    }

    private OkHttpClient buildHttpClientWithDedicatedTrust(String certPath) {
        try {
            Resource resource = new DefaultResourceLoader().getResource(certPath);

            X509Certificate caCert;
            try (InputStream is = resource.getInputStream()) {
                caCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
            }

            log.info("MinIO: CA carregada — subject: {}, válido até: {}",
                    caCert.getSubjectX500Principal().getName(), caCert.getNotAfter());

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("minio-ca", caCert);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            X509TrustManager dedicatedTm = Arrays.stream(tmf.getTrustManagers())
                    .filter(tm -> tm instanceof X509TrustManager)
                    .map(tm -> (X509TrustManager) tm)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Nenhum X509TrustManager encontrado"));

            SSLContext dedicatedSslContext = SSLContext.getInstance("TLS");
            dedicatedSslContext.init(null, new TrustManager[]{dedicatedTm}, null);

            return new OkHttpClient.Builder()
                    .sslSocketFactory(dedicatedSslContext.getSocketFactory(), dedicatedTm)
                    .build();

        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao carregar certificado CA do MinIO: " + certPath, e);
        }
    }
}

