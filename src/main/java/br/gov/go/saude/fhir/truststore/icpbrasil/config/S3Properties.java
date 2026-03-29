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
 * Configuração do cliente S3-compatível (AWS S3, MinIO, Digital Ocean Spaces, etc.).
 *
 * <p>Ativado quando {@code truststore-icpbrasil.storage.type=s3}.</p>
 *
 * <p>Quando {@code ca-cert-path} é definido, o OkHttpClient é construído com um
 * KeyStore exclusivo para aquele certificado, isolando a confiança do S3
 * do SSLContext principal da aplicação.
 * Quando omitido, usa o trustManager global.</p>
 */
@Slf4j
@Getter
@Setter
@Validated
@Configuration
@ConditionalOnProperty(name = "truststore-icpbrasil.storage.type", havingValue = "s3")
@ConfigurationProperties(prefix = "truststore-icpbrasil.s3")
public class S3Properties {

    @NotBlank(message = "S3 endpoint must be provided")
    private String endpoint;

    @NotBlank(message = "S3 access key must be provided")
    private String accessKey;

    @NotBlank(message = "S3 secret key must be provided")
    private String secretKey;

    @NotBlank(message = "S3 bucket must be provided")
    private String bucket;

    /**
     * Caminho para o certificado PEM da CA usada pelo servidor S3 (classpath: ou file:).
     * Quando não definido, usa o trustManager global.
     * Exemplo: MINIO_CA_CERT_PATH=file:/etc/ssl/certs/ca-certificates.crt
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
     * Constrói o OkHttpClient com a estratégia TLS adequada:
     * - ca-cert-path definido → KeyStore dedicado com o cert da CA do servidor S3
     * - ca-cert-path ausente  → usa o trustManager global
     */
    private OkHttpClient buildHttpClient(SSLContext sslContext, X509TrustManager trustManager) {
        if (StringUtils.hasText(caCertPath)) {
            log.info("S3: usando CA dedicada para TLS: {}", caCertPath);
            return buildHttpClientWithDedicatedTrust(caCertPath);
        }
        log.info("S3: usando trustManager global para TLS");
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

            log.info("S3: CA carregada — subject: {}, válido até: {}",
                    caCert.getSubjectX500Principal().getName(), caCert.getNotAfter());

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("s3-ca", caCert);

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
            throw new IllegalStateException("Falha ao carregar certificado CA do S3: " + certPath, e);
        }
    }
}
