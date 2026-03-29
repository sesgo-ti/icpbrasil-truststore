package br.gov.go.saude.fhir.truststore.icpbrasil.config;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;

/**
 * Configuração do cliente S3-compatível (AWS S3, MinIO, Digital Ocean Spaces, etc.).
 *
 * <p>Ativado quando {@code truststore-icpbrasil.storage.type=s3}.</p>
 *
 * <p>Quando {@code ca-cert-path} é definido, o cliente é construído com um
 * TrustManager exclusivo para aquele certificado CA, isolando a confiança do S3
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

    @NotBlank(message = "S3 region must be provided")
    private String region;

    @NotBlank(message = "S3 access key must be provided")
    private String accessKey;

    @NotBlank(message = "S3 secret key must be provided")
    private String secretKey;

    @NotBlank(message = "S3 bucket must be provided")
    private String bucket;

    /**
     * Caminho para o certificado PEM da CA usada pelo servidor S3 (classpath: ou file:).
     * Quando não definido, usa o trustManager global.
     * Exemplo: S3_CA_CERT_PATH=file:/etc/ssl/certs/ca-certificates.crt
     */
    private String caCertPath;

    @Bean(destroyMethod = "close")
    public S3Client s3Client(X509TrustManager trustManager) {
        var httpClientBuilder = ApacheHttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(10))
                .socketTimeout(Duration.ofSeconds(60));

        if (StringUtils.hasText(caCertPath)) {
            log.info("S3: usando CA dedicada para TLS: {}", caCertPath);
            TrustManager[] dedicatedTrustManagers = buildDedicatedTrustManagers(caCertPath);
            httpClientBuilder.tlsTrustManagersProvider(() -> dedicatedTrustManagers);
        } else {
            log.info("S3: usando trustManager global para TLS");
            httpClientBuilder.tlsTrustManagersProvider(() -> new TrustManager[]{trustManager});
        }

        return S3Client.builder()
                .endpointOverride(URI.create(endpoint))
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKey, secretKey)))
                .forcePathStyle(true)
                .httpClientBuilder(httpClientBuilder)
                .build();
    }

    private TrustManager[] buildDedicatedTrustManagers(String certPath) {
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

            return Arrays.stream(tmf.getTrustManagers())
                    .filter(tm -> tm instanceof X509TrustManager)
                    .toArray(TrustManager[]::new);

        } catch (Exception e) {
            throw new IllegalStateException("Falha ao carregar certificado CA do S3: " + certPath, e);
        }
    }
}
