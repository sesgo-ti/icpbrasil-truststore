package br.gov.go.saude.fhir.truststore.icpbrasil.config;

import io.minio.MinioClient;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import okhttp3.OkHttpClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

@Getter
@Setter
@Validated
@Configuration
@ConditionalOnProperty(name = "truststore.storage.type", havingValue = "minio")
@ConfigurationProperties(prefix = "truststore-icpbrasil.minio")
public class MinioProperties {
    @NotBlank(message = "MinIO Enpoint must be provided")
    private String endpoint;

    @NotBlank(message = "MinIO Access Key must be provided")
    private String accessKey;

    @NotBlank(message = "MinIO Secret Key must be provided")
    private String secretKey;

    @Bean
    public MinioClient minioClient() {
        return MinioClient.builder()
                .endpoint(endpoint)
                .credentials(accessKey, secretKey)
                .httpClient(getUnsafeOkHttpClient())
                .build();
    }

    // TODO: Essa implementação é insegura, deve ser substituída
    //  por uma implementação que valide os certificados
    @SneakyThrows
    private OkHttpClient getUnsafeOkHttpClient() {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());

        return new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(),
                        (X509TrustManager) trustAllCerts[0])
                .hostnameVerifier((hostname, session) -> true)
                .build();
    }
}
