package br.gov.go.saude.truststore.icpbrasil.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
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
 * Fábrica do {@link S3Client}, ativada apenas quando {@code truststore-icpbrasil.storage.type=s3}.
 *
 * <p>Separada de {@link S3Properties} para manter o core livre de dependências do AWS SDK:
 * {@code S3Properties} é um POJO puro; este módulo ({@code autoconfigure}) detém a dependência
 * do SDK e toda a lógica de construção do cliente.</p>
 *
 * <p>Quando {@code truststore-icpbrasil.s3.ca-cert-path} é definido, o cliente usa um
 * {@code TrustManager} exclusivo para aquele certificado CA, isolando a confiança do S3
 * do SSLContext principal da aplicação. Quando omitido, usa o JVM default truststore (cacerts),
 * adequado para AWS S3 e endpoints com CA pública reconhecida.</p>
 */
@Slf4j
@Configuration
@ConditionalOnProperty(name = "truststore-icpbrasil.storage.type", havingValue = "s3")
public class S3ClientFactory {

    /**
     * Produz o {@link S3Client} configurado a partir das propriedades S3.
     * O {@code destroyMethod = "close"} garante que o cliente HTTP seja fechado
     * corretamente durante o shutdown do contexto Spring.
     */
    @Bean(destroyMethod = "close")
    public S3Client s3Client(S3Properties props) {
        var httpClientBuilder = ApacheHttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(10))
                .socketTimeout(Duration.ofSeconds(60));

        if (StringUtils.hasText(props.getCaCertPath())) {
            log.info("S3: usando CA dedicada para TLS: {}", props.getCaCertPath());
            TrustManager[] dedicatedTrustManagers = buildDedicatedTrustManagers(props.getCaCertPath());
            httpClientBuilder.tlsTrustManagersProvider(() -> dedicatedTrustManagers);
        } else {
            log.info("S3: usando JVM default truststore para TLS");
        }

        return S3Client.builder()
                .endpointOverride(URI.create(props.getEndpoint()))
                .region(Region.of(props.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(props.getAccessKey(), props.getSecretKey())))
                .forcePathStyle(true)
                .httpClientBuilder(httpClientBuilder)
                .build();
    }

    /**
     * Carrega o certificado CA indicado por {@code certPath} e constrói um array de
     * {@link TrustManager} restrito àquela CA. O isolamento impede que o cliente S3
     * confie em CAs além da especificada, reduzindo a superfície de ataque em redes privadas.
     */
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
