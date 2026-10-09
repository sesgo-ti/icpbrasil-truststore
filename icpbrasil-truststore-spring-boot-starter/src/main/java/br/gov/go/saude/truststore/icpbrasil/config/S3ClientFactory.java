package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.http.tls.TlsTrust;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.util.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import javax.net.ssl.TrustManager;
import java.io.InputStream;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

/**
 * Fábrica do {@link S3Client} padrão da biblioteca. Importada por {@link S3StorageConfiguration}
 * (que já garante SDK presente e {@code storage.type=s3}); não é descoberta por component scan,
 * evitando registro duplicado no serviço standalone.
 *
 * <p>Separada de {@link S3Properties} para manter o core livre de dependências do AWS SDK:
 * {@code S3Properties} é um POJO puro; este módulo ({@code spring-boot-starter}) detém a dependência
 * do SDK e toda a lógica de construção do cliente. Um bean {@code S3Client} definido pelo
 * consumidor tem precedência.</p>
 *
 * <p>Quando {@code icpbrasil-truststore.s3.ca-cert-path} é definido, o cliente usa um
 * {@code TrustManager} exclusivo para aquele certificado CA, isolando a confiança do S3
 * do SSLContext principal da aplicação. Quando omitido, usa o JVM default truststore (cacerts),
 * adequado para AWS S3 e endpoints com CA pública reconhecida.</p>
 */
@Slf4j
class S3ClientFactory {

    /**
     * Produz o {@link S3Client} configurado a partir das propriedades S3.
     * O {@code destroyMethod = "close"} garante que o cliente HTTP seja fechado
     * corretamente durante o shutdown do contexto Spring.
     */
    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean(S3Client.class)
    public S3Client s3Client(S3Properties props) {
        var httpClientBuilder = ApacheHttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(10))
                .socketTimeout(Duration.ofSeconds(60));

        if (StringUtils.hasText(props.getCaCertPath())) {
            TrustManager[] dedicatedTrustManagers = buildDedicatedTrustManagers(props.getCaCertPath());
            httpClientBuilder.tlsTrustManagersProvider(() -> dedicatedTrustManagers);
        } else {
            log.info("S3: confia em {}", TlsTrust.jvmDefault().describe());
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
        X509Certificate caCert;
        try (InputStream is = new DefaultResourceLoader().getResource(certPath).getInputStream()) {
            caCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao carregar certificado CA do S3: " + certPath, e);
        }
        TlsTrust trust = TlsTrust.dedicatedCa(List.of(caCert));
        log.info("S3: confia em {}", trust.describe());
        return new TrustManager[]{trust.trustManager()};
    }
}
