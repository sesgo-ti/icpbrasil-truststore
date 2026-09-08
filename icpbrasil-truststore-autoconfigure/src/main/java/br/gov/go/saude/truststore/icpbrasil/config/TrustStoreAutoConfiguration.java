package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.TrustStoreManager;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreBootstrap;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreCacheHealthIndicator;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreScheduler;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.S3Repository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.service.provider.CertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.TrustedCertsProvider;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.CrlClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.OcspClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationCache;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.validation.annotation.Validated;
import software.amazon.awssdk.services.s3.S3Client;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Auto-configuração do icpbrasil-truststore.
 *
 * <p>Registra explicitamente (via {@link Bean @Bean}) todos os componentes do
 * core, sem component scan, seguindo o padrão recomendado para módulos de auto-configuração.
 * Todos os beans usam {@link ConditionalOnMissingBean @ConditionalOnMissingBean},
 * permitindo que o consumidor sobrescreva qualquer componente.</p>
 *
 * <p>O binding usa {@code @Bean @ConfigurationProperties}, sem anotações Spring
 * nos objetos de configuração. Adaptadores opcionais são importados somente
 * quando suas dependências estão disponíveis.</p>
 */
@AutoConfiguration
@EnableConfigurationProperties
@Import({TrustStoreAutoConfiguration.S3Configuration.class,
        TrustStoreAutoConfiguration.MissingS3Configuration.class,
        TrustStoreAutoConfiguration.HealthConfiguration.class})
public class TrustStoreAutoConfiguration {

    /**
     * Binding de {@link TrustStoreConfig} com validação diferida via {@code initMethod}.
     * O Spring faz o binding dos campos ANTES de chamar {@code validateProperties()},
     * garantindo que a validação veja os valores já preenchidos.
     * {@code @ConditionalOnMissingBean} permite que o consumidor forneça o próprio bean
     * sem causar {@code NoUniqueBeanDefinitionException}.
     */
    @Bean(initMethod = "validateProperties")
    @ConfigurationProperties(prefix = "icpbrasil-truststore")
    @ConditionalOnMissingBean(TrustStoreConfig.class)
    TrustStoreConfig trustStoreConfig() {
        return new TrustStoreConfig();
    }

    @Bean
    @ConditionalOnMissingBean
    public RetryPolicy retryPolicy(TrustStoreConfig trustStoreConfig) {
        return new RetryPolicy(trustStoreConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    public DownloadPolicy downloadPolicy(TrustStoreConfig trustStoreConfig) {
        return new DownloadPolicy(trustStoreConfig);
    }

    /**
     * Lê os documentos JSON do diretório de certificados confiáveis usando o
     * {@link ResourcePatternResolver} do Spring, que funciona corretamente em fat jars.
     * Os bytes lidos são repassados ao {@link TrustedCertsProvider}, que não realiza I/O.
     */
    @Bean
    @ConditionalOnMissingBean(name = "trustedCertsProvider")
    CertificateProvider trustedCertsProvider(TrustStoreConfig config,
                                              ResourcePatternResolver resolver) {
        // Valida antes de usar para evitar NPE com mensagem opaca
        TrustStoreConfig.TrustedCertsConfig trustedCerts = config.getTrustedCerts();
        if (trustedCerts == null || trustedCerts.getDir() == null || trustedCerts.getDir().isBlank()) {
            throw new IllegalStateException(
                    "Propriedade 'icpbrasil-truststore.trusted-certs.dir' é obrigatória");
        }
        String dir = trustedCerts.getDir();
        // classpath: e classpath*: são equivalentes para o usuário; normaliza para classpath*:
        // para que o resolver busque em todos os JARs do classpath (necessário em fat jars)
        String pattern;
        if (dir.startsWith("classpath")) {
            String semPrefixo = dir.substring(dir.indexOf(':') + 1);
            pattern = "classpath*:" + semPrefixo + "/*.json";
        } else {
            pattern = "file:" + dir + "/*.json";
        }
        List<byte[]> docs = new ArrayList<>();
        try {
            for (Resource r : resolver.getResources(pattern)) {
                try (InputStream in = r.getInputStream()) {
                    docs.add(in.readAllBytes());
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Falha ao ler certificados confiáveis de: " + dir, e);
        }
        if (docs.isEmpty()) {
            throw new IllegalStateException("Nenhum certificado confiável (.json) encontrado em: " + dir);
        }
        return new TrustedCertsProvider(docs);
    }

    @Bean
    @ConditionalOnMissingBean
    public TrustStoreManager trustStoreManager(
            @Qualifier("trustedCertsProvider") CertificateProvider certificateProvider) {
        return new TrustStoreManager(certificateProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public Downloader downloader(TrustStoreManager trustStoreManager, RetryPolicy retryPolicy,
                                 TrustStoreConfig trustStoreConfig) {
        return new Downloader(trustStoreManager, retryPolicy, trustStoreConfig);
    }

    @Bean
    @ConditionalOnMissingBean(TrustStoreRepository.class)
    @ConditionalOnProperty(name = "icpbrasil-truststore.storage.type", havingValue = "filesystem", matchIfMissing = true)
    public FilesystemTrustStoreRepository filesystemTrustStoreRepository(TrustStoreConfig trustStoreConfig) {
        return new FilesystemTrustStoreRepository(trustStoreConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    public IcpBrasilCertificateProvider icpBrasilCertificateProvider(TrustStoreConfig trustStoreConfig,
                                                                     Downloader downloader,
                                                                     TrustStoreRepository trustStoreRepository) {
        return new IcpBrasilCertificateProvider(trustStoreConfig, downloader, trustStoreRepository);
    }

    /**
     * Índice em memória do acervo — instância única por aplicação (escopo singleton
     * do Spring). A escrita é restrita ao {@link TrustStoreService}; consumidores
     * injetam este bean apenas para leitura.
     */
    @Bean
    @ConditionalOnMissingBean
    public Cache trustStoreCache() {
        return new Cache();
    }

    @Bean
    @ConditionalOnMissingBean
    public TrustStoreService trustStoreService(TrustStoreRepository trustStoreRepository,
                                               IcpBrasilCertificateProvider icpBrasilCertificateProvider,
                                               TrustStoreConfig trustStoreConfig,
                                               Cache trustStoreCache) {
        return new TrustStoreService(trustStoreRepository, icpBrasilCertificateProvider, trustStoreConfig,
                trustStoreCache);
    }

    @Bean
    @ConditionalOnMissingBean
    public CertificateChainResolver certificateChainResolver(RetryPolicy retryPolicy,
                                                             TrustStoreConfig trustStoreConfig,
                                                             DownloadPolicy downloadPolicy) {
        return new CertificateChainResolver(retryPolicy, trustStoreConfig, downloadPolicy);
    }

    @Bean
    @ConditionalOnMissingBean
    public RevocationCache revocationCache(TrustStoreConfig trustStoreConfig) {
        return new RevocationCache(trustStoreConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    public OcspClient ocspClient(RevocationCache revocationCache, RetryPolicy retryPolicy,
                                 TrustStoreConfig trustStoreConfig, DownloadPolicy downloadPolicy) {
        return new OcspClient(revocationCache, retryPolicy, trustStoreConfig, downloadPolicy);
    }

    @Bean
    @ConditionalOnMissingBean
    public CrlClient crlClient(RevocationCache revocationCache, RetryPolicy retryPolicy,
                               TrustStoreConfig trustStoreConfig, DownloadPolicy downloadPolicy) {
        return new CrlClient(revocationCache, retryPolicy, trustStoreConfig, downloadPolicy);
    }

    @Bean
    @ConditionalOnMissingBean
    public RevocationService revocationService(OcspClient ocspClient, CrlClient crlClient) {
        return new RevocationService(ocspClient, crlClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "icpbrasil-truststore.bootstrap", name = "enabled",
            havingValue = "true", matchIfMissing = true)
    public TrustStoreBootstrap trustStoreBootstrap(TrustStoreService trustStoreService,
                                                   TrustStoreConfig trustStoreConfig) {
        return new TrustStoreBootstrap(trustStoreService, trustStoreConfig);
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "icpbrasil-truststore.scheduling", name = "enabled",
            havingValue = "true", matchIfMissing = true)
    public TrustStoreScheduler trustStoreScheduler(TrustStoreService trustStoreService,
                                                   TrustStoreConfig trustStoreConfig) {
        return new TrustStoreScheduler(trustStoreService, trustStoreConfig);
    }

    // Configurações lite importadas, sem @Configuration: o scan do standalone não
    // deve registrá-las antes das condições de back-off da auto-configuração.
    @ConditionalOnClass(S3Client.class)
    @ConditionalOnProperty(name = "icpbrasil-truststore.storage.type", havingValue = "s3")
    @Import(S3ClientFactory.class)
    static class S3Configuration {

        @Bean
        @ConfigurationProperties(prefix = "icpbrasil-truststore.s3")
        @Validated
        @ConditionalOnMissingBean
        S3Properties s3Properties() {
            return new S3Properties();
        }

        @Bean
        @ConditionalOnMissingBean(TrustStoreRepository.class)
        S3Repository s3Repository(S3Client s3Client, TrustStoreConfig config, S3Properties properties) {
            return new S3Repository(s3Client, config, properties);
        }

        @Bean
        @ConditionalOnMissingClass("software.amazon.awssdk.http.apache.ApacheHttpClient")
        @ConditionalOnMissingBean(S3Client.class)
        S3Client missingS3HttpClient() {
            throw new IllegalStateException("icpbrasil-truststore.storage.type=s3 requer "
                    + "software.amazon.awssdk:apache-client ou um bean S3Client customizado");
        }
    }

    @ConditionalOnMissingClass("software.amazon.awssdk.services.s3.S3Client")
    @ConditionalOnProperty(name = "icpbrasil-truststore.storage.type", havingValue = "s3")
    static class MissingS3Configuration {

        @Bean
        @ConditionalOnMissingBean(TrustStoreRepository.class)
        TrustStoreRepository missingS3Repository() {
            throw new IllegalStateException("icpbrasil-truststore.storage.type=s3 requer "
                    + "software.amazon.awssdk:s3 e software.amazon.awssdk:apache-client no classpath");
        }
    }

    @ConditionalOnClass(name = "org.springframework.boot.actuate.health.HealthIndicator")
    static class HealthConfiguration {

        @Bean
        @ConditionalOnMissingBean
        TrustStoreCacheHealthIndicator trustStoreCacheHealthIndicator(TrustStoreConfig config, Cache cache) {
            return new TrustStoreCacheHealthIndicator(config, cache);
        }
    }
}
