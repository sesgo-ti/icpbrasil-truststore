package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.controller.TrustStoreController;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.TrustStoreManager;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.S3Repository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreBootstrap;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreCacheHealthIndicator;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreScheduler;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.service.provider.CertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.FilesystemCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.CrlClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.OcspClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationCache;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;
import software.amazon.awssdk.services.s3.S3Client;

/**
 * Auto-configuração do icpbrasil-truststore.
 *
 * <p>Registra explicitamente (via {@link Bean @Bean}) todos os componentes do
 * core, sem component scan, seguindo o padrão recomendado para starters.
 * Todos os beans usam {@link ConditionalOnMissingBean @ConditionalOnMissingBean},
 * permitindo que o consumidor sobrescreva qualquer componente.</p>
 */
@AutoConfiguration
@EnableScheduling
@EnableConfigurationProperties(TrustStoreConfig.class)
@Import({S3Properties.class, TrustStoreController.class})
public class TrustStoreAutoConfiguration {

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

    @Bean
    @ConditionalOnMissingBean
    public FilesystemCertificateProvider filesystemCertificateProvider(TrustStoreConfig trustStoreConfig) {
        return new FilesystemCertificateProvider(trustStoreConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    public TrustStoreManager trustStoreManager(
            @Qualifier("filesystemCertificateProvider") CertificateProvider certificateProvider) {
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
    @ConditionalOnProperty(name = "truststore-icpbrasil.storage.type", havingValue = "filesystem", matchIfMissing = true)
    public FilesystemTrustStoreRepository filesystemTrustStoreRepository(TrustStoreConfig trustStoreConfig) {
        return new FilesystemTrustStoreRepository(trustStoreConfig);
    }

    @Bean
    @ConditionalOnMissingBean(TrustStoreRepository.class)
    @ConditionalOnProperty(name = "truststore-icpbrasil.storage.type", havingValue = "s3")
    public S3Repository s3Repository(S3Client s3Client, TrustStoreConfig trustStoreConfig,
                                     S3Properties s3Properties) {
        return new S3Repository(s3Client, trustStoreConfig, s3Properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public IcpBrasilCertificateProvider icpBrasilCertificateProvider(TrustStoreConfig trustStoreConfig,
                                                                     Downloader downloader,
                                                                     TrustStoreRepository trustStoreRepository) {
        return new IcpBrasilCertificateProvider(trustStoreConfig, downloader, trustStoreRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public TrustStoreService trustStoreService(TrustStoreRepository trustStoreRepository,
                                               IcpBrasilCertificateProvider icpBrasilCertificateProvider,
                                               TrustStoreConfig trustStoreConfig) {
        return new TrustStoreService(trustStoreRepository, icpBrasilCertificateProvider, trustStoreConfig);
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
    @ConditionalOnProperty(prefix = "truststore-icpbrasil.bootstrap", name = "enabled",
            havingValue = "true", matchIfMissing = true)
    public TrustStoreBootstrap trustStoreBootstrap(TrustStoreService trustStoreService,
                                                   TrustStoreConfig trustStoreConfig) {
        return new TrustStoreBootstrap(trustStoreService, trustStoreConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "truststore-icpbrasil.scheduling", name = "enabled",
            havingValue = "true", matchIfMissing = true)
    public TrustStoreScheduler trustStoreScheduler(TrustStoreService trustStoreService) {
        return new TrustStoreScheduler(trustStoreService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "org.springframework.boot.actuate.health.HealthIndicator")
    public TrustStoreCacheHealthIndicator trustStoreCacheHealthIndicator(TrustStoreRepository repository,
                                                                         TrustStoreConfig config) {
        return new TrustStoreCacheHealthIndicator(repository, config);
    }
}
