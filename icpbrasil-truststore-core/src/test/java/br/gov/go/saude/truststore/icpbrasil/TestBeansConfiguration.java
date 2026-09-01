package br.gov.go.saude.truststore.icpbrasil;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.TrustStoreManager;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.service.provider.CertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.FilesystemCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.CrlClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.OcspClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationCache;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Configuração Spring exclusiva para os testes do módulo core.
 *
 * <p>Espelha a montagem de beans feita pela auto-configuração do módulo
 * {@code icpbrasil-truststore-spring-boot-starter} (que o core não pode
 * referenciar para evitar dependência cíclica).</p>
 */
@SpringBootConfiguration
@EnableConfigurationProperties(TrustStoreConfig.class)
public class TestBeansConfiguration {

    @Bean
    RetryPolicy retryPolicy(TrustStoreConfig trustStoreConfig) {
        return new RetryPolicy(trustStoreConfig);
    }

    @Bean
    DownloadPolicy downloadPolicy(TrustStoreConfig trustStoreConfig) {
        return new DownloadPolicy(trustStoreConfig);
    }

    @Bean
    FilesystemCertificateProvider filesystemCertificateProvider(TrustStoreConfig trustStoreConfig) {
        return new FilesystemCertificateProvider(trustStoreConfig);
    }

    @Bean
    TrustStoreManager trustStoreManager(
            @Qualifier("filesystemCertificateProvider") CertificateProvider certificateProvider) {
        return new TrustStoreManager(certificateProvider);
    }

    @Bean
    Downloader downloader(TrustStoreManager trustStoreManager, RetryPolicy retryPolicy,
                          TrustStoreConfig trustStoreConfig) {
        return new Downloader(trustStoreManager, retryPolicy, trustStoreConfig);
    }

    @Bean
    TrustStoreRepository trustStoreRepository(TrustStoreConfig trustStoreConfig) {
        return new FilesystemTrustStoreRepository(trustStoreConfig);
    }

    @Bean
    IcpBrasilCertificateProvider icpBrasilCertificateProvider(TrustStoreConfig trustStoreConfig,
                                                              Downloader downloader,
                                                              TrustStoreRepository trustStoreRepository) {
        return new IcpBrasilCertificateProvider(trustStoreConfig, downloader, trustStoreRepository);
    }

    @Bean
    TrustStoreService trustStoreService(TrustStoreRepository trustStoreRepository,
                                        IcpBrasilCertificateProvider icpBrasilCertificateProvider,
                                        TrustStoreConfig trustStoreConfig) {
        return new TrustStoreService(trustStoreRepository, icpBrasilCertificateProvider, trustStoreConfig);
    }

    @Bean
    CertificateChainResolver certificateChainResolver(RetryPolicy retryPolicy,
                                                      TrustStoreConfig trustStoreConfig,
                                                      DownloadPolicy downloadPolicy) {
        return new CertificateChainResolver(retryPolicy, trustStoreConfig, downloadPolicy);
    }

    @Bean
    RevocationCache revocationCache(TrustStoreConfig trustStoreConfig) {
        return new RevocationCache(trustStoreConfig);
    }

    @Bean
    OcspClient ocspClient(RevocationCache revocationCache, RetryPolicy retryPolicy,
                          TrustStoreConfig trustStoreConfig, DownloadPolicy downloadPolicy) {
        return new OcspClient(revocationCache, retryPolicy, trustStoreConfig, downloadPolicy);
    }

    @Bean
    CrlClient crlClient(RevocationCache revocationCache, RetryPolicy retryPolicy,
                        TrustStoreConfig trustStoreConfig, DownloadPolicy downloadPolicy) {
        return new CrlClient(revocationCache, retryPolicy, trustStoreConfig, downloadPolicy);
    }

    @Bean
    RevocationService revocationService(OcspClient ocspClient, CrlClient crlClient) {
        return new RevocationService(ocspClient, crlClient);
    }
}
