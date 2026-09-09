package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.TrustStoreManager;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreBootstrap;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreScheduler;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;

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
 * <p>O binding de {@link TrustStoreConfig} é feito aqui via
 * {@code @Bean @ConfigurationProperties} — a classe é um POJO puro no core,
 * sem anotações Spring, o que a torna testável de forma isolada.</p>
 *
 * <p>Integrações que dependem de bibliotecas opcionais (AWS SDK para S3, Actuator para
 * health) ficam em {@link S3StorageConfiguration} e {@link HealthConfiguration}, condicionadas
 * no nível da classe. Esta classe não pode referenciar tipos dessas bibliotecas em campos ou
 * assinaturas: a introspecção dos métodos {@code @Bean} carregaria as classes ausentes e
 * derrubaria o contexto mesmo com {@code storage.type=filesystem}.</p>
 */
@AutoConfiguration
@Import({S3StorageConfiguration.class, HealthConfiguration.class})
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

    /**
     * Falha cedo, com diagnóstico legível, quando o storage S3 é selecionado sem o AWS SDK
     * no classpath. Sem esta configuração, {@link S3StorageConfiguration} seria apenas
     * ignorada e o erro apareceria como ausência genérica de {@link TrustStoreRepository}.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(name = "icpbrasil-truststore.storage.type", havingValue = "s3")
    @ConditionalOnMissingClass("software.amazon.awssdk.services.s3.S3Client")
    static class S3SdkAusenteConfiguration {
        S3SdkAusenteConfiguration() {
            throw new IllegalStateException("icpbrasil-truststore.storage.type=s3 requer as dependências "
                    + "software.amazon.awssdk:s3 e software.amazon.awssdk:apache-client no classpath "
                    + "(opcionais no icpbrasil-truststore-autoconfigure)");
        }
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
}
