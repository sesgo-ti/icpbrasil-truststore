package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.repository.S3Repository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.validation.annotation.Validated;
import software.amazon.awssdk.services.s3.S3Client;

/**
 * Storage S3, ativo apenas com {@code icpbrasil-truststore.storage.type=s3} e com o AWS SDK
 * no classpath. É importada por {@link TrustStoreAutoConfiguration}, não descoberta por
 * component scan; por isso não é {@code @Configuration}.
 *
 * <p>As condições ficam no nível da classe para que, sem o SDK, nenhum método desta classe
 * seja introspectado — é o que mantém a auto-configuração principal utilizável em
 * aplicações que só usam filesystem.</p>
 */
@ConditionalOnClass(S3Client.class)
@ConditionalOnProperty(name = "icpbrasil-truststore.storage.type", havingValue = "s3")
@Import(S3ClientFactory.class)
class S3StorageConfiguration {

    /**
     * Binding de {@link S3Properties}; a validação Bean Validation ({@code @Validated})
     * roda após o binding. {@code @ConditionalOnMissingBean} permite que o consumidor
     * forneça o próprio bean.
     */
    @Bean
    @ConfigurationProperties(prefix = "icpbrasil-truststore.s3")
    @Validated
    @ConditionalOnMissingBean(S3Properties.class)
    S3Properties s3Properties() {
        return new S3Properties();
    }

    @Bean
    @ConditionalOnMissingBean(TrustStoreRepository.class)
    S3Repository s3Repository(S3Client s3Client, TrustStoreConfig trustStoreConfig,
                              S3Properties s3Properties) {
        return new S3Repository(s3Client, trustStoreConfig, s3Properties);
    }
}
