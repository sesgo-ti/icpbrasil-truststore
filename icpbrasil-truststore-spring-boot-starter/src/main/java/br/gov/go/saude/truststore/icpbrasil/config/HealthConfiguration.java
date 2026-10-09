package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreCacheHealthIndicator;
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Health indicator do acervo, registrado apenas quando o Actuator está no classpath.
 * Importada por {@link TrustStoreAutoConfiguration}; a condição no nível da classe evita
 * introspectar {@link TrustStoreCacheHealthIndicator} (que implementa {@link HealthIndicator})
 * em aplicações sem Actuator.
 */
@ConditionalOnClass(HealthIndicator.class)
class HealthConfiguration {

    @Bean
    @ConditionalOnMissingBean
    TrustStoreCacheHealthIndicator trustStoreCacheHealthIndicator(TrustStoreConfig config, Cache trustStoreCache) {
        return new TrustStoreCacheHealthIndicator(config, trustStoreCache);
    }
}
