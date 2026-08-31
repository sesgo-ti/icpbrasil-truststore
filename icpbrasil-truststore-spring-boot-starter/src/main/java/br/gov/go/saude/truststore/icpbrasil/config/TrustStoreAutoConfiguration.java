package br.gov.go.saude.truststore.icpbrasil.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

/**
 * Auto-configuração para o icpbrasil-truststore.
 * Permite que o Spring Boot detecte automaticamente os componentes do icpbrasil-truststore.
 */
@AutoConfiguration
@EnableConfigurationProperties(TrustStoreConfig.class)
@ComponentScan(basePackages = "br.gov.go.saude.truststore.icpbrasil")
public class TrustStoreAutoConfiguration {
}
