package br.gov.go.saude.fhir.truststore.icpbrasil.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

/**
 * Auto-configuração para o trust-store-spring-boot-starter.
 * Permite que o Spring Boot detecte automaticamente os componentes do trust-store.
 */
@AutoConfiguration
@EnableConfigurationProperties(TrustStoreConfig.class)
@ComponentScan(basePackages = "br.gov.go.saude.fhir.truststore.icpbrasil")
public class TrustStoreAutoConfiguration {
}
