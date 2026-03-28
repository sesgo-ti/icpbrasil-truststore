package com.github.nogueiralegacy.truststore.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

/**
 * Auto-configuração para o trust-store-spring-boot-starter.
 * Permite que o Spring Boot detecte automaticamente os componentes do trust-store.
 */
@AutoConfiguration
@EnableConfigurationProperties(TrustStoreConfig.class)
@ComponentScan(basePackages = "com.github.nogueiralegacy.truststore")
public class TrustStoreAutoConfiguration {
}
