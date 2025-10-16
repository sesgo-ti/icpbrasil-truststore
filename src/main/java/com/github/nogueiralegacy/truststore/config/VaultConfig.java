package com.github.nogueiralegacy.truststore.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuração para integração com HashiCorp Vault.
 * Define beans necessários para acessar certificados armazenados no Vault.
 */
@Slf4j
@Configuration
public class VaultConfig {
    
    /**
     * Configura ObjectMapper para serialização/deserialização JSON.
     * Inclui suporte para tipos de data/hora do Java 8+.
     * 
     * @return ObjectMapper configurado
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }
}