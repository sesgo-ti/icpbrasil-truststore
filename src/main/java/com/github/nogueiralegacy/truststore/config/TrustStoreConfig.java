package com.github.nogueiralegacy.truststore.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

/**
 * Propriedades de configuração para o trust store ICP-Brasil.
 * Esta classe gerencia todas as configurações necessárias para download,
 * validação e armazenamento dos certificados do trust store ICP-Brasil.
 */
@Data
@Slf4j
@Component
@ConfigurationProperties(prefix = "truststore.icp-brasil")
public class TrustStoreConfig {

    /**
     * URL do arquivo de certificados (trust store ICP-Brasil)
     */
    private String certificateUrl;

    /**
     * URL do arquivo contendo o hash do arquivo de certificados
     */
    private String hashUrl;

    /**
     * Configurações de rede
     */
    private NetworkConfig network;

    /**
     * TTL do cache de consulta em horas (padrão 24 horas, intervalo [1, 168])
     */
    private int cacheTtlHours = 24;

    /**
     * Período para recuperação de trust store atualizado em horas
     */
    private int refreshIntervalHours = 2;

    /**
     * Certificados LetsEncrypt de CA (Certificate Authority).
     * Necessários para validar certificado do site https://acraiz.icpbrasil.gov.br/
     */
    private Map<String, String> certificates = new LetsEncryptProperties().getCertificates();


    /**
     * Configurações de rede para download
     */
    @Data
    public static class NetworkConfig {
        /**
         * Timeout de download em segundos (padrão 60, intervalo [30, 300])
         */
        private int downloadTimeoutSeconds = 60;

        /**
         * Número máximo de tentativas (padrão 3, intervalo [1, 10])
         */
        private int maxRetries = 3;

        /**
         * Intervalo entre tentativas em segundos (padrão 30, intervalo [10, 300])
         */
        private int retryIntervalSeconds = 30;
    }

    /**
     * Valida todas as propriedades após a inicialização do bean.
     * 
     * @throws IllegalStateException se alguma configuração for inválida
     */
    @PostConstruct
    public void validateProperties() {
        log.info("Iniciando validação das propriedades do trust store ICP-Brasil");

        validateUrls();
        validateNetworkConfig();
        validateCacheConfig();
    }

    /**
     * Valida as URLs de certificado e hash
     */
    private void validateUrls() {
        // Validar URL do certificado
        if (!StringUtils.hasText(certificateUrl)) {
            throw new IllegalStateException("URL do certificado ICP-Brasil não pode ser null ou vazia. " +
                    "Configure a propriedade 'truststore.icp-brasil.certificate-url'");
        }

        validateUrl(certificateUrl, "URL do certificado");

        // Validar URL do hash
        if (!StringUtils.hasText(hashUrl)) {
            throw new IllegalStateException("URL do hash do certificado ICP-Brasil não pode ser null ou vazia. " +
                    "Configure a propriedade 'truststore.icp-brasil.hash-url'");
        }

        validateUrl(hashUrl, "URL do hash");

        log.debug("URLs validadas com sucesso");
    }

    /**
     * Valida se uma URL é válida e usa HTTPS
     */
    private void validateUrl(String urlString, String description) {
        try {
            URL url = new URL(urlString);
            
            if (!"https".equalsIgnoreCase(url.getProtocol())) {
                throw new IllegalStateException(description + " deve usar protocolo HTTPS por segurança. " +
                        "URL fornecida: " + urlString);
            }

        } catch (MalformedURLException e) {
            throw new IllegalStateException(description + " é inválida: " + urlString, e);
        }
    }

    /**
     * Valida as configurações de rede
     */
    private void validateNetworkConfig() {
        if (network == null) {
            network = new NetworkConfig();
            log.warn("Configurações de rede não definidas, usando valores padrão");
        }

        // Validar timeout de download (30-300 segundos)
        if (network.downloadTimeoutSeconds < 30 || network.downloadTimeoutSeconds > 300) {
            throw new IllegalStateException("Timeout de download deve estar entre 30 e 300 segundos. " +
                    "Valor atual: " + network.downloadTimeoutSeconds);
        }

        // Validar número máximo de tentativas (1-10)
        if (network.maxRetries < 1 || network.maxRetries > 10) {
            throw new IllegalStateException("Número máximo de tentativas deve estar entre 1 e 10. " +
                    "Valor atual: " + network.maxRetries);
        }

        // Validar intervalo entre tentativas (10-300 segundos)
        if (network.retryIntervalSeconds < 10 || network.retryIntervalSeconds > 300) {
            throw new IllegalStateException("Intervalo entre tentativas deve estar entre 10 e 300 segundos. " +
                    "Valor atual: " + network.retryIntervalSeconds);
        }

        log.debug("Configurações de rede validadas com sucesso");
    }

    /**
     * Valida as configurações de cache
     */
    private void validateCacheConfig() {
        // Validar TTL do cache (1-168 horas)
        if (cacheTtlHours < 1 || cacheTtlHours > 168) {
            throw new IllegalStateException("TTL do cache deve estar entre 1 e 168 horas. " +
                    "Valor atual: " + cacheTtlHours);
        }

        // Validar intervalo de refresh (deve ser positivo)
        if (refreshIntervalHours < 1) {
            throw new IllegalStateException("Intervalo de refresh deve ser pelo menos 1 hora. " +
                    "Valor atual: " + refreshIntervalHours);
        }

        log.debug("Configurações de cache validadas com sucesso");
    }

    /**
     * Retorna o timeout de download em milissegundos
     */
    public long getDownloadTimeoutMillis() {
        return network.downloadTimeoutSeconds * 1000L;
    }

    /**
     * Retorna o intervalo entre tentativas em milissegundos
     */
    public long getRetryIntervalMillis() {
        return network.retryIntervalSeconds * 1000L;
    }

    /**
     * Retorna o TTL do cache em milissegundos
     */
    public long getCacheTtlMillis() {
        return cacheTtlHours * 60 * 60 * 1000L;
    }

    /**
     * Retorna o intervalo de refresh em milissegundos
     */
    public long getRefreshIntervalMillis() {
        return refreshIntervalHours * 60 * 60 * 1000L;
    }
}