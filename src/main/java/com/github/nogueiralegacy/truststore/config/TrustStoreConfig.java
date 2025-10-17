package com.github.nogueiralegacy.truststore.config;

import io.minio.MinioClient;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Propriedades de configuração para o trust store ICP-Brasil.
 * Esta classe gerencia todas as configurações necessárias para download,
 * validação e armazenamento dos certificados do trust store ICP-Brasil.
 */
@Data
@Slf4j
@ConfigurationProperties(prefix = "truststore")
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
    private int cacheTtlHours;

    /**
     * Período para recuperação de trust store atualizado em horas, inteiros positivos
     */
    private int refreshIntervalHours;

    /**
     * Configurações de armazenamento no MinIO
     */
    private StorageConfig storage;

    @Autowired
    private MinioClient minIOClient;

    @Autowired
    private VaultProperties vaultProperties;

    /**
     * Configurações de armazenamento genérico (S3, MinIO, FileSystem, etc.)
     */
    @Data
    public static class StorageConfig {
        /**
         * Nome do container de armazenamento (bucket no S3/MinIO, diretório no FileSystem)
         */
        private String containerName;

        /**
         * Caminho do arquivo compactado do truststore
         */
        private String truststoreArchivePath;

        /**
         * Caminho do arquivo de hash
         */
        private String hashFilePath;

        /**
         * Caminho do arquivo de última confirmação
         */
        private String confirmationFilePath;
    }

    /**
     * Configurações de rede para download
     */
    @Data
    public static class NetworkConfig {
        /**
         * Timeout de download em segundos (padrão 60, intervalo [30, 300])
         */
        private int downloadTimeoutSeconds;

        /**
         * Número máximo de tentativas (padrão 3, intervalo [1, 10])
         */
        private int maxRetries;

        /**
         * Intervalo entre tentativas em segundos (padrão 30, intervalo [10, 300])
         */
        private int retryIntervalSeconds;

        /**
         * Retorna o timeout de download em milissegundos
         */
        public int getDownloadTimeoutMillis() {
            return downloadTimeoutSeconds * 1000;
        }

        /**
         * Retorna o intervalo entre tentativas em milissegundos
         */
        public int getRetryIntervalMillis() {
            return retryIntervalSeconds * 1000;
        }

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
        validateStorageConfig();
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
            URI uri = new URI(urlString);

            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                throw new IllegalStateException(description + " deve usar protocolo HTTPS por segurança. " +
                        "URL fornecida: " + urlString);
            }

            if (!uri.isAbsolute() || uri.getHost() == null) {
                throw new IllegalStateException(description + " deve ser uma URL absoluta válida com host. " +
                        "URL fornecida: " + urlString);
            }
        } catch (URISyntaxException e) {
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
     * Valida as configurações de armazenamento
     */
    private void validateStorageConfig() {
        if (storage == null) {
            throw new IllegalStateException("Configurações de storage não podem ser null. " +
                    "Configure as propriedades 'truststore.icp-brasil.storage.*'");
        }

        if (!StringUtils.hasText(storage.containerName)) {
            throw new IllegalStateException("Nome do container não pode ser null ou vazio. " +
                    "Configure a propriedade 'truststore.icp-brasil.storage.container-name'");
        }

        if (!StringUtils.hasText(storage.truststoreArchivePath)) {
            throw new IllegalStateException("Caminho do arquivo compactado não pode ser null ou vazio. " +
                    "Configure a propriedade 'truststore.icp-brasil.storage.truststore-archive-path'");
        }

        if (!StringUtils.hasText(storage.hashFilePath)) {
            throw new IllegalStateException("Caminho do arquivo de hash não pode ser null ou vazio. " +
                    "Configure a propriedade 'truststore.icp-brasil.storage.hash-file-path'");
        }

        if (!StringUtils.hasText(storage.confirmationFilePath)) {
            throw new IllegalStateException("Caminho do arquivo de confirmação não pode ser null ou vazio. " +
                    "Configure a propriedade 'truststore.icp-brasil.storage.confirmation-file-path'");
        }

        log.debug("Configurações de storage validadas com sucesso");
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