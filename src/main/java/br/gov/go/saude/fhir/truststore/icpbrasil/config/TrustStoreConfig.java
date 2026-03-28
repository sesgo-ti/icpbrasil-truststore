package br.gov.go.saude.fhir.truststore.icpbrasil.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Propriedades de configuração para o TrustStore ICP-Brasil.
 * Esta classe gerencia todas as configurações necessárias para download,
 * validação e armazenamento dos certificados do TrustStore ICP-Brasil.
 */
@Data
@Slf4j
@ConfigurationProperties(prefix = "truststore-icpbrasil")
public class TrustStoreConfig {

    /**
     * URL do arquivo de certificados (Trust Store ICP-Brasil).
     * [Resultado]: Define de onde o sistema baixa as atualizações.
     */
    private String certificateUrl;

    /**
     * URL do arquivo contendo o hash do arquivo de certificados.
     * [Resultado]: Usado para verificar a integridade do download.
     */
    private String hashUrl;

    /**
     * Configurações de Rede e Resiliência.
     * [Resultado]: Controla o comportamento em caso de falha na conexão.
     */
    private NetworkConfig network;

    /**
     * TTL crítico do cache em horas (usado para alertas).
     * [Resultado]: Tempo sem atualização para entrar em estado CRÍTICO.
     */
    private int cacheTtlCriticalHours;

    /**
     * TTL máximo do cache em horas (usado para alertas).
     * [Resultado]: Tempo máximo de vida do cache antes de expirar.
     */
    private int cacheTtlMaxHours;

    /**
     * Período para recuperação de Trust Store atualizado em horas.
     * [Resultado]: Frequência de verificação de novas atualizações.
     */
    private int refreshIntervalHours;

    /**
     * Estratégia de Armazenamento.
     * [Resultado]: Define se os artefatos ficam em disco local ou na nuvem (S3/MinIO).
     */
    private StorageConfig storage;

    /**
     * Diretório de Certificados Confiáveis Fixos.
     * [Resultado]: Local onde o sistema busca certificados adicionais (JSON).
     */
    private TrustedCertsConfig trustedCerts;

    /**
     * Configurações de armazenamento genérico (S3, MinIO, FileSystem, etc.)
     */
    @Data
    public static class StorageConfig {
        /**
         * Nome do bucket de armazenamento (necessário para storage.type=minio).
         */
        private String bucketName;

        /**
         * Diretório base para armazenamento no filesystem (usado quando storage.type=filesystem).
         */
        private String filesystemBaseDir;

        /**
         * Caminho do arquivo compactado do truststore.
         */
        private String truststoreArchivePath;

        /**
         * Caminho do arquivo de hash.
         */
        private String hashFilePath;

        /**
         * Caminho do arquivo de última confirmação.
         */
        private String confirmationFilePath;
    }

    /**
     * Configurações de certificados confiáveis no filesystem
     */
    @Data
    public static class TrustedCertsConfig {
        /**
         * Diretório contendo os arquivos JSON de certificados confiáveis (classpath ou disco).
         */
        private String dir;
    }

    /**
     * Configurações de rede para download
     */
    @Data
    public static class NetworkConfig {
        /**
         * Timeout de download em segundos (padrão 60, intervalo [30, 300]).
         */
        private int downloadTimeoutSeconds;

        /**
         * Número máximo de tentativas (padrão 3, intervalo [1, 10]).
         */
        private int maxRetries;

        /**
         * Intervalo entre tentativas em segundos (padrão 30, intervalo [10, 300]).
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
        log.info("Iniciando validação das propriedades de configuração do TrustStore ICP-Brasil");

        validateUrls();
        validateNetworkConfig();
        validateCacheConfig();
        validateStorageConfig();

        log.info("Validação das propriedades de configuração concluída com sucesso - Sistema pronto para operação");
    }

    /**
     * Valida as URLs de certificado e hash
     */
    private void validateUrls() {
        if (!StringUtils.hasText(certificateUrl)) {
            throw new IllegalStateException("[Erro de Configuração] URL do Certificado: Não pode ser nulo ou vazio. Propriedade: 'truststore-icpbrasil.certificate-url'");
        }

        validateUrl(certificateUrl, "URL do Certificado", "truststore-icpbrasil.certificate-url");

        if (!StringUtils.hasText(hashUrl)) {
            throw new IllegalStateException("[Erro de Configuração] URL do Hash: Não pode ser nulo ou vazio. Propriedade: 'truststore-icpbrasil.hash-url'");
        }

        validateUrl(hashUrl, "URL do Hash", "truststore-icpbrasil.hash-url");

        log.debug("URLs validadas com sucesso");
    }

    /**
     * Valida se uma URL é válida e usa HTTPS
     */
    private void validateUrl(String urlString, String description, String propertyName) {
        try {
            URI uri = new URI(urlString);

            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                throw new IllegalStateException(String.format("[Erro de Configuração] %s: Deve usar protocolo HTTPS por segurança. Propriedade: '%s' (Valor: '%s')",
                        description, propertyName, urlString));
            }

            if (!uri.isAbsolute() || uri.getHost() == null) {
                throw new IllegalStateException(String.format("[Erro de Configuração] %s: Deve ser uma URL absoluta válida com host. Propriedade: '%s' (Valor: '%s')",
                        description, propertyName, urlString));
            }
        } catch (URISyntaxException e) {
            throw new IllegalStateException(String.format("[Erro de Configuração] %s: URL inválida. Propriedade: '%s' (Valor: '%s')",
                    description, propertyName, urlString), e);
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
            throw new IllegalStateException(String.format("[Erro de Configuração] Timeout de Download: Deve ser entre 30 e 300 segundos. Propriedade: 'truststore-icpbrasil.network.download-timeout-seconds' (Valor: '%d')",
                    network.downloadTimeoutSeconds));
        }

        // Validar número máximo de tentativas (1-10)
        if (network.maxRetries < 1 || network.maxRetries > 10) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Máximo de Tentativas: Deve ser entre 1 e 10. Propriedade: 'truststore-icpbrasil.network.max-retries' (Valor: '%d')",
                    network.maxRetries));
        }

        // Validar intervalo entre tentativas (10-300 segundos)
        if (network.retryIntervalSeconds < 10 || network.retryIntervalSeconds > 300) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Intervalo entre Tentativas: Deve ser entre 10 e 300 segundos. Propriedade: 'truststore-icpbrasil.network.retry-interval-seconds' (Valor: '%d')",
                    network.retryIntervalSeconds));
        }

        log.debug("Configurações de rede validadas com sucesso");
    }

    /**
     * Valida as configurações de cache
     */
    private void validateCacheConfig() {
        if (cacheTtlCriticalHours < 24 || cacheTtlCriticalHours > 168) {
            throw new IllegalStateException(String.format("[Erro de Configuração] TTL Crítico: Deve ser entre 24 e 168 horas. Propriedade: 'truststore-icpbrasil.cache-ttl-critical-hours' (Valor: '%d')",
                    cacheTtlCriticalHours));
        }

        if (cacheTtlMaxHours < 72 || cacheTtlMaxHours > 720) {
            throw new IllegalStateException(String.format("[Erro de Configuração] TTL Máximo: Deve ser entre 168 e 720 horas. Propriedade: 'truststore-icpbrasil.cache-ttl-max-hours' (Valor: '%d')",
                    cacheTtlMaxHours));
        }

        if (cacheTtlMaxHours <= cacheTtlCriticalHours) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Regra de TTL: TTL Máximo deve ser maior que TTL Crítico. Propriedades: '...cache-ttl-max-hours' (%d) e '...cache-ttl-critical-hours' (%d)",
                    cacheTtlMaxHours, cacheTtlCriticalHours));
        }

//        // Validar TTL do cache (1-168 horas)
//        if (cacheTtlHours < 24 || cacheTtlHours > 168) {
//            throw new IllegalStateException("TTL do cache deve estar entre 1 e 168 horas. " +
//                    "Valor atual: " + cacheTtlHours);
//        }

        // Validar intervalo de refresh (deve ser positivo)
        if (refreshIntervalHours < 1 || refreshIntervalHours > cacheTtlCriticalHours) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Intervalo de Refresh: Deve estar entre 1 e o TTL Crítico (%d). Propriedade: 'truststore-icpbrasil.refresh-interval-hours' (Valor: '%d')",
                    cacheTtlCriticalHours, refreshIntervalHours));
        }

        log.debug("Configurações de cache validadas com sucesso");
    }

    /**
     * Valida as configurações de armazenamento
     */
    private void validateStorageConfig() {
        if (storage == null) {
            throw new IllegalStateException("[Erro de Configuração] Storage: As configurações de armazenamento não podem ser nulas. Propriedade: 'truststore-icpbrasil.storage.*'");
        }

        if (!StringUtils.hasText(storage.getBucketName())) {
            throw new IllegalStateException("[Erro de Configuração] Nome do Bucket: Não pode ser nulo ou vazio. Propriedade: 'truststore-icpbrasil.storage.bucket-name'");
        }

        if (!StringUtils.hasText(storage.truststoreArchivePath)) {
            throw new IllegalStateException("[Erro de Configuração] Caminho do Arquivo ZIP: Não pode ser nulo ou vazio. Propriedade: 'truststore-icpbrasil.storage.truststore-archive-path'");
        }

        if (!StringUtils.hasText(storage.hashFilePath)) {
            throw new IllegalStateException("[Erro de Configuração] Caminho do Arquivo Hash: Não pode ser nulo ou vazio. Propriedade: 'truststore-icpbrasil.storage.hash-file-path'");
        }

        if (!StringUtils.hasText(storage.confirmationFilePath)) {
            throw new IllegalStateException("[Erro de Configuração] Caminho da Confirmação: Não pode ser nulo ou vazio. Propriedade: 'truststore-icpbrasil.storage.confirmation-file-path'");
        }

        log.debug("Configurações de storage validadas com sucesso");
    }

    /**
     * Retorna o intervalo de refresh em milissegundos
     */
    public long getRefreshIntervalMillis() {
        return refreshIntervalHours * 60 * 60 * 1000L;
    }

    /**
     * Retorna o TTL crítico do cache em milissegundos
     */
    public long getCacheTtlCriticalMillis() {
        return cacheTtlCriticalHours * 60 * 60 * 1000L;
    }

    /**
     * Retorna o TTL máximo do cache em milissegundos
     */
    public long getCacheTtlMaxMillis() {
        return cacheTtlMaxHours * 60 * 60 * 1000L;
    }
}