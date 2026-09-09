package br.gov.go.saude.truststore.icpbrasil.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Security;
import java.util.List;

/**
 * Propriedades de configuração para o TrustStore ICP-Brasil.
 * Esta classe gerencia todas as configurações necessárias para download,
 * validação e armazenamento dos certificados do TrustStore ICP-Brasil.
 *
 * <p>Os valores iniciais dos campos são os defaults da biblioteca: uma aplicação
 * consumidora precisa informar apenas o que não tem default (hoje, o diretório base
 * do storage filesystem). {@link #validateProperties()} valida o resultado final
 * do binding, com ou sem sobrescrita.</p>
 */
@Data
@Slf4j
public class TrustStoreConfig {

    // BouncyCastle é necessário para operações OCSP e CRL (assinaturas, parsing de extensões).
    // O registro deve ocorrer antes de qualquer uso, por isso fica no bloco estático da config.
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * URL do arquivo de certificados (Trust Store ICP-Brasil).
     * [Resultado]: Define de onde o sistema baixa as atualizações.
     */
    private String certificateUrl =
            "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip";

    /**
     * URL do arquivo contendo o hash do arquivo de certificados.
     * [Resultado]: Usado para verificar a integridade do download.
     */
    private String hashUrl =
            "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt";

    /**
     * Configurações de Rede e Resiliência.
     * [Resultado]: Controla o comportamento em caso de falha na conexão.
     */
    private NetworkConfig network = new NetworkConfig();

    /**
     * TTL crítico do cache em horas (usado para alertas).
     * [Resultado]: Tempo sem atualização para entrar em estado CRÍTICO.
     */
    private int cacheTtlCriticalHours = 72;

    /**
     * TTL máximo do cache em horas (usado para alertas).
     * [Resultado]: Tempo máximo de vida do cache antes de expirar.
     */
    private int cacheTtlMaxHours = 168;

    /**
     * Período para recuperação de Trust Store atualizado em horas.
     * [Resultado]: Frequência de verificação de novas atualizações.
     */
    private int refreshIntervalHours = 2;

    /**
     * Estratégia de Armazenamento.
     * [Resultado]: Define se os artefatos ficam em disco local ou na nuvem (S3-compatível).
     */
    private StorageConfig storage = new StorageConfig();

    /**
     * Configurações específicas para armazenamento no filesystem local.
     * Ativado quando storage.type=filesystem.
     */
    private FilesystemConfig filesystem = new FilesystemConfig();

    /**
     * Diretório de Certificados Confiáveis Fixos.
     * [Resultado]: Local onde o sistema busca certificados adicionais (JSON).
     */
    private TrustedCertsConfig trustedCerts = new TrustedCertsConfig();

    /**
     * Configurações de verificação de revogação (OCSP e CRL).
     */
    private RevocationConfig revocation = new RevocationConfig();

    /**
     * Configurações de montagem de cadeia de certificados via AIA CA Issuers.
     */
    private ChainConfig chain = new ChainConfig();

    /**
     * Configurações de política de download (proteção SSRF e limites de tamanho).
     */
    private DownloadPolicyConfig downloadPolicy = new DownloadPolicyConfig();

    /**
     * Configurações do bootstrap síncrono (carga do cache durante o startup).
     */
    private BootstrapConfig bootstrap = new BootstrapConfig();

    /**
     * Configurações de armazenamento — caminhos dos artefatos (comuns a todos os tipos).
     */
    @Data
    public static class StorageConfig {
        /**
         * Tipo de armazenamento (filesystem | s3).
         */
        private String type = "filesystem";

        /**
         * Caminho do arquivo compactado do truststore.
         */
        private String truststoreArchivePath = "ACcompactado.zip";

        /**
         * Caminho do arquivo de hash.
         */
        private String hashFilePath = "hash.txt";

        /**
         * Caminho do arquivo de última confirmação.
         */
        private String confirmationFilePath = "ultima_confirmacao.txt";
    }

    /**
     * Configurações específicas para o storage filesystem local.
     */
    @Data
    public static class FilesystemConfig {
        /**
         * Diretório base onde os artefatos são armazenados no disco.
         * Sem default: cada aplicação define onde o acervo pode ser gravado.
         */
        private String baseDir;
    }

    /**
     * Configurações de certificados confiáveis no filesystem
     */
    @Data
    public static class TrustedCertsConfig {
        /**
         * Diretório contendo os arquivos JSON de certificados confiáveis (classpath ou disco).
         */
        private String dir = "classpath:registries/certificates";
    }

    /**
     * Configurações de rede para download
     */
    @Data
    public static class NetworkConfig {
        /**
         * Timeout de download em segundos (padrão 60, intervalo [30, 300]).
         */
        private int downloadTimeoutSeconds = 60;

        /**
         * Número máximo de tentativas (padrão 3, intervalo [1, 10]).
         */
        private int maxRetries = 3;

        /**
         * Intervalo entre tentativas em segundos (padrão 30, intervalo [10, 300]).
         */
        private int retryIntervalSeconds = 30;

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
     * Valida todas as propriedades.
     *
     * @throws IllegalStateException se alguma configuração for inválida
     */
    public void validateProperties() {
        log.info("Iniciando validação das propriedades de configuração do TrustStore ICP-Brasil");

        validateUrls();
        validateNetworkConfig();
        validateCacheConfig();
        validateStorageConfig();
        validateRevocationConfig();
        validateChainConfig();
        validateDownloadPolicyConfig();
        validateBootstrapConfig();

        log.info("Validação das propriedades de configuração concluída com sucesso - Sistema pronto para operação");
    }

    /**
     * Valida as configurações do bootstrap síncrono.
     */
    private void validateBootstrapConfig() {
        if (bootstrap == null) {
            bootstrap = new BootstrapConfig();
            log.info("Configurações de bootstrap não definidas, usando valores padrão");
            return;
        }

        log.debug("Configurações de bootstrap validadas com sucesso");
    }

    /**
     * Valida as URLs de certificado e hash
     */
    private void validateUrls() {
        if (certificateUrl == null || certificateUrl.isBlank()) {
            throw new IllegalStateException("[Erro de Configuração] URL do Certificado: Não pode ser nulo ou vazio. Propriedade: 'icpbrasil-truststore.certificate-url'");
        }

        validateUrl(certificateUrl, "URL do Certificado", "icpbrasil-truststore.certificate-url");

        if (hashUrl == null || hashUrl.isBlank()) {
            throw new IllegalStateException("[Erro de Configuração] URL do Hash: Não pode ser nulo ou vazio. Propriedade: 'icpbrasil-truststore.hash-url'");
        }

        validateUrl(hashUrl, "URL do Hash", "icpbrasil-truststore.hash-url");

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
            throw new IllegalStateException(String.format("[Erro de Configuração] Timeout de Download: Deve ser entre 30 e 300 segundos. Propriedade: 'icpbrasil-truststore.network.download-timeout-seconds' (Valor: '%d')",
                    network.downloadTimeoutSeconds));
        }

        // Validar número máximo de tentativas (1-10)
        if (network.maxRetries < 1 || network.maxRetries > 10) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Máximo de Tentativas: Deve ser entre 1 e 10. Propriedade: 'icpbrasil-truststore.network.max-retries' (Valor: '%d')",
                    network.maxRetries));
        }

        // Validar intervalo entre tentativas (10-300 segundos)
        if (network.retryIntervalSeconds < 10 || network.retryIntervalSeconds > 300) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Intervalo entre Tentativas: Deve ser entre 10 e 300 segundos. Propriedade: 'icpbrasil-truststore.network.retry-interval-seconds' (Valor: '%d')",
                    network.retryIntervalSeconds));
        }

        log.debug("Configurações de rede validadas com sucesso");
    }

    /**
     * Valida as configurações de cache
     */
    private void validateCacheConfig() {
        if (cacheTtlCriticalHours < 24 || cacheTtlCriticalHours > 168) {
            throw new IllegalStateException(String.format("[Erro de Configuração] TTL Crítico: Deve ser entre 24 e 168 horas. Propriedade: 'icpbrasil-truststore.cache-ttl-critical-hours' (Valor: '%d')",
                    cacheTtlCriticalHours));
        }

        if (cacheTtlMaxHours < 72 || cacheTtlMaxHours > 720) {
            throw new IllegalStateException(String.format("[Erro de Configuração] TTL Máximo: Deve ser entre 168 e 720 horas. Propriedade: 'icpbrasil-truststore.cache-ttl-max-hours' (Valor: '%d')",
                    cacheTtlMaxHours));
        }

        if (cacheTtlMaxHours <= cacheTtlCriticalHours) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Regra de TTL: TTL Máximo deve ser maior que TTL Crítico. Propriedades: '...cache-ttl-max-hours' (%d) e '...cache-ttl-critical-hours' (%d)",
                    cacheTtlMaxHours, cacheTtlCriticalHours));
        }

        // Validar intervalo de refresh (deve ser positivo)
        if (refreshIntervalHours < 1 || refreshIntervalHours > cacheTtlCriticalHours) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Intervalo de Refresh: Deve estar entre 1 e o TTL Crítico (%d). Propriedade: 'icpbrasil-truststore.refresh-interval-hours' (Valor: '%d')",
                    cacheTtlCriticalHours, refreshIntervalHours));
        }

        log.debug("Configurações de cache validadas com sucesso");
    }

    /**
     * Valida as configurações de armazenamento
     */
    private void validateStorageConfig() {
        if (storage == null) {
            throw new IllegalStateException("[Erro de Configuração] Storage: As configurações de armazenamento não podem ser nulas. Propriedade: 'icpbrasil-truststore.storage.*'");
        }

        if ("filesystem".equalsIgnoreCase(storage.getType()) && (filesystem == null || filesystem.getBaseDir() == null || filesystem.getBaseDir().isBlank())) {
            throw new IllegalStateException("[Erro de Configuração] Filesystem Base Dir: Não pode ser nulo ou vazio quando storage.type=filesystem. Propriedade: 'icpbrasil-truststore.filesystem.base-dir'");
        }

        if (storage.truststoreArchivePath == null || storage.truststoreArchivePath.isBlank()) {
            throw new IllegalStateException("[Erro de Configuração] Caminho do Arquivo ZIP: Não pode ser nulo ou vazio. Propriedade: 'icpbrasil-truststore.storage.truststore-archive-path'");
        }

        if (storage.hashFilePath == null || storage.hashFilePath.isBlank()) {
            throw new IllegalStateException("[Erro de Configuração] Caminho do Arquivo Hash: Não pode ser nulo ou vazio. Propriedade: 'icpbrasil-truststore.storage.hash-file-path'");
        }

        if (storage.confirmationFilePath == null || storage.confirmationFilePath.isBlank()) {
            throw new IllegalStateException("[Erro de Configuração] Caminho da Confirmação: Não pode ser nulo ou vazio. Propriedade: 'icpbrasil-truststore.storage.confirmation-file-path'");
        }

        log.debug("Configurações de storage validadas com sucesso");
    }

    /**
     * Valida as configurações de revogação
     */
    private void validateRevocationConfig() {
        if (revocation == null) {
            revocation = new RevocationConfig();
            log.info("Configurações de revogação não definidas, usando valores padrão");
            return;
        }

        if (revocation.ocspTimeoutSeconds < 1 || revocation.ocspTimeoutSeconds > 60) {
            throw new IllegalStateException(String.format("[Erro de Configuração] OCSP Timeout: Deve ser entre 1 e 60 segundos. Propriedade: 'icpbrasil-truststore.revocation.ocsp-timeout-seconds' (Valor: '%d')",
                    revocation.ocspTimeoutSeconds));
        }

        if (revocation.crlTimeoutSeconds < 1 || revocation.crlTimeoutSeconds > 60) {
            throw new IllegalStateException(String.format("[Erro de Configuração] CRL Timeout: Deve ser entre 1 e 60 segundos. Propriedade: 'icpbrasil-truststore.revocation.crl-timeout-seconds' (Valor: '%d')",
                    revocation.crlTimeoutSeconds));
        }

        if (revocation.maxRetries < 0 || revocation.maxRetries > 10) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Revocation Max Retries: Deve ser entre 0 e 10. Propriedade: 'icpbrasil-truststore.revocation.max-retries' (Valor: '%d')",
                    revocation.maxRetries));
        }

        if (revocation.retryIntervalSeconds < 1 || revocation.retryIntervalSeconds > 60) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Revocation Retry Interval: Deve ser entre 1 e 60 segundos. Propriedade: 'icpbrasil-truststore.revocation.retry-interval-seconds' (Valor: '%d')",
                    revocation.retryIntervalSeconds));
        }

        if (revocation.ocspCacheTtlSeconds < 60 || revocation.ocspCacheTtlSeconds > 86400) {
            throw new IllegalStateException(String.format("[Erro de Configuração] OCSP Cache TTL: Deve ser entre 60 e 86400 segundos. Propriedade: 'icpbrasil-truststore.revocation.ocsp-cache-ttl-seconds' (Valor: '%d')",
                    revocation.ocspCacheTtlSeconds));
        }

        if (revocation.crlCacheTtlSeconds < 60 || revocation.crlCacheTtlSeconds > 86400) {
            throw new IllegalStateException(String.format("[Erro de Configuração] CRL Cache TTL: Deve ser entre 60 e 86400 segundos. Propriedade: 'icpbrasil-truststore.revocation.crl-cache-ttl-seconds' (Valor: '%d')",
                    revocation.crlCacheTtlSeconds));
        }

        if (revocation.ocspCacheMaxSize < 100 || revocation.ocspCacheMaxSize > 1_000_000) {
            throw new IllegalStateException(String.format("[Erro de Configuração] OCSP Cache Max Size: Deve ser entre 100 e 1000000. Propriedade: 'icpbrasil-truststore.revocation.ocsp-cache-max-size' (Valor: '%d')",
                    revocation.ocspCacheMaxSize));
        }

        if (revocation.crlCacheMaxSize < 100 || revocation.crlCacheMaxSize > 100_000) {
            throw new IllegalStateException(String.format("[Erro de Configuração] CRL Cache Max Size: Deve ser entre 100 e 100000. Propriedade: 'icpbrasil-truststore.revocation.crl-cache-max-size' (Valor: '%d')",
                    revocation.crlCacheMaxSize));
        }

        log.debug("Configurações de revogação validadas com sucesso");
    }

    /**
     * Valida as configurações de montagem de cadeia
     */
    private void validateChainConfig() {
        if (chain == null) {
            chain = new ChainConfig();
            log.info("Configurações de cadeia não definidas, usando valores padrão");
            return;
        }

        if (chain.downloadTimeoutSeconds < 1 || chain.downloadTimeoutSeconds > 60) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Chain Download Timeout: Deve ser entre 1 e 60 segundos. Propriedade: 'icpbrasil-truststore.chain.download-timeout-seconds' (Valor: '%d')",
                    chain.downloadTimeoutSeconds));
        }

        if (chain.maxRetries < 0 || chain.maxRetries > 5) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Chain Max Retries: Deve ser entre 0 e 5. Propriedade: 'icpbrasil-truststore.chain.max-retries' (Valor: '%d')",
                    chain.maxRetries));
        }

        if (chain.retryIntervalSeconds < 1 || chain.retryIntervalSeconds > 30) {
            throw new IllegalStateException(String.format("[Erro de Configuração] Chain Retry Interval: Deve ser entre 1 e 30 segundos. Propriedade: 'icpbrasil-truststore.chain.retry-interval-seconds' (Valor: '%d')",
                    chain.retryIntervalSeconds));
        }

        log.debug("Configurações de cadeia validadas com sucesso");
    }

    /**
     * Valida as configurações de política de download.
     */
    private void validateDownloadPolicyConfig() {
        if (downloadPolicy == null) {
            downloadPolicy = new DownloadPolicyConfig();
            log.info("Configurações de política de download não definidas, usando valores padrão");
            return;
        }

        if (downloadPolicy.maxOcspResponseBytes < 1024 || downloadPolicy.maxOcspResponseBytes > 10_485_760L) {
            throw new IllegalStateException(String.format(
                    "[Erro de Configuração] Download Policy OCSP Max Size: Deve ser entre 1024 e 10485760 bytes. " +
                    "Propriedade: 'icpbrasil-truststore.download-policy.max-ocsp-response-bytes' (Valor: '%d')",
                    downloadPolicy.maxOcspResponseBytes));
        }

        if (downloadPolicy.maxCrlResponseBytes < 1024 || downloadPolicy.maxCrlResponseBytes > 524_288_000L) {
            throw new IllegalStateException(String.format(
                    "[Erro de Configuração] Download Policy CRL Max Size: Deve ser entre 1024 e 524288000 bytes. " +
                    "Propriedade: 'icpbrasil-truststore.download-policy.max-crl-response-bytes' (Valor: '%d')",
                    downloadPolicy.maxCrlResponseBytes));
        }

        if (downloadPolicy.maxAiaResponseBytes < 1024 || downloadPolicy.maxAiaResponseBytes > 104_857_600L) {
            throw new IllegalStateException(String.format(
                    "[Erro de Configuração] Download Policy AIA Max Size: Deve ser entre 1024 e 104857600 bytes. " +
                    "Propriedade: 'icpbrasil-truststore.download-policy.max-aia-response-bytes' (Valor: '%d')",
                    downloadPolicy.maxAiaResponseBytes));
        }

        log.debug("Configurações de política de download validadas com sucesso");
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

    /**
     * Configurações de verificação de revogação (OCSP e CRL).
     */
    @Data
    public static class RevocationConfig {
        /**
         * Timeout da requisição OCSP em segundos (padrão 10, intervalo [1, 60]).
         */
        private int ocspTimeoutSeconds = 10;

        /**
         * Timeout da requisição CRL em segundos (padrão 10, intervalo [1, 60]).
         */
        private int crlTimeoutSeconds = 10;

        /**
         * Número máximo de tentativas (padrão 2, intervalo [0, 10]).
         */
        private int maxRetries = 2;

        /**
         * Intervalo entre tentativas em segundos (padrão 3, intervalo [1, 60]).
         */
        private int retryIntervalSeconds = 3;

        /**
         * TTL do cache OCSP em segundos (padrão 3600 = 1h, intervalo [60, 86400]).
         */
        private long ocspCacheTtlSeconds = 3600;

        /**
         * TTL do cache CRL em segundos (padrão 3600 = 1h, intervalo [60, 86400]).
         */
        private long crlCacheTtlSeconds = 3600;

        /**
         * Tamanho máximo do cache OCSP em número de entradas (padrão 10000, intervalo [100, 1000000]).
         */
        private long ocspCacheMaxSize = 10_000;

        /**
         * Tamanho máximo do cache CRL em número de entradas (padrão 1000, intervalo [100, 100000]).
         */
        private long crlCacheMaxSize = 1_000;
    }

    /**
     * Configurações de montagem de cadeia de certificados via AIA CA Issuers.
     */
    @Data
    public static class ChainConfig {
        /**
         * Timeout do download de certificados via AIA em segundos (padrão 10, intervalo [1, 60]).
         */
        private int downloadTimeoutSeconds = 10;

        /**
         * Número máximo de retries por URL (padrão 1, intervalo [0, 5]).
         */
        private int maxRetries = 1;

        /**
         * Intervalo entre tentativas em segundos (padrão 2, intervalo [1, 30]).
         */
        private int retryIntervalSeconds = 2;
    }

    /**
     * Política de segurança para downloads iniciados por URLs extraídas de certificados.
     * Protege contra SSRF e consumo abusivo de memória.
     */
    @Data
    public static class DownloadPolicyConfig {

        /**
         * Tamanho máximo da resposta OCSP em bytes (padrão 1 MB, intervalo [1024, 10485760]).
         * Respostas típicas de OCSP têm menos de 10 KB.
         */
        private long maxOcspResponseBytes = 1_048_576L;

        /**
         * Tamanho máximo da CRL em bytes (padrão 50 MB, intervalo [1024, 524288000]).
         * CRLs do ICP-Brasil podem chegar a alguns MB; 50 MB é um limite de segurança.
         */
        private long maxCrlResponseBytes = 52_428_800L;

        /**
         * Tamanho máximo da resposta AIA CA Issuers em bytes (padrão 10 MB, intervalo [1024, 104857600]).
         * Um arquivo p7b com cadeia completa raramente ultrapassa alguns MB.
         */
        private long maxAiaResponseBytes = 10_485_760L;

        /**
         * Se true, resolve o hostname antes do download e bloqueia endereços não públicos ou
         * falha de resolução; não elimina DNS rebinding.
         */
        private boolean blockPrivateHostnames = true;

        /**
         * Lista de domínios permitidos (ex: "icpbrasil.gov.br", "serpro.gov.br").
         * Subdomínios são automaticamente incluídos. Vazia = qualquer domínio público aceito.
         */
        private List<String> allowedDomains = List.of();
    }

    /**
     * Configurações do bootstrap síncrono.
     * Controla a carga inicial do cache durante o startup do Spring Boot,
     * antes de o contexto ser declarado "Started".
     */
    @Data
    public static class BootstrapConfig {

        /**
         * Se true, o bootstrap síncrono é executado no startup (padrão).
         * Quando desabilitado, o cache só é populado pela primeira execução do scheduler.
         * Útil em testes que sobem o contexto sem rede disponível.
         */
        private boolean enabled = true;

        /**
         * Se true (padrão), uma falha no bootstrap aborta o startup (lança IllegalStateException).
         * Se false, loga erro e deixa a aplicação subir com cache vazio — útil apenas em
         * cenários de desenvolvimento onde a indisponibilidade do repositório ITI é aceitável.
         */
        private boolean failFast = true;
    }
}