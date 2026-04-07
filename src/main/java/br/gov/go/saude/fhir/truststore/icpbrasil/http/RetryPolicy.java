package br.gov.go.saude.fhir.truststore.icpbrasil.http;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.function.Supplier;

/**
 * Política de retry configurável para operações de rede.
 *
 * <p>Oferece dois modos de uso:</p>
 * <ul>
 *   <li>{@link #executeWithRetry(String, Supplier)} — usa configuração de rede padrão
 *       e aceita apenas unchecked exceptions (usado pelo {@code Downloader})</li>
 *   <li>{@link #executeWithRetry(String, int, long, CheckedSupplier)} — aceita parâmetros
 *       explícitos e propaga checked exceptions (usado pelo {@code RevocationService})</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RetryPolicy {

    private final TrustStoreConfig trustStoreConfig;

    /**
     * Executa uma operação com retry baseado na configuração de rede padrão.
     */
    public <T> T executeWithRetry(String operation, Supplier<T> supplier) throws IOException {
        TrustStoreConfig.NetworkConfig networkConfig = trustStoreConfig.getNetwork();
        int maxRetries = networkConfig.getMaxRetries();
        int retryInterval = networkConfig.getRetryIntervalMillis();

        Exception lastException = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                log.debug("Tentativa {}/{} para: {}", attempt, maxRetries, operation);
                return supplier.get();

            } catch (Exception e) {
                lastException = e;
                log.warn("Tentativa {}/{} falhou para {}: {}", attempt, maxRetries, operation, e.getMessage());

                if (attempt == maxRetries) {
                    break;
                }

                waitBeforeRetry(retryInterval, operation);
            }
        }

        throw new IOException("Operação falhou após " + maxRetries + " tentativas: " + operation, lastException);
    }

    /**
     * Executa uma operação com retry usando parâmetros explícitos.
     * Propaga a exceção original (checked ou unchecked) caso todas as tentativas falhem.
     *
     * @param operation      descrição da operação (para logging)
     * @param maxRetries     número máximo de tentativas (0 = sem retry)
     * @param intervalMillis intervalo entre tentativas em milissegundos
     * @param supplier       operação a executar
     * @return resultado da primeira execução bem-sucedida
     * @throws Exception exceção da última tentativa se todas falharem
     */
    public <T> T executeWithRetry(String operation, int maxRetries, long intervalMillis,
                                   CheckedSupplier<T> supplier) throws Exception {
        Exception lastException = null;

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                log.debug("Tentativa {}/{} para: {}", attempt + 1, maxRetries + 1, operation);
                return supplier.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw e;
            } catch (Exception e) {
                lastException = e;
                log.warn("Tentativa {}/{} falhou para {}: {}",
                        attempt + 1, maxRetries + 1, operation, e.getMessage());
                if (attempt < maxRetries) {
                    waitBeforeRetry(intervalMillis, operation);
                }
            }
        }

        throw lastException;
    }

    private void waitBeforeRetry(long intervalMillis, String operation) throws IOException {
        try {
            log.debug("Aguardando {}ms antes da próxima tentativa para: {}", intervalMillis, operation);
            Thread.sleep(intervalMillis);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Operação interrompida: " + operation, ie);
        }
    }

    /**
     * Interface funcional para operações que podem lançar checked exceptions.
     *
     * @param <T> tipo de retorno
     */
    @FunctionalInterface
    public interface CheckedSupplier<T> {
        T get() throws Exception;
    }
}
