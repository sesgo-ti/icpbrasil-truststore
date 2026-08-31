package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * Política de retry configurável para operações de rede.
 *
 * <p>Oferece dois modos de uso:</p>
 * <ul>
 *   <li>{@link #executeWithRetry(String, Supplier)} — usa configuração de rede padrão
 *       e encapsula falhas em {@link IOException} (usado pelo {@code Downloader})</li>
 *   <li>{@link #executeWithRetry(String, int, long, Callable)} — aceita parâmetros
 *       explícitos e propaga checked exceptions (usado por {@code OcspClient} e {@code CrlClient})</li>
 * </ul>
 */
@Slf4j
@Component
public class RetryPolicy {

    private final TrustStoreConfig.NetworkConfig config;

    public RetryPolicy(TrustStoreConfig trustStoreConfig) {
        this.config = trustStoreConfig.getNetwork();
    }

    /**
     * Executa uma operação com retry baseado na configuração de rede padrão.
     * Encapsula qualquer exceção em {@link IOException}.
     *
     * <p>Nota: {@code NetworkConfig.maxRetries} representa o número total de tentativas
     * (ex: 3 = três tentativas), enquanto o overload explícito usa retries adicionais
     * (ex: 2 = uma tentativa + dois retries).</p>
     */
    public <T> T executeWithRetry(String operation, Supplier<T> supplier) throws IOException {
        try {
            return executeWithRetry(
                    operation,
                    config.getMaxRetries() - 1,
                    config.getRetryIntervalMillis(),
                    supplier::get);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Operação falhou após " + config.getMaxRetries()
                    + " tentativas: " + operation, e);
        }
    }

    /**
     * Executa uma operação com retry usando parâmetros explícitos.
     * Propaga a exceção original caso todas as tentativas falhem.
     *
     * @param operation      descrição da operação (para logging)
     * @param maxRetries     número máximo de retries após a primeira tentativa (0 = sem retry)
     * @param intervalMillis intervalo entre tentativas em milissegundos
     * @param task           operação a executar
     * @return resultado da primeira execução bem-sucedida
     * @throws Exception exceção da última tentativa se todas falharem
     */
    public <T> T executeWithRetry(String operation, int maxRetries, long intervalMillis,
                                   Callable<T> task) throws Exception {
        int totalAttempts = maxRetries + 1;
        Exception lastException = null;

        for (int attempt = 1; attempt <= totalAttempts; attempt++) {
            try {
                log.debug("Tentativa {}/{} para: {}", attempt, totalAttempts, operation);
                return task.call();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw e;
            } catch (Exception e) {
                lastException = e;
                log.warn("Tentativa {}/{} falhou para {}: {}",
                        attempt, totalAttempts, operation, e.getMessage());
                if (attempt < totalAttempts) {
                    sleep(intervalMillis);
                }
            }
        }

        throw lastException;
    }

    /* Metodo auxiliar para aguardar entre tentativas, com logging. */
    private void sleep(long millis) throws InterruptedException {
        log.debug("Aguardando {}ms antes da próxima tentativa", millis);
        Thread.sleep(millis);
    }

}
