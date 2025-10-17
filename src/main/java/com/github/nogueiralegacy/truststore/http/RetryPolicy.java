package com.github.nogueiralegacy.truststore.http;

import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.function.Supplier;

/**
 * Política de retry configurável para operações de download
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RetryPolicy {

    private final TrustStoreConfig trustStoreConfig;

    /**
     * Executa uma operação com retry automático baseado na configuração
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

    private void waitBeforeRetry(int retryInterval, String operation) throws IOException {
        try {
            log.debug("Aguardando {}ms antes da próxima tentativa para: {}", retryInterval, operation);
            Thread.sleep(retryInterval);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Operação interrompida: " + operation, ie);
        }
    }
}