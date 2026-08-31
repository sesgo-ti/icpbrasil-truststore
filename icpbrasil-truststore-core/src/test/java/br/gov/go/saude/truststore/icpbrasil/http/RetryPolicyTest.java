package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RetryPolicyTest {

    private RetryPolicy retryPolicy;

    @BeforeEach
    void setUp() {
        TrustStoreConfig config = new TrustStoreConfig();
        TrustStoreConfig.NetworkConfig networkConfig = new TrustStoreConfig.NetworkConfig();
        networkConfig.setMaxRetries(3);
        networkConfig.setRetryIntervalSeconds(0);
        networkConfig.setDownloadTimeoutSeconds(30);
        config.setNetwork(networkConfig);

        retryPolicy = new RetryPolicy(config);
    }

    @Test
    void testExecuteWithRetry_Supplier_ComSucesso_DeveRetornarResultado() throws IOException {
        String result = retryPolicy.executeWithRetry("operação", () -> "ok");

        assertEquals("ok", result);
    }

    @Test
    void testExecuteWithRetry_Supplier_ComFalhaPersistente_DeveLancarIOException() {
        assertThrows(IOException.class, () ->
                retryPolicy.executeWithRetry("operação", () -> {
                    throw new RuntimeException("falha");
                }));
    }

    @Test
    void testExecuteWithRetry_Callable_ComSucesso_DeveRetornarResultado() throws Exception {
        String result = retryPolicy.executeWithRetry("operação", 2, 1, () -> "ok");

        assertEquals("ok", result);
    }

    @Test
    void testExecuteWithRetry_Callable_SemRetry_DeveExecutarUmaVez() throws Exception {
        AtomicInteger tentativas = new AtomicInteger(0);

        String result = retryPolicy.executeWithRetry("operação", 0, 1, () -> {
            tentativas.incrementAndGet();
            return "ok";
        });

        assertEquals("ok", result);
        assertEquals(1, tentativas.get());
    }

    @Test
    void testExecuteWithRetry_Callable_ComFalhaParcial_DeveRetentar() throws Exception {
        AtomicInteger tentativas = new AtomicInteger(0);

        String result = retryPolicy.executeWithRetry("operação", 2, 1, () -> {
            if (tentativas.incrementAndGet() < 3) {
                throw new IOException("falha temporária");
            }
            return "ok";
        });

        assertEquals("ok", result);
        assertEquals(3, tentativas.get());
    }

    @Test
    void testExecuteWithRetry_Callable_ComFalhaPersistente_DevePropagar() {
        IOException thrown = assertThrows(IOException.class, () ->
                retryPolicy.executeWithRetry("operação", 1, 1, () -> {
                    throw new IOException("falha permanente");
                }));

        assertEquals("falha permanente", thrown.getMessage());
    }

    @Test
    void testExecuteWithRetry_Callable_ComFalhaPersistente_DeveExecutarTodasTentativas() {
        AtomicInteger tentativas = new AtomicInteger(0);

        assertThrows(IOException.class, () ->
                retryPolicy.executeWithRetry("operação", 2, 1, () -> {
                    tentativas.incrementAndGet();
                    throw new IOException("falha");
                }));

        assertEquals(3, tentativas.get());
    }
}
