package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

/**
 * Compartilha carregamentos em andamento por chave: consultas simultâneas pela mesma evidência
 * (mesma URL de CRL, mesmo par emissor/serial no OCSP) esperam o download já iniciado em vez de
 * repeti-lo.
 *
 * <p>Quem inicia o carregamento o executa na própria thread, então limites de tempo, retentativas
 * e política de download continuam os do chamador. A entrada sai do mapa ao terminar, com sucesso
 * ou falha: uma falha é entregue a quem estava esperando, mas não fica memorizada, e a próxima
 * consulta tenta de novo. Quem espera e é interrompido desiste sozinho, sem cancelar o
 * carregamento dos demais; se quem carregava é que foi interrompido, os demais recebem
 * {@link IOException}.</p>
 */
final class InFlightLoads<K, V> {

    private final ConcurrentHashMap<K, CompletableFuture<V>> inFlight = new ConcurrentHashMap<>();

    V load(K key, Callable<V> loader) throws Exception {
        CompletableFuture<V> mine = new CompletableFuture<>();
        CompletableFuture<V> running = inFlight.putIfAbsent(key, mine);
        if (running != null) {
            return await(running);
        }
        try {
            V value = loader.call();
            mine.complete(value);
            return value;
        } catch (Throwable t) {
            mine.completeExceptionally(t);
            throw t;
        } finally {
            inFlight.remove(key, mine);
        }
    }

    /** Carregamentos em andamento; os testes o usam para provar que nenhuma entrada sobra no mapa. */
    int pending() {
        return inFlight.size();
    }

    private static <V> V await(CompletableFuture<V> running) throws Exception {
        try {
            return running.get();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            // A interrupção foi da thread que carregava, não desta: para quem espera é uma falha
            // de carregamento, e propagar InterruptedException marcaria esta thread por engano.
            if (cause instanceof InterruptedException) {
                throw new IOException("Carregamento compartilhado interrompido", cause);
            }
            if (cause instanceof Exception exception) {
                throw exception;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw e;
        }
    }
}
