package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InFlightLoadsTest {

    private final InFlightLoads<String, Object> loads = new InFlightLoads<>();

    @Test
    void testLoad_ConsultasSimultaneasMesmaChave_CompartilhamUmCarregamento() throws Exception {
        CountDownLatch iniciou = new CountDownLatch(1);
        CountDownLatch liberar = new CountDownLatch(1);
        AtomicInteger execucoes = new AtomicInteger();
        Object valor = new Object();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Object> primeira = executor.submit(() -> loads.load("k", () -> {
                execucoes.incrementAndGet();
                iniciou.countDown();
                liberar.await();
                return valor;
            }));
            assertTrue(iniciou.await(5, TimeUnit.SECONDS));
            Future<Object> segunda = executor.submit(() -> loads.load("k", () -> {
                execucoes.incrementAndGet();
                return new Object();
            }));
            awaitWaiting(segunda);
            liberar.countDown();

            assertSame(valor, primeira.get(5, TimeUnit.SECONDS));
            assertSame(valor, segunda.get(5, TimeUnit.SECONDS));
            assertEquals(1, execucoes.get());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void testLoad_ChavesDiferentes_CarregamentosIndependentes() throws Exception {
        AtomicInteger execucoes = new AtomicInteger();

        loads.load("a", execucoes::incrementAndGet);
        loads.load("b", execucoes::incrementAndGet);

        assertEquals(2, execucoes.get());
    }

    @Test
    void testLoad_FalhaDoCarregamento_PropagaENaoFicaPresa() throws Exception {
        assertThrows(IOException.class, () -> loads.load("k", () -> {
            throw new IOException("falhou");
        }));

        assertEquals("ok", loads.load("k", () -> "ok"));
        assertEquals(0, loads.pending());
    }

    @Test
    void testLoad_AguardandoInterrompido_NaoCancelaOCarregamentoNemFicaPreso() throws Exception {
        CountDownLatch iniciou = new CountDownLatch(1);
        CountDownLatch liberar = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Object> dono = executor.submit(() -> loads.load("k", () -> {
                iniciou.countDown();
                liberar.await();
                return "valor";
            }));
            assertTrue(iniciou.await(5, TimeUnit.SECONDS));
            Future<Object> aguardando = executor.submit(() -> loads.load("k", () -> "outro"));
            awaitWaiting(aguardando);

            aguardando.cancel(true);
            liberar.countDown();

            assertEquals("valor", dono.get(5, TimeUnit.SECONDS));
            assertEquals(0, loads.pending());
            assertEquals("novo", loads.load("k", () -> "novo"));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void testLoad_DonoInterrompido_QuemAguardaRecebeFalhaSemSerMarcadoComoInterrompido() throws Exception {
        CountDownLatch iniciou = new CountDownLatch(1);
        CountDownLatch liberar = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            executor.submit(() -> loads.load("k", () -> {
                iniciou.countDown();
                liberar.await();
                throw new InterruptedException("dono interrompido");
            }));
            assertTrue(iniciou.await(5, TimeUnit.SECONDS));
            Future<Boolean> aguardando = executor.submit(() -> {
                try {
                    loads.load("k", () -> "outro");
                    return false;
                } catch (InterruptedException e) {
                    return false;
                } catch (Exception e) {
                    return !Thread.currentThread().isInterrupted();
                }
            });
            awaitWaiting(aguardando);
            liberar.countDown();

            assertTrue(aguardando.get(5, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }

    /** Dá tempo à segunda consulta de chegar ao carregamento em andamento. */
    private static void awaitWaiting(Future<?> future) throws InterruptedException {
        Thread.sleep(200);
        assertTrue(!future.isDone());
    }
}
