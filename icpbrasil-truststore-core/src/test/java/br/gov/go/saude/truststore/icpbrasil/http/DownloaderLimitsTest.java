package br.gov.go.saude.truststore.icpbrasil.http;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cobre a leitura limitada e o prazo total do {@link Downloader} isolando o método de leitura,
 * sem servidor TLS: o contrato de limite e prazo independe do transporte.
 */
class DownloaderLimitsTest {

    private static final long SEM_PRAZO = System.nanoTime() + TimeUnit.HOURS.toNanos(1);

    @SneakyThrows
    @Test
    void testReadLimited_DentroDoLimite_RetornaTodosOsBytes() {
        byte[] dados = new byte[100_000];
        new Random(42).nextBytes(dados);

        byte[] lido = Downloader.readLimited(new ByteArrayInputStream(dados), Downloader.MAX_BINARY_BYTES, SEM_PRAZO);

        assertArrayEquals(dados, lido);
    }

    @SneakyThrows
    @Test
    void testReadLimited_ExatamenteNoLimite_Aceita() {
        byte[] dados = new byte[Downloader.MAX_TEXT_BYTES];
        Arrays.fill(dados, (byte) 'a');

        byte[] lido = Downloader.readLimited(new ByteArrayInputStream(dados), Downloader.MAX_TEXT_BYTES, SEM_PRAZO);

        assertArrayEquals(dados, lido);
    }

    @Test
    void testReadLimited_UmByteAlemDoLimite_LancaIOException() {
        byte[] dados = new byte[Downloader.MAX_TEXT_BYTES + 1];

        IOException ex = assertThrows(IOException.class,
                () -> Downloader.readLimited(new ByteArrayInputStream(dados), Downloader.MAX_TEXT_BYTES, SEM_PRAZO));
        assertFalse(ex instanceof SocketTimeoutException);
        assertTrue(ex.getMessage().contains("limite"));
    }

    @Test
    void testReadLimited_CorpoSemFim_AbortaAoExcederOLimite() {
        AtomicLong entregues = new AtomicLong();
        InputStream infinito = new InputStream() {
            @Override
            public int read() {
                entregues.incrementAndGet();
                return 0;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                entregues.addAndGet(len);
                return len;
            }
        };

        assertThrows(IOException.class, () -> Downloader.readLimited(infinito, 1_000_000, SEM_PRAZO));
        assertTrue(entregues.get() < 1_000_000 + 64 * 1024,
                "leitura deveria parar logo após o limite, mas consumiu " + entregues.get() + " bytes");
    }

    @Test
    void testReadLimited_ServidorGotejandoBytes_LancaSocketTimeoutExceptionNoPrazo() {
        InputStream lento = new InputStream() {
            @Override
            @SneakyThrows
            public int read() {
                Thread.sleep(20);
                return 0;
            }

            @Override
            @SneakyThrows
            public int read(byte[] b, int off, int len) {
                Thread.sleep(20);
                b[off] = 0;
                return 1;
            }
        };
        long prazo = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(150);
        long inicio = System.nanoTime();

        assertThrows(SocketTimeoutException.class, () -> Downloader.readLimited(lento, 1_000_000, prazo));

        long decorridoMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - inicio);
        assertTrue(decorridoMillis >= 150 && decorridoMillis < 2_000,
                "prazo deveria ser aplicado em ~150 ms, decorrido: " + decorridoMillis + " ms");
    }

    @Test
    void testReadLimited_PrazoJaVencido_FalhaSemLer() {
        AtomicLong leituras = new AtomicLong();
        InputStream contado = new InputStream() {
            @Override
            public int read() {
                leituras.incrementAndGet();
                return -1;
            }
        };
        long prazoVencido = System.nanoTime() - 1;

        assertThrows(SocketTimeoutException.class, () -> Downloader.readLimited(contado, 1024, prazoVencido));
        assertEquals(0, leituras.get());
    }

    @SneakyThrows
    @Test
    void testReadLimited_StreamVazio_RetornaArrayVazio() {
        byte[] lido = Downloader.readLimited(new ByteArrayInputStream(new byte[0]), 1024, SEM_PRAZO);

        assertEquals(0, lido.length);
    }
}
