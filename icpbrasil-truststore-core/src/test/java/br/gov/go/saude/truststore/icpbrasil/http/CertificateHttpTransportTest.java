package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport.LimitedBodySubscriber;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CertificateHttpTransportTest {

    private static final long MAX_BYTES = 64 * 1024;
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private HttpServer server;
    private ExecutorService serverExecutor;
    private String baseUrl;
    private DownloadPolicy downloadPolicy;
    private CertificateHttpTransport transport;

    @BeforeEach
    @SneakyThrows
    void setUp() {
        // Bind explícito em IPv4: com preferIPv6Addresses o loopback padrão seria ::1 e a URL
        // montada a partir do endereço real do servidor precisaria de colchetes.
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
        serverExecutor = Executors.newCachedThreadPool();
        server.setExecutor(serverExecutor);
        server.start();
        InetSocketAddress bound = server.getAddress();
        baseUrl = "http://" + bound.getHostString() + ":" + bound.getPort();

        // O servidor de teste roda em loopback, que a política real bloqueia sempre; o stub
        // permissivo isola o comportamento do transporte sem relaxar a política de produção.
        downloadPolicy = mock(DownloadPolicy.class);
        transport = new CertificateHttpTransport(downloadPolicy, Duration.ofSeconds(2));
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
        serverExecutor.shutdownNow();
    }

    // --- construtores ---

    @Test
    void testConstrutor_HttpClientQueSegueRedirects_LancaIllegalArgumentException() {
        HttpClient normal = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
        HttpClient always = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build();

        assertThrows(IllegalArgumentException.class, () -> new CertificateHttpTransport(downloadPolicy, normal));
        assertThrows(IllegalArgumentException.class, () -> new CertificateHttpTransport(downloadPolicy, always));
    }

    @Test
    void testConstrutor_HttpClientSemRedirects_Aceito() {
        HttpClient never = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

        assertDoesNotThrow(() -> new CertificateHttpTransport(downloadPolicy, never));
    }

    // --- sucesso ---

    @Test
    @SneakyThrows
    void testGet_Sucesso_RetornaCorpoCompletoEValidaUrl() {
        byte[] expected = pattern(50_000);
        server.createContext("/ok", fixedLength(200, expected));
        String url = baseUrl + "/ok";

        byte[] body = transport.get(url, MAX_BYTES, TIMEOUT);

        assertArrayEquals(expected, body);
        verify(downloadPolicy).validateUrl(url);
    }

    @Test
    @SneakyThrows
    void testPost_Sucesso_EnviaCorpoECabecalhosERetornaResposta() {
        AtomicReference<String> method = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        AtomicReference<String> accept = new AtomicReference<>();
        AtomicReference<byte[]> requestBody = new AtomicReference<>();
        server.createContext("/ocsp", exchange -> {
            method.set(exchange.getRequestMethod());
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            accept.set(exchange.getRequestHeaders().getFirst("Accept"));
            requestBody.set(exchange.getRequestBody().readAllBytes());
            byte[] response = "resposta".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        });
        byte[] request = "requisicao".getBytes(StandardCharsets.UTF_8);

        byte[] body = transport.post(baseUrl + "/ocsp", request,
                "application/ocsp-request", "application/ocsp-response", MAX_BYTES, TIMEOUT);

        assertEquals("resposta", new String(body, StandardCharsets.UTF_8));
        assertEquals("POST", method.get());
        assertEquals("application/ocsp-request", contentType.get());
        assertEquals("application/ocsp-response", accept.get());
        assertArrayEquals(request, requestBody.get());
    }

    @Test
    @SneakyThrows
    void testGet_MuitosFragmentosPequenos_ReconstroiCorpoIntegralmente() {
        byte[] expected = pattern(12_000);
        server.createContext("/fragmentos", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream os = exchange.getResponseBody()) {
                for (int offset = 0; offset < expected.length; offset += 3) {
                    os.write(expected, offset, Math.min(3, expected.length - offset));
                    os.flush();
                }
            }
        });

        byte[] body = transport.get(baseUrl + "/fragmentos", MAX_BYTES, TIMEOUT);

        assertArrayEquals(expected, body);
    }

    // --- redirects ---

    @Test
    void testGet_RedirectParaHostPrivado_RejeitadoSemRequisitarDestino() {
        AtomicInteger destinoHits = new AtomicInteger();
        server.createContext("/interno", exchange -> {
            destinoHits.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", baseUrl + "/interno");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        String url = baseUrl + "/redirect";

        DownloadPolicyException ex = assertThrows(DownloadPolicyException.class,
                () -> transport.get(url, MAX_BYTES, TIMEOUT));

        assertTrue(ex.getMessage().contains("302"), ex.getMessage());
        assertEquals(0, destinoHits.get());
        verify(downloadPolicy, times(1)).validateUrl(anyString());
    }

    // --- política ---

    @Test
    void testGet_UrlBloqueadaPelaPolitica_NaoRequisita() {
        AtomicInteger hits = new AtomicInteger();
        server.createContext("/bloqueado", exchange -> {
            hits.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        String url = baseUrl + "/bloqueado";
        doThrow(new DownloadPolicyException("bloqueada")).when(downloadPolicy).validateUrl(url);

        assertThrows(DownloadPolicyException.class, () -> transport.get(url, MAX_BYTES, TIMEOUT));

        assertEquals(0, hits.get());
    }

    // --- limite de tamanho ---

    @Test
    @SneakyThrows
    void testGet_CorpoChunkedAcimaDoLimite_CancelaConexao() {
        StreamingHandler handler = new StreamingHandler(200);
        server.createContext("/grande", handler);
        String url = baseUrl + "/grande";

        DownloadPolicyException ex = assertThrows(DownloadPolicyException.class,
                () -> transport.get(url, MAX_BYTES, TIMEOUT));

        assertTrue(ex.getMessage().contains("excede o limite"), ex.getMessage());
        assertTrue(handler.finished.await(10, TimeUnit.SECONDS), "servidor não encerrou o envio");
        assertTrue(handler.clientClosed, "servidor deveria ter detectado o fechamento pelo cliente");
        assertTrue(handler.bytesWritten < StreamingHandler.SAFETY_CAP);
    }

    @Test
    @SneakyThrows
    void testGet_Status500ComCorpoGrande_CancelaAntesDeLerCorpo() {
        StreamingHandler handler = new StreamingHandler(500);
        server.createContext("/erro-grande", handler);
        String url = baseUrl + "/erro-grande";
        long limiteAlto = 64L * 1024 * 1024;

        IOException ex = assertThrows(IOException.class, () -> transport.get(url, limiteAlto, TIMEOUT));

        assertTrue(ex.getMessage().contains("HTTP 500"), ex.getMessage());
        assertTrue(handler.finished.await(10, TimeUnit.SECONDS), "servidor não encerrou o envio");
        assertTrue(handler.clientClosed, "servidor deveria ter detectado o fechamento pelo cliente");
        // Cancelado nos cabeçalhos: o servidor só consegue escrever o que cabe nos buffers do
        // socket, muito menos do que o limite que uma acumulação até maxBytes consumiria.
        assertTrue(handler.bytesWritten < limiteAlto / 2,
                "servidor escreveu " + handler.bytesWritten + " bytes antes de detectar o fechamento");
    }

    @Test
    void testGet_Status500ComCorpoPequeno_LancaIOException() {
        server.createContext("/erro", fixedLength(500, "erro".getBytes(StandardCharsets.UTF_8)));
        String url = baseUrl + "/erro";

        IOException ex = assertThrows(IOException.class, () -> transport.get(url, MAX_BYTES, TIMEOUT));

        assertTrue(ex.getMessage().contains("HTTP 500"), ex.getMessage());
    }

    @Test
    @SneakyThrows
    void testGet_CorpoNoLimiteExato_Aceito() {
        byte[] expected = pattern((int) MAX_BYTES);
        server.createContext("/exato", fixedLength(200, expected));

        byte[] body = transport.get(baseUrl + "/exato", MAX_BYTES, TIMEOUT);

        assertArrayEquals(expected, body);
    }

    // --- timeout ---

    @Test
    void testGet_CorpoLento_ExcedeTimeoutMesmoComCabecalhosRecebidos() {
        server.createContext("/lento", exchange -> {
            exchange.sendResponseHeaders(200, 1000);
            OutputStream os = exchange.getResponseBody();
            os.write(new byte[10]);
            os.flush();
            try {
                Thread.sleep(3000);
                os.write(new byte[990]);
                os.close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException ignored) {
                // cliente já encerrou
            }
        });
        String url = baseUrl + "/lento";

        assertThrows(HttpTimeoutException.class,
                () -> transport.get(url, MAX_BYTES, Duration.ofMillis(500)));
    }

    // --- LimitedBodySubscriber ---

    @Test
    @SneakyThrows
    void testLimitedBodySubscriber_FragmentosCopiados_NaoRetemBuffers() {
        LimitedBodySubscriber subscriber = new LimitedBodySubscriber(1_000_000);
        subscriber.onSubscribe(new RecordingSubscription());
        int fragments = 50_000;
        ByteBuffer shared = ByteBuffer.allocate(Integer.BYTES);

        // O mesmo buffer é sobrescrito a cada fragmento: se o subscriber retivesse referências,
        // o corpo final repetiria o último valor em vez da sequência.
        for (int i = 0; i < fragments; i++) {
            shared.clear();
            shared.putInt(i);
            shared.flip();
            subscriber.onNext(List.of(shared));
        }
        subscriber.onComplete();

        byte[] body = subscriber.getBody().toCompletableFuture().get();
        assertEquals(fragments * Integer.BYTES, body.length);
        ByteBuffer view = ByteBuffer.wrap(body);
        for (int i = 0; i < fragments; i++) {
            assertEquals(i, view.getInt());
        }
    }

    @Test
    void testLimitedBodySubscriber_ExcedeLimite_FalhaResultadoAntesDeCancelar() {
        LimitedBodySubscriber subscriber = new LimitedBodySubscriber(64);
        CompletableFuture<byte[]> body = subscriber.getBody().toCompletableFuture();
        RecordingSubscription subscription = new RecordingSubscription();
        subscription.onCancel = () -> subscription.resultDoneAtCancel = body.isDone();
        subscriber.onSubscribe(subscription);

        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[40])));
        assertFalse(subscription.cancelled);
        assertFalse(subscriber.isLimitExceeded());

        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[25])));

        assertTrue(subscription.cancelled);
        assertTrue(subscription.resultDoneAtCancel);
        assertTrue(subscriber.isLimitExceeded());
        ExecutionException ex = assertThrows(ExecutionException.class, body::get);
        assertInstanceOf(DownloadPolicyException.class, ex.getCause());

        subscriber.onComplete();
        assertTrue(body.isCompletedExceptionally());
    }

    @Test
    @SneakyThrows
    void testLimitedBodySubscriber_CorpoNoLimiteExato_Aceito() {
        LimitedBodySubscriber subscriber = new LimitedBodySubscriber(64);
        RecordingSubscription subscription = new RecordingSubscription();
        subscriber.onSubscribe(subscription);

        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[40]), ByteBuffer.wrap(new byte[24])));
        subscriber.onComplete();

        assertFalse(subscription.cancelled);
        assertEquals(64, subscriber.getBody().toCompletableFuture().get().length);
    }

    // --- helpers ---

    private static byte[] pattern(int length) {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++) {
            data[i] = (byte) (i * 31 + 7);
        }
        return data;
    }

    private static HttpHandler fixedLength(int status, byte[] body) {
        return exchange -> {
            exchange.sendResponseHeaders(status, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        };
    }

    /**
     * Envia blocos em chunked até o cliente fechar a conexão. O teto só existe para o teste
     * terminar caso o cancelamento não aconteça.
     */
    private static final class StreamingHandler implements HttpHandler {
        static final int BLOCK = 1024;
        static final long SAFETY_CAP = 256L * 1024 * 1024;

        final int status;
        final CountDownLatch finished = new CountDownLatch(1);
        volatile long bytesWritten;
        volatile boolean clientClosed;

        StreamingHandler(int status) {
            this.status = status;
        }

        @Override
        public void handle(HttpExchange exchange) {
            try {
                exchange.sendResponseHeaders(status, 0);
                OutputStream os = exchange.getResponseBody();
                byte[] block = new byte[BLOCK];
                while (bytesWritten < SAFETY_CAP) {
                    os.write(block);
                    os.flush();
                    bytesWritten += BLOCK;
                }
            } catch (IOException e) {
                clientClosed = true;
            } finally {
                exchange.close();
                finished.countDown();
            }
        }
    }

    private static final class RecordingSubscription implements Flow.Subscription {
        volatile boolean cancelled;
        volatile boolean resultDoneAtCancel;
        Runnable onCancel = () -> { };

        @Override
        public void request(long n) {
        }

        @Override
        public void cancel() {
            onCancel.run();
            cancelled = true;
        }
    }
}
