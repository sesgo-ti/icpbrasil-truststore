package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.IncompleteChainException;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.CrlClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.OcspClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationCache;
import com.sun.net.httpserver.HttpServer;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodySubscriber;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow.Subscription;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(15)
class CertificateHttpTransportTest {

    private static KeyPair issuerKey;
    private static KeyPair leafKey;
    private static X509Certificate issuer;

    private HttpServer server;
    private ExecutorService executor;
    private HttpClient httpClient;
    private DownloadPolicy policy;
    private CertificateHttpTransport transport;
    private TrustStoreConfig config;
    private String url;

    @BeforeAll
    @SneakyThrows
    static void setUpCertificates() {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        issuerKey = generator.generateKeyPair();
        leafKey = generator.generateKeyPair();
        issuer = generateRootCert(issuerKey);
    }

    @BeforeEach
    @SneakyThrows
    void setUp() {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        executor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(executor);
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort() + "/artifact";
        httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        config = new TrustStoreConfig();
        config.setDownloadPolicy(new TrustStoreConfig.DownloadPolicyConfig());
        config.setChain(new TrustStoreConfig.ChainConfig());
        config.setRevocation(new TrustStoreConfig.RevocationConfig());
        config.getChain().setRetryIntervalSeconds(0);
        config.getRevocation().setRetryIntervalSeconds(0);
        policy = spy(new DownloadPolicy(config));
        // Somente este endpoint local e permitido; qualquer outro destino usa a politica real.
        doNothing().when(policy).validateUrl(url);
        transport = new CertificateHttpTransport(httpClient, policy);
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
        executor.shutdownNow();
        httpClient.shutdownNow();
    }

    @Test
    void testSendPoliticaPadraoBloqueiaServidorLocal() {
        AtomicInteger hits = new AtomicInteger();
        server.createContext("/artifact", exchange -> {
            hits.incrementAndGet();
            exchange.close();
        });
        CertificateHttpTransport production = new CertificateHttpTransport(httpClient, new DownloadPolicy(config));
        assertThrows(DownloadPolicyException.class, () -> production.send(request(Duration.ofSeconds(2)), 1024));
        assertEquals(0, hits.get());
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 302, 303, 307, 308})
    void testSendRedirectPrivadoNaoAcessaDestino(int status) {
        AtomicInteger destinationHits = new AtomicInteger();
        server.createContext("/artifact", exchange -> {
            exchange.getResponseHeaders().set("Location", url.replace("/artifact", "/private"));
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.createContext("/private", exchange -> {
            destinationHits.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        assertThrows(DownloadPolicyException.class, () -> transport.send(request(Duration.ofSeconds(2)), 1024));
        assertEquals(0, destinationHits.get());
    }

    @Test
    void testConstrutoresRejeitamClientesComRedirectAutomatico() {
        for (HttpClient.Redirect redirect : List.of(HttpClient.Redirect.NORMAL, HttpClient.Redirect.ALWAYS)) {
            try (HttpClient unsafe = HttpClient.newBuilder().followRedirects(redirect).build()) {
                RetryPolicy retry = new RetryPolicy(config);
                RevocationCache cache = new RevocationCache(config);
                assertThrows(IllegalArgumentException.class, () -> new CertificateHttpTransport(unsafe, policy));
                assertThrows(IllegalArgumentException.class,
                        () -> new CertificateChainResolver(retry, config.getChain(), unsafe, policy));
                assertThrows(IllegalArgumentException.class,
                        () -> new OcspClient(cache, retry, config.getRevocation(), unsafe, policy));
                assertThrows(IllegalArgumentException.class,
                        () -> new CrlClient(cache, retry, config.getRevocation(), unsafe, policy));
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 302, 500})
    @SneakyThrows
    void testSendChunkedExcedenteCancelaAntesDoFimInclusiveErro(int status) {
        CountDownLatch disconnected = new CountDownLatch(1);
        serveOversized(status, disconnected, new AtomicInteger());
        DownloadPolicyException failure = assertTimeoutPreemptively(Duration.ofSeconds(3),
                () -> assertThrows(DownloadPolicyException.class,
                        () -> transport.send(request(Duration.ofSeconds(5)), 1024)));
        assertTrue(failure.getMessage().contains("1024"));
        assertTrue(disconnected.await(3, TimeUnit.SECONDS), "Servidor deve observar cancelamento da transferencia");
    }

    @Test
    @SneakyThrows
    void testSendContentLengthExcedenteBloqueado() {
        serveBytes(200, new byte[1025]);
        assertThrows(DownloadPolicyException.class, () -> transport.send(request(Duration.ofSeconds(2)), 1024));
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 500})
    @SneakyThrows
    void testSendTimeoutAbrangeCorpoParadoInclusiveErro(int status) {
        CountDownLatch headersSent = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        server.createContext("/artifact", exchange -> {
            try {
                exchange.sendResponseHeaders(status, 0);
                exchange.getResponseBody().write(1);
                exchange.getResponseBody().flush();
                headersSent.countDown();
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(3), () -> assertThrows(HttpTimeoutException.class,
                    () -> transport.send(request(Duration.ofMillis(500)), 1024)));
            assertEquals(0, headersSent.getCount(), "Timeout deve ocorrer depois dos headers");
        } finally {
            release.countDown();
        }
    }

    @Test
    @SneakyThrows
    void testSendInterrupcaoCancelaDownload() {
        CountDownLatch headersSent = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        server.createContext("/artifact", exchange -> {
            try {
                exchange.sendResponseHeaders(200, 0);
                exchange.getResponseBody().write(1);
                exchange.getResponseBody().flush();
                headersSent.countDown();
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        Thread caller = Thread.ofVirtual().start(() -> {
            try {
                transport.send(request(Duration.ofSeconds(10)), 1024);
            } catch (Throwable e) {
                failure.set(e);
            }
        });
        try {
            assertTrue(headersSent.await(3, TimeUnit.SECONDS));
            caller.interrupt();
            caller.join(3000);
            assertFalse(caller.isAlive());
            assertInstanceOf(InterruptedException.class, failure.get());
        } finally {
            release.countDown();
            caller.interrupt();
        }
    }

    @Test
    @SneakyThrows
    void testSendSucessoNoLimiteComPolicyControlada() {
        byte[] body = new byte[1024];
        serveBytes(200, body);
        assertArrayEquals(body, transport.send(request(Duration.ofSeconds(2)), body.length));
        verify(policy).validateUrl(url);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @SneakyThrows
    @SuppressWarnings("unchecked")
    void testSendMuitosFragmentosDeUmByteAcumuladosCompactamente(boolean direct) {
        int fragmentCount = 262_144;
        int maxBytes = 52_428_800;
        byte[] expected = new byte[fragmentCount];
        HttpClient client = mock(HttpClient.class);
        when(client.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        when(client.sendAsync(any(HttpRequest.class), any(BodyHandler.class))).thenAnswer(invocation -> {
            BodyHandler<byte[]> handler = invocation.getArgument(1);
            BodySubscriber<byte[]> subscriber = handler.apply(mock(HttpResponse.ResponseInfo.class));
            AtomicLong demand = new AtomicLong();
            subscriber.onSubscribe(new Subscription() {
                @Override
                public void request(long count) {
                    assertEquals(1, count);
                    assertEquals(1, demand.addAndGet(count), "Somente um lote pendente por vez");
                }

                @Override
                public void cancel() {
                    fail("Resposta dentro do limite nao deve ser cancelada");
                }
            });

            // Inspecao pontual do orcamento, sem expor detalhes do subscriber na API de producao.
            Field storage = subscriber.getClass().getDeclaredField("bytes");
            storage.setAccessible(true);
            assertEquals(0, ((byte[]) storage.get(subscriber)).length);
            ByteBuffer backing = direct ? ByteBuffer.allocateDirect(8192) : ByteBuffer.allocate(8192);
            for (int i = 0; i < fragmentCount; i++) {
                assertEquals(1, demand.getAndDecrement());
                expected[i] = (byte) i;
                backing.put(7, expected[i]);
                ByteBuffer fragment = backing.asReadOnlyBuffer().position(7).limit(8);
                subscriber.onNext(List.of(fragment));
                assertFalse(fragment.hasRemaining(), "Fragmento deve ser consumido durante onNext");
                backing.put(7, (byte) 0); // Reutilizacao nao pode alterar o corpo ja acumulado.
                if (i == 0 || i == 8192 || i == fragmentCount - 1) {
                    int capacity = ((byte[]) storage.get(subscriber)).length;
                    assertTrue(capacity >= i + 1);
                    assertTrue(capacity <= Math.max(8192, 2 * (i + 1)));
                    assertTrue(capacity < maxBytes, "Nao reservar o limite maximo antecipadamente");
                }
            }
            assertFalse(subscriber.getBody().toCompletableFuture().isDone());
            subscriber.onComplete();
            assertNull(storage.get(subscriber), "Acumulador deve ser liberado ao concluir");
            return subscriber.getBody().thenApply(body -> {
                HttpResponse<byte[]> response = mock(HttpResponse.class);
                when(response.statusCode()).thenReturn(200);
                when(response.body()).thenReturn(body);
                return response;
            }).toCompletableFuture();
        });

        CertificateHttpTransport compactTransport = new CertificateHttpTransport(client, policy);
        assertArrayEquals(expected, compactTransport.send(request(Duration.ofSeconds(5)), maxBytes));
    }

    @Test
    void testSendErroHttpDentroDoLimite() {
        serveBytes(503, new byte[10]);
        IOException failure = assertThrows(IOException.class,
                () -> transport.send(request(Duration.ofSeconds(2)), 1024));
        assertTrue(failure.getMessage().contains("503"));
    }

    @Test
    @SneakyThrows
    void testSendCorpoContinuoNaoRenovaPrazoTotal() {
        CountDownLatch disconnected = new CountDownLatch(1);
        serveOversized(200, disconnected, new AtomicInteger());
        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> assertThrows(HttpTimeoutException.class,
                () -> transport.send(request(Duration.ofMillis(500)), 10_485_760)));
        assertTrue(disconnected.await(3, TimeUnit.SECONDS));
    }

    @Test
    @SneakyThrows
    void testSendRetryRevalidaPoliticaAntesDeAcessarUrl() {
        AtomicInteger hits = new AtomicInteger();
        server.createContext("/artifact", exchange -> {
            hits.incrementAndGet();
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });
        doNothing().doThrow(new DownloadPolicyException("Destino deixou de ser permitido"))
                .when(policy).validateUrl(url);
        assertThrows(DownloadPolicyException.class, () -> new RetryPolicy(config).executeWithRetry(
                "download local", 2, 0, () -> transport.send(request(Duration.ofSeconds(2)), 1024)));
        assertEquals(1, hits.get());
        verify(policy, times(2)).validateUrl(url);
    }

    @Test
    @SneakyThrows
    void testResolveChainSucessoHttpLocal() {
        X509Certificate leaf = leafWithAia();
        serveBytes(200, issuer.getEncoded());
        CertificateChainResolver resolver = new CertificateChainResolver(
                new RetryPolicy(config), config.getChain(), httpClient, policy);
        assertEquals(List.of(leaf, issuer), resolver.resolveChain(leaf));
    }

    @Test
    @SneakyThrows
    void testOcspSucessoHttpLocal() {
        X509Certificate leaf = leafWithAia();
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID id = new CertificateID(digests.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuer), leaf.getSerialNumber());
        JcaBasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(issuerKey.getPublic(),
                digests.get(CertificateID.HASH_SHA1));
        builder.addResponse(id, CertificateStatus.GOOD);
        BasicOCSPResp basic = builder.build(new JcaContentSignerBuilder("SHA256WithRSA")
                .build(issuerKey.getPrivate()), new X509CertificateHolder[0], new Date());
        byte[] body = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
        AtomicReference<String> method = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        server.createContext("/artifact", exchange -> {
            method.set(exchange.getRequestMethod());
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        OcspClient client = new OcspClient(new RevocationCache(config), new RetryPolicy(config),
                config.getRevocation(), httpClient, policy);
        assertInstanceOf(RevocationStatus.Good.class, client.check(leaf, issuer, url));
        assertEquals("POST", method.get());
        assertEquals("application/ocsp-request", contentType.get());
    }

    @Test
    @SneakyThrows
    void testCrlSucessoHttpLocal() {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                new JcaX509CertificateHolder(issuer).getSubject(), new Date());
        builder.setNextUpdate(Date.from(Instant.now().plusSeconds(3600)));
        byte[] body = builder.build(new JcaContentSignerBuilder("SHA256WithRSA")
                .build(issuerKey.getPrivate())).getEncoded();
        serveBytes(200, body);
        CrlClient client = new CrlClient(new RevocationCache(config), new RetryPolicy(config),
                config.getRevocation(), httpClient, policy);
        assertInstanceOf(RevocationStatus.Good.class, client.check(leafWithAia(), issuer, url));
    }

    @ParameterizedTest
    @ValueSource(strings = {"AIA", "OCSP", "CRL"})
    @SneakyThrows
    void testClientesAplicamLimiteDuranteRecebimentoSemRetry(String artifact) {
        config.getDownloadPolicy().setMaxAiaResponseBytes(1024);
        config.getDownloadPolicy().setMaxOcspResponseBytes(1024);
        config.getDownloadPolicy().setMaxCrlResponseBytes(1024);
        AtomicInteger hits = new AtomicInteger();
        CountDownLatch disconnected = new CountDownLatch(1);
        serveOversized(500, disconnected, hits);
        RetryPolicy retry = new RetryPolicy(config);
        RevocationCache cache = spy(new RevocationCache(config));
        X509Certificate leaf = leafWithAia();
        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> {
            switch (artifact) {
                case "AIA" -> {
                    CertificateChainResolver resolver = new CertificateChainResolver(
                            retry, config.getChain(), httpClient, policy);
                    assertThrows(IncompleteChainException.class, () -> resolver.resolveChain(leaf));
                }
                case "OCSP" -> {
                    OcspClient client = new OcspClient(cache, retry, config.getRevocation(), httpClient, policy);
                    assertInstanceOf(RevocationStatus.OcspUnavailable.class, client.check(leaf, issuer, url));
                    verify(cache, never()).putOcsp(any(), any());
                }
                case "CRL" -> {
                    CrlClient client = new CrlClient(cache, retry, config.getRevocation(), httpClient, policy);
                    assertInstanceOf(RevocationStatus.CrlUnavailable.class, client.check(leaf, issuer, url));
                    assertTrue(cache.getCrl(url).isEmpty());
                }
                default -> fail("Artefato inesperado");
            }
        });
        assertTrue(disconnected.await(3, TimeUnit.SECONDS));
        assertEquals(1, hits.get(), "Bloqueios de politica nao devem ser repetidos");
    }

    private HttpRequest request(Duration timeout) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(timeout).GET().build();
    }

    private void serveBytes(int status, byte[] body) {
        server.createContext("/artifact", exchange -> {
            try {
                exchange.sendResponseHeaders(status, body.length);
                exchange.getResponseBody().write(body);
            } finally {
                exchange.close();
            }
        });
    }

    private void serveOversized(int status, CountDownLatch disconnected, AtomicInteger hits) {
        server.createContext("/artifact", exchange -> {
            hits.incrementAndGet();
            try {
                exchange.getRequestBody().readAllBytes();
                exchange.sendResponseHeaders(status, 0);
                byte[] chunk = new byte[2048];
                // Nao envia EOF: sucesso do teste depende de rejeitar durante a transferencia.
                long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
                while (System.nanoTime() < deadline) {
                    exchange.getResponseBody().write(chunk);
                    exchange.getResponseBody().flush();
                    Thread.sleep(5);
                }
            } catch (IOException e) {
                disconnected.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
    }

    @SneakyThrows
    private X509Certificate leafWithAia() {
        X509v3CertificateBuilder builder = createBuilder(
                new JcaX509CertificateHolder(issuer).getSubject(),
                new X500Name("CN=Local HTTP Leaf"), 42, leafKey);
        addSki(builder, leafKey);
        addAki(builder, issuerKey);
        addAia(builder, url);
        return sign(builder, issuerKey);
    }
}
