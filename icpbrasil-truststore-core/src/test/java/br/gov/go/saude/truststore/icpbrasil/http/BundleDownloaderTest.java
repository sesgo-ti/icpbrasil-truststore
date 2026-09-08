package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(15)
class BundleDownloaderTest {
    private static SSLContext serverContext;
    private static SSLContext dedicatedContext;
    private HttpsServer server;
    private ExecutorService executor;
    private HttpClient client;
    private TrustStoreConfig config;
    private Downloader downloader;
    private String url;

    @BeforeAll
    @SneakyThrows
    static void setUpTls() {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var key = generator.generateKeyPair();
        var name = new X500Name("CN=Local HTTPS Test");
        var builder = createBuilder(name, name, 1, key);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.iPAddress, "127.0.0.1")));
        var certificate = sign(builder, key);
        var store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        char[] password = "test-only".toCharArray();
        store.setKeyEntry("server", key.getPrivate(), password, new Certificate[]{certificate});
        var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, password);
        serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), null, null);
        var trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("local-test", certificate);
        var managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        dedicatedContext = SSLContext.getInstance("TLS");
        dedicatedContext.init(null, managers.getTrustManagers(), null);
    }

    @BeforeEach
    @SneakyThrows
    void setUp() {
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        executor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(executor);
        server.start();
        url = "https://127.0.0.1:" + server.getAddress().getPort() + "/bundle";
        client = HttpClient.newBuilder().sslContext(dedicatedContext)
                .followRedirects(HttpClient.Redirect.NEVER).build();
        config = new TrustStoreConfig();
        var network = new TrustStoreConfig.NetworkConfig();
        network.setDownloadTimeoutSeconds(1);
        network.setMaxRetries(1);
        config.setNetwork(network);
        config.getBundle().setMaxCompressedBytes(1024);
        config.getBundle().setMaxHashBytes(128);
        downloader = new Downloader(client, new RetryPolicy(config), config);
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
        executor.shutdownNow();
        client.shutdownNow();
    }

    @Test
    @SneakyThrows
    void testDownload_ConstrutorPublicoUsaTlsDedicadoSemAlterarJvmOuBloquearHostAdministrativo() {
        SSLContext defaultContext = SSLContext.getDefault();
        var manager = mock(TrustStoreManager.class);
        when(manager.getSslContext()).thenReturn(dedicatedContext);
        serve(new byte[1024], 200, false);
        var production = new Downloader(manager, new RetryPolicy(config), config);
        assertEquals(1024, production.downloadBytes(url).length);
        verify(manager).getSslContext();
        assertSame(defaultContext, SSLContext.getDefault());
        try (var untrustedClient = HttpClient.newBuilder().build()) {
            var untrusted = new Downloader(untrustedClient, new RetryPolicy(config), config);
            assertThrows(IOException.class, () -> untrusted.downloadBytes(url));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testDownload_CompressedExcedenteComOuSemContentLength_Rejeita(boolean chunked) {
        serve(new byte[1025], 200, chunked);
        assertThrows(DownloadPolicyException.class, () -> downloader.downloadBytes(url));
    }

    @Test
    @SneakyThrows
    void testDownload_HashTemLimiteProprio_AceitaExatoRejeitaExcedente() {
        serve("a".repeat(128).getBytes(), 200, true);
        assertEquals(128, downloader.downloadText(url).length());
        server.removeContext("/bundle");
        serve(new byte[129], 200, true);
        assertThrows(DownloadPolicyException.class, () -> downloader.downloadText(url));
        assertEquals(129, downloader.downloadBytes(url).length);
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 500})
    @SneakyThrows
    void testDownload_CorpoContinuoExcedente_CancelaSemEsperarFim(int status) {
        var disconnected = new CountDownLatch(1);
        server.createContext("/bundle", exchange -> {
            try {
                exchange.sendResponseHeaders(status, 0);
                for (int i = 0; i < 10_000; i++) {
                    exchange.getResponseBody().write(new byte[512]);
                    exchange.getResponseBody().flush();
                }
            } catch (IOException e) {
                disconnected.countDown();
            } finally {
                exchange.close();
            }
        });
        assertThrows(DownloadPolicyException.class, () -> downloader.downloadBytes(url));
        assertTrue(disconnected.await(3, TimeUnit.SECONDS));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @SneakyThrows
    void testDownload_PrazoTotalAbrangeStreamParadoOuLento(boolean slow) {
        var headers = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        server.createContext("/bundle", exchange -> {
            try {
                exchange.sendResponseHeaders(200, 0);
                exchange.getResponseBody().write(1);
                exchange.getResponseBody().flush();
                headers.countDown();
                if (slow) {
                    for (int i = 0; i < 100; i++) {
                        Thread.sleep(100);
                        exchange.getResponseBody().write(1);
                        exchange.getResponseBody().flush();
                    }
                } else {
                    release.await(10, TimeUnit.SECONDS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException ignored) {
                // O cliente fecha o stream ao atingir o prazo total.
            } finally {
                exchange.close();
            }
        });
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(3),
                    () -> assertThrows(HttpTimeoutException.class, () -> downloader.downloadBytes(url)));
            assertEquals(0, headers.getCount());
        } finally {
            release.countDown();
        }
    }

    @Test
    void testDownload_RedirectNaoAcessaDestino() {
        var hits = new AtomicInteger();
        server.createContext("/bundle", exchange -> {
            exchange.getResponseHeaders().set("Location", url.replace("/bundle", "/target"));
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/target", exchange -> {
            hits.incrementAndGet();
            exchange.close();
        });
        assertThrows(DownloadPolicyException.class, () -> downloader.downloadBytes(url));
        assertEquals(0, hits.get());
        assertThrows(IOException.class, () -> downloader.downloadBytes(url.replace("https:", "http:")));
    }

    @Test
    @SneakyThrows
    void testDownload_InterrupcaoCancelaEPreservaFlagSemRetry() {
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var failure = new AtomicReference<Throwable>();
        var interrupted = new AtomicReference<Boolean>();
        server.createContext("/bundle", exchange -> {
            try {
                exchange.sendResponseHeaders(200, 0);
                exchange.getResponseBody().write(1);
                exchange.getResponseBody().flush();
                entered.countDown();
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        Thread caller = Thread.ofVirtual().start(() -> {
            try {
                downloader.downloadBytes(url);
            } catch (Throwable e) {
                failure.set(e);
                interrupted.set(Thread.currentThread().isInterrupted());
            }
        });
        try {
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            caller.interrupt();
            caller.join(3000);
            assertFalse(caller.isAlive());
            assertInstanceOf(IOException.class, failure.get());
            assertEquals(true, interrupted.get());
        } finally {
            release.countDown();
            caller.interrupt();
        }
    }

    private void serve(byte[] bytes, int status, boolean chunked) {
        server.createContext("/bundle", exchange -> {
            try {
                exchange.sendResponseHeaders(status, chunked ? 0 : bytes.length);
                exchange.getResponseBody().write(bytes);
            } finally {
                exchange.close();
            }
        });
    }
}
