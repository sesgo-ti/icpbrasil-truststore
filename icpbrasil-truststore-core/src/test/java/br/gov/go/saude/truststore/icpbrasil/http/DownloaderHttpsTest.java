package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercita o {@link Downloader} contra um servidor HTTPS local cujo certificado é a única
 * âncora do {@link TrustStoreManager}, reproduzindo o isolamento de TLS usado em produção.
 */
class DownloaderHttpsTest {

    private HttpsServer server;
    private ExecutorService executor;
    private String baseUrl;
    private Downloader downloader;

    @BeforeEach
    @SneakyThrows
    void setUp() {
        KeyPair keyPair = TestBundleFactory.newKeyPair();
        X509Certificate serverCert = serverCertificate(keyPair);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", keyPair.getPrivate(), new char[0], new Certificate[]{serverCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        // Bind explícito em IPv4 para que a URL montada e o SAN iPAddress do certificado coincidam.
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        executor = Executors.newCachedThreadPool();
        server.setExecutor(executor);
        server.start();
        InetSocketAddress bound = server.getAddress();
        baseUrl = "https://" + bound.getHostString() + ":" + bound.getPort();

        TrustStoreConfig config = buildConfig();
        TrustStoreManager trustStoreManager = new TrustStoreManager(() -> List.of(serverCert));
        downloader = new Downloader(trustStoreManager, new RetryPolicy(config), config);
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
        executor.shutdownNow();
    }

    @SneakyThrows
    @Test
    void testDownloadBytes_Status200_RetornaCorpoCompleto() {
        byte[] esperado = new byte[200_000];
        for (int i = 0; i < esperado.length; i++) {
            esperado[i] = (byte) i;
        }
        server.createContext("/bundle.zip", fixedLength(200, esperado));

        byte[] corpo = downloader.downloadBytes(baseUrl + "/bundle.zip");

        assertArrayEquals(esperado, corpo);
    }

    @SneakyThrows
    @Test
    void testDownloadText_Status200_RetornaTextoUtf8() {
        server.createContext("/hash.txt", fixedLength(200, "abc123  ACcompactado.zip\n".getBytes(StandardCharsets.UTF_8)));

        assertEquals("abc123  ACcompactado.zip\n", downloader.downloadText(baseUrl + "/hash.txt"));
    }

    @Test
    void testDownloadBytes_Redirect302_LancaIOExceptionSemSeguir() {
        AtomicInteger destinoAcessado = new AtomicInteger();
        server.createContext("/destino", exchange -> {
            destinoAcessado.incrementAndGet();
            fixedLength(200, "seguiu".getBytes(StandardCharsets.UTF_8)).handle(exchange);
        });
        server.createContext("/antigo", exchange -> {
            exchange.getResponseHeaders().add("Location", baseUrl + "/destino");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        IOException ex = assertThrows(IOException.class, () -> downloader.downloadBytes(baseUrl + "/antigo"));

        assertTrue(ex.getMessage().contains("302"), ex.getMessage());
        assertEquals(0, destinoAcessado.get());
    }

    @Test
    void testDownloadBytes_Status404_LancaIOException() {
        server.createContext("/ausente", fixedLength(404, "nao encontrado".getBytes(StandardCharsets.UTF_8)));

        IOException ex = assertThrows(IOException.class, () -> downloader.downloadBytes(baseUrl + "/ausente"));

        assertTrue(ex.getMessage().contains("404"), ex.getMessage());
    }

    @Test
    void testDownloadText_CorpoExcedeMaxTextBytes_LancaIOException() {
        byte[] excedente = new byte[Downloader.MAX_TEXT_BYTES + 1];
        server.createContext("/hash.txt", fixedLength(200, excedente));

        IOException ex = assertThrows(IOException.class, () -> downloader.downloadText(baseUrl + "/hash.txt"));

        assertTrue(ex.getMessage().contains("limite"), ex.getMessage());
    }

    @Test
    void testDownloadBytes_UrlHttp_LancaIOException() {
        IOException ex = assertThrows(IOException.class,
                () -> downloader.downloadBytes("http://127.0.0.1:1/bundle.zip"));

        assertTrue(ex.getMessage().contains("HTTPS"), ex.getMessage());
    }

    @SneakyThrows
    private static X509Certificate serverCertificate(KeyPair keyPair) {
        X500Name name = new X500Name("CN=127.0.0.1, O=Test, C=BR");
        X509v3CertificateBuilder builder = TestCertificateFactory.createBuilder(name, name, 1, keyPair);
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.iPAddress, "127.0.0.1")));
        TestCertificateFactory.addSki(builder, keyPair);
        return TestCertificateFactory.sign(builder, keyPair);
    }

    private static HttpHandler fixedLength(int status, byte[] body) {
        return exchange -> {
            exchange.sendResponseHeaders(status, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        };
    }

    private static TrustStoreConfig buildConfig() {
        TrustStoreConfig config = new TrustStoreConfig();
        TrustStoreConfig.NetworkConfig network = new TrustStoreConfig.NetworkConfig();
        network.setDownloadTimeoutSeconds(5);
        // Uma única tentativa: o comportamento sob teste é o de cada tentativa, não o retry.
        network.setMaxRetries(1);
        network.setRetryIntervalSeconds(10);
        config.setNetwork(network);
        return config;
    }
}
