package br.gov.go.saude.truststore.icpbrasil;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreCacheHealthIndicator;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.support.GenericApplicationContext;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(60)
class TrustStoreHttpTest {
    private static final Instant NOW = Instant.parse("2026-09-01T00:00:00Z");
    private static Bundle first;
    private static Bundle second;

    @BeforeAll
    @SneakyThrows
    static void setUpCertificates() {
        first = bundle(1);
        second = bundle(2);
    }

    @Test
    @SneakyThrows
    void testHttp_IndisponivelValidoCriticoExpiradoERecuperado_SemIoNasConsultas() {
        Fixture fixture = new Fixture();
        try (var context = fixture.start(false); var client = HttpClient.newHttpClient()) {
            int port = context.getWebServer().getPort();
            var service = context.getBean(TrustStoreService.class);
            var health = context.getBean(TrustStoreCacheHealthIndicator.class);
            assertHealth(client, port, "readiness", 503, "DOWN");
            assertHealth(client, port, "liveness", 200, "UP");
            assertCertificateUnavailable(client, port);
            assertEquals("UNAVAILABLE", health.health().getDetails().get("status"));
            verifyNoInteractions(fixture.repository, fixture.downloader);

            fixture.remote(first);
            service.refresh();
            clearInvocations(fixture.repository, fixture.downloader);
            assertHealth(client, port, "readiness", 200, "UP");
            assertHealth(client, port, "", 200, "UP");
            assertEquals("VALID", health.health().getDetails().get("status"));
            assertCertificate(client, port, first);
            var missing = get(client, port, "/certificate?ski=missing");
            assertEquals(404, missing.statusCode());
            assertEquals("no-store", missing.headers().firstValue("Cache-Control").orElseThrow());

            fixture.at(NOW.plus(Duration.ofHours(72)));
            assertEquals("VALID", health.health().getDetails().get("status"));
            fixture.at(NOW.plus(Duration.ofHours(72)).plusNanos(1));
            assertEquals("CRITICAL", health.health().getDetails().get("status"));
            assertHealth(client, port, "readiness", 200, "UP");
            assertCertificate(client, port, first);

            fixture.at(NOW.plus(Duration.ofHours(168)).minusNanos(1));
            assertHealth(client, port, "readiness", 200, "UP");
            fixture.at(NOW.plus(Duration.ofHours(168)));
            assertEquals("EXPIRED", health.health().getDetails().get("status"));
            assertHealth(client, port, "readiness", 503, "DOWN");
            assertHealth(client, port, "", 503, "DOWN");
            assertHealth(client, port, "liveness", 200, "UP");
            assertCertificateUnavailable(client, port);
            verifyNoInteractions(fixture.repository, fixture.downloader);

            fixture.remote(second);
            service.refresh();
            clearInvocations(fixture.repository, fixture.downloader);
            assertNotEquals(first.hash(), fixture.cache.getState().orElseThrow().hash());
            assertEquals("VALID", health.health().getDetails().get("status"));
            assertHealth(client, port, "readiness", 200, "UP");
            assertHealth(client, port, "liveness", 200, "UP");
            assertCertificate(client, port, second);
            assertEquals(404, get(client, port, "/certificate?ski=" + first.ski()).statusCode());
            verifyNoInteractions(fixture.repository, fixture.downloader);
        }
    }

    @Test
    @SneakyThrows
    void testHttp_RefreshFalhaERelogioRetrocede_FalhaFechadoSemExporExcecao() {
        Fixture fixture = new Fixture();
        try (var context = fixture.start(false); var client = HttpClient.newHttpClient()) {
            int port = context.getWebServer().getPort();
            var service = context.getBean(TrustStoreService.class);
            fixture.remote(first);
            service.refresh();
            when(fixture.downloader.downloadText(anyString()))
                    .thenThrow(new IllegalStateException("secret-storage-host/internal-path"));
            service.refresh();
            assertEquals(NOW, fixture.cache.getState().orElseThrow().confirmedAt());
            clearInvocations(fixture.repository, fixture.downloader);
            assertHealth(client, port, "readiness", 200, "UP");
            fixture.at(NOW.minusNanos(1));
            assertHealth(client, port, "readiness", 503, "DOWN");
            assertHealth(client, port, "liveness", 200, "UP");
            assertCertificateUnavailable(client, port);
            var health = context.getBean(TrustStoreCacheHealthIndicator.class).health();
            assertEquals(Status.DOWN, health.getStatus());
            assertEquals("EXPIRED", health.getDetails().get("status"));
            assertFalse(health.toString().contains("secret-storage-host"));
            verifyNoInteractions(fixture.repository, fixture.downloader);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @SneakyThrows
    void testStartup_RunnerPendente_HttpAceitaMasReadinessRecusaMesmoComCacheLocal(boolean local) {
        Fixture fixture = new Fixture();
        fixture.remote(first);
        if (local) {
            when(fixture.repository.recuperarZip()).thenReturn(Optional.of(first.zip()));
            when(fixture.repository.recuperarHash()).thenReturn(Optional.of(first.hash()));
            when(fixture.repository.recuperarUltimaConfirmacao()).thenReturn(Optional.of(NOW));
        }
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(fixture.downloader.downloadText(anyString())).thenAnswer(invocation -> {
            entered.countDown();
            if (!release.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timeout aguardando liberacao do runner de teste");
            }
            return first.hash();
        });
        CompletableFuture<ServletWebServerApplicationContext> server = new CompletableFuture<>();
        fixture.application.addListeners(event -> {
            if (event instanceof WebServerInitializedEvent initialized) {
                server.complete((ServletWebServerApplicationContext) initialized.getApplicationContext());
            }
        });
        var executor = Executors.newSingleThreadExecutor();
        var startup = executor.submit(() -> fixture.start(true));
        ServletWebServerApplicationContext context = null;
        try (var client = HttpClient.newHttpClient()) {
            context = server.get(30, TimeUnit.SECONDS);
            assertTrue(entered.await(10, TimeUnit.SECONDS));
            assertFalse(startup.isDone());
            int port = context.getWebServer().getPort();
            clearInvocations(fixture.repository, fixture.downloader);
            assertHealth(client, port, "readiness", 503, local ? "OUT_OF_SERVICE" : "DOWN");
            assertHealth(client, port, "liveness", 200, "UP");
            if (local) {
                assertCertificate(client, port, first);
                assertEquals(Status.UP, context.getBean(TrustStoreCacheHealthIndicator.class).health().getStatus());
            } else {
                assertCertificateUnavailable(client, port);
            }
            verifyNoInteractions(fixture.repository, fixture.downloader);
            release.countDown();
            assertSame(context, startup.get(15, TimeUnit.SECONDS));
            assertHealth(client, port, "readiness", 200, "UP");
            assertCertificate(client, port, first);
        } finally {
            release.countDown();
            try {
                startup.get(15, TimeUnit.SECONDS).close();
            } finally {
                if (context != null) {
                    context.close();
                }
                executor.shutdownNow();
                assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
            }
        }
    }

    @SneakyThrows
    private static HttpResponse<byte[]> get(HttpClient client, int port, String path) {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(5)).GET().build(), BodyHandlers.ofByteArray());
    }

    @SneakyThrows
    private static void assertHealth(HttpClient client, int port, String group, int code, String status) {
        var response = get(client, port, "/actuator/health" + (group.isEmpty() ? "" : "/" + group));
        assertEquals(code, response.statusCode());
        var body = new ObjectMapper().readTree(response.body());
        assertEquals(status, body.path("status").asText());
        assertFalse(body.has("components"));
        assertFalse(body.has("details"));
        assertEquals(group.isEmpty() ? 2 : 1, body.size(), "Health publico so expoe status e nomes dos grupos");
        if (group.isEmpty()) {
            assertTrue(body.path("groups").isArray());
        }
    }

    private static void assertCertificateUnavailable(HttpClient client, int port) {
        var response = get(client, port, "/certificate?ski=" + first.ski());
        assertEquals(503, response.statusCode());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
    }

    @SneakyThrows
    private static void assertCertificate(HttpClient client, int port, Bundle bundle) {
        for (String type : new String[]{"pem", "der"}) {
            var response = get(client, port, "/certificate?ski=" + bundle.ski()
                    + (type.equals("pem") ? "" : "&type=der"));
            assertEquals(200, response.statusCode());
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
            String contentType = response.headers().firstValue("Content-Type").orElseThrow();
            assertTrue(contentType.startsWith(type.equals("pem") ? "text/plain" : "application/x-x509-ca-cert"));
            var parsed = CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(response.body()));
            assertArrayEquals(bundle.certificate().getEncoded(), parsed.getEncoded());
            if (type.equals("der")) {
                assertArrayEquals(bundle.certificate().getEncoded(), response.body());
                assertTrue(response.headers().firstValue("Content-Disposition").orElseThrow()
                        .contains(bundle.ski() + ".der"));
            }
        }
    }

    @SneakyThrows
    private static Bundle bundle(int serial) {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var keys = generator.generateKeyPair();
        var name = new X500Name("CN=Synthetic CA " + serial);
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(serial),
                Date.from(NOW.minus(Duration.ofDays(1))), Date.from(NOW.plus(Duration.ofDays(365))),
                name, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keys.getPublic()));
        var certificate = new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("ca.der"));
            zip.write(certificate.getEncoded());
            zip.closeEntry();
        }
        byte[] zip = bytes.toByteArray();
        return new Bundle(certificate, CertificateParser.getSubjectKeyIdentifier(certificate), zip,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-512").digest(zip)));
    }

    private record Bundle(X509Certificate certificate, String ski, byte[] zip, String hash) {}

    private static class Fixture {
        final Clock clock = mock(Clock.class);
        final Cache cache = new Cache(clock);
        final TrustStoreRepository repository = mock(TrustStoreRepository.class);
        final Downloader downloader = mock(Downloader.class);
        final SpringApplication application = new SpringApplication(TrustStoreApplication.class);

        Fixture() {
            at(NOW);
            application.addInitializers(context -> {
                var beans = (GenericApplicationContext) context;
                beans.registerBean("trustStoreCache", Cache.class, () -> cache);
                beans.registerBean("testRepository", TrustStoreRepository.class, () -> repository);
                beans.registerBean("downloader", Downloader.class, () -> downloader);
            });
        }

        ServletWebServerApplicationContext start(boolean bootstrap) {
            return (ServletWebServerApplicationContext) application.run("--server.port=0",
                    "--icpbrasil-truststore.bootstrap.enabled=" + bootstrap,
                    "--icpbrasil-truststore.scheduling.enabled=false");
        }

        void at(Instant instant) {
            when(clock.instant()).thenReturn(instant);
        }

        @SneakyThrows
        void remote(Bundle bundle) {
            var config = new TrustStoreConfig();
            when(downloader.downloadText(config.getHashUrl())).thenReturn(bundle.hash());
            when(downloader.downloadBytes(config.getCertificateUrl())).thenReturn(bundle.zip());
        }
    }
}
