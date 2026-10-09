package br.gov.go.saude.truststore.icpbrasil.lifecycle;

import br.gov.go.saude.truststore.icpbrasil.config.IcpBrasilEndpoints;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import br.gov.go.saude.truststore.icpbrasil.service.RaizesFixadas;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestClock;
import br.gov.go.saude.truststore.icpbrasil.util.HashValidator;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * O snapshot é publicado pelo pipeline real ({@link TrustStoreService} com {@link Downloader}
 * mockado), pois a escrita do {@link Cache} é restrita ao pacote do core. O relógio do cache é
 * controlado pelo teste; a idade da confirmação é medida pelo indicador com o relógio do sistema,
 * por isso os instantes de confirmação são fixados em relação a {@link Instant#now()}.
 */
class TrustStoreCacheHealthIndicatorTest {

    private static final Duration TTL_CRITICAL = Duration.ofHours(72);
    private static final Duration TTL_MAX = Duration.ofHours(168);

    static X509Certificate root;
    static byte[] zip;
    static String hash;

    @TempDir
    Path baseDir;

    TrustStoreConfig config;
    Downloader downloader;
    TestClock clock;
    Cache cache;
    TrustStoreService service;
    TrustStoreCacheHealthIndicator indicator;

    @BeforeAll
    static void generateBundle() {
        root = TestBundleFactory.caCert("Raiz A", TestBundleFactory.newKeyPair());
        zip = TestBundleFactory.bundleOf(root);
        hash = HashValidator.computeSha512(zip);
    }

    @BeforeEach
    void setUp() {
        config = new TrustStoreConfig();
        config.setCacheTtlCriticalHours((int) TTL_CRITICAL.toHours());
        config.setCacheTtlMaxHours((int) TTL_MAX.toHours());
        config.getFilesystem().setBaseDir(baseDir.toString());
        downloader = mock(Downloader.class);
        clock = new TestClock(Instant.now());
        cache = new Cache(clock);
        FilesystemTrustStoreRepository repository = new FilesystemTrustStoreRepository(config);
        IcpBrasilCertificateProvider provider = new IcpBrasilCertificateProvider(downloader, repository);
        service = new TrustStoreService(repository, provider, config, cache,
                RaizesFixadas.de(Set.of(CertificateParser.getFingerprintSha256(root))), clock);
        indicator = new TrustStoreCacheHealthIndicator(config, cache);
    }

    @Test
    void testHealth_SemSnapshot_DownUnavailableSemOutrosDetalhes() {
        Health health = indicator.health();

        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("UNAVAILABLE", health.getDetails().get("status"));
        assertEquals(Set.of("status"), health.getDetails().keySet());
    }

    @Test
    void testHealth_ConfirmacaoRecente_UpValidComInstantesDoSnapshot() {
        publicar(Instant.now());

        Health health = indicator.health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals("VALID", health.getDetails().get("status"));
        assertDetalhesDoSnapshot(health);
    }

    @Test
    void testHealth_ConfirmacaoAlemDoTtlCritico_UpCritical() {
        publicar(Instant.now().minus(TTL_CRITICAL).minus(Duration.ofHours(1)));

        Health health = indicator.health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals("CRITICAL", health.getDetails().get("status"));
        assertDetalhesDoSnapshot(health);
    }

    @Test
    void testHealth_SnapshotExpiradoPeloRelogio_DownExpired() {
        publicar(Instant.now());
        clock.advance(TTL_MAX);

        Health health = indicator.health();

        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("EXPIRED", health.getDetails().get("status"));
        assertDetalhesDoSnapshot(health);
    }

    @Test
    @SneakyThrows
    void testHealth_RaizDescartada_UpComDetalheRaizesNaoFixadas() {
        X509Certificate estranha = TestBundleFactory.caCert("Estranha", TestBundleFactory.newKeyPair());
        byte[] zipComEstranha = TestBundleFactory.bundleOf(root, estranha);
        String hashComEstranha = HashValidator.computeSha512(zipComEstranha);
        when(downloader.downloadText(IcpBrasilEndpoints.BUNDLE_HASH_URL)).thenReturn(hashComEstranha + "  ACcompactado.zip\n");
        when(downloader.downloadBytes(IcpBrasilEndpoints.BUNDLE_ZIP_URL)).thenReturn(zipComEstranha);
        service.refresh();

        Health health = indicator.health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals(List.of(Map.of(
                        "subject", estranha.getSubjectX500Principal().getName(),
                        "fingerprintSha256", CertificateParser.getFingerprintSha256(estranha))),
                health.getDetails().get("raizesNaoFixadas"));
    }

    /** Publica via pipeline real com a confirmação no instante indicado. */
    @SneakyThrows
    private void publicar(Instant confirmadoEm) {
        clock.set(confirmadoEm);
        when(downloader.downloadText(IcpBrasilEndpoints.BUNDLE_HASH_URL)).thenReturn(hash + "  ACcompactado.zip\n");
        when(downloader.downloadBytes(IcpBrasilEndpoints.BUNDLE_ZIP_URL)).thenReturn(zip);
        service.refresh();
        assertTrue(cache.isCacheValid(), "pré-condição: snapshot publicado");
        assertEquals(confirmadoEm, cache.getState().orElseThrow().confirmedAt());
    }

    /** Detalhes são exatamente status, confirmedAt e expiresAt do snapshot — nada de exceções. */
    private void assertDetalhesDoSnapshot(Health health) {
        Cache.State state = cache.getState().orElseThrow();
        assertEquals(Set.of("status", "confirmedAt", "expiresAt"), health.getDetails().keySet());
        assertEquals(state.confirmedAt().toString(), health.getDetails().get("confirmedAt"));
        assertEquals(state.expiresAt().toString(), health.getDetails().get("expiresAt"));
    }
}
