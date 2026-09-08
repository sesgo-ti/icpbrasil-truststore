package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static br.gov.go.saude.truststore.icpbrasil.support.TestBundle.*;
import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.generateRootCert;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(15)
class TrustStoreServiceTest {
    private static final Instant NOW = Instant.parse("2026-09-01T00:00:00Z");
    private static X509Certificate caA;
    private static X509Certificate caB;
    private static byte[] zipA;
    private static byte[] zipB;

    @TempDir
    Path directory;
    private TrustStoreConfig config;
    private TrustStoreRepository repository;
    private Downloader downloader;
    private Clock clock;
    private Cache cache;
    private IcpBrasilCertificateProvider provider;
    private TrustStoreService service;

    @BeforeAll
    @SneakyThrows
    static void setUpCertificates() {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        caA = generateRootCert(generator.generateKeyPair());
        caB = generateRootCert(generator.generateKeyPair());
        zipA = zip(caA);
        zipB = zip(caB);
    }

    @BeforeEach
    @SneakyThrows
    void setUp() {
        config = new TrustStoreConfig();
        config.setCacheTtlMaxHours(1);
        config.setCertificateUrl("https://iti.example/bundle.zip");
        config.setHashUrl("https://iti.example/hash.txt");
        var storage = new TrustStoreConfig.StorageConfig();
        storage.setTruststoreArchivePath("bundle.zip");
        storage.setHashFilePath("hash.txt");
        storage.setConfirmationFilePath("confirmation.txt");
        config.setStorage(storage);
        var filesystem = new TrustStoreConfig.FilesystemConfig();
        filesystem.setBaseDir(directory.toString());
        config.setFilesystem(filesystem);
        repository = spy(new FilesystemTrustStoreRepository(config));
        downloader = mock(Downloader.class);
        clock = mock(Clock.class);
        when(clock.instant()).thenReturn(NOW);
        cache = new Cache(clock);
        provider = new IcpBrasilCertificateProvider(config, downloader, repository);
        service = new TrustStoreService(repository, provider, config, cache);
        remote(zipA);
    }

    @Test
    void testRefresh_PublicaGeracaoCompletaA_B_ReconfirmaSemBaixarZip() {
        service.refresh();
        assertGeneration(caA, zipA, NOW);
        advance(100);
        service.refresh();
        assertGeneration(caA, zipA, NOW.plusSeconds(100));
        advance(200);
        remote(zipB);
        service.refresh();
        assertGeneration(caB, zipB, NOW.plusSeconds(200));
        advance(300);
        service.refresh();
        assertGeneration(caB, zipB, NOW.plusSeconds(300));
        verifyDownloads(2, 4);
    }

    @Test
    void testRefresh_BComHashValidoMasParsingInvalido_NaoRenovaAEmConfirmacoesRepetidas() {
        service.refresh();
        byte[] corruptB = zip(Map.of("ca.crt", new byte[]{1, 2, 3}));
        remote(corruptB);
        for (int seconds : new int[]{100, 1000, 3500}) {
            advance(seconds);
            service.refresh();
            assertGeneration(caA, zipA, NOW);
            assertEquals(NOW, repository.recuperarUltimaConfirmacao().orElseThrow());
            assertArrayEquals(zipA, repository.recuperarZip().orElseThrow());
        }
        advance(3600);
        assertExpired();
        service.refresh();
        assertExpired();
        remote(zipB);
        service.refresh();
        assertGeneration(caB, zipB, NOW.plusSeconds(3600));
    }

    @Test
    @SneakyThrows
    void testRefresh_HashRemotoBDownloadA_NaoConfirmaNemPersiste() {
        service.refresh();
        advance(100);
        when(downloader.downloadText(config.getHashUrl())).thenReturn(hash(zipB));
        service.refresh();
        assertGeneration(caA, zipA, NOW);
        assertEquals(hash(zipA), repository.recuperarHash().orElseThrow());
        assertEquals(NOW, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @Test
    void testRefresh_HashLocalRemotoBMasZipCorrompido_NaoRenovaIndiceA() {
        service.refresh();
        byte[] corruptB = zip(Map.of("invalid.crt", new byte[]{0}));
        repository.armazenarZip(corruptB);
        repository.armazenarHash(hash(corruptB));
        remote(corruptB);
        advance(100);
        service.refresh();
        advance(200);
        service.refresh();
        assertGeneration(caA, zipA, NOW);
        assertEquals(NOW, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @Test
    void testRefresh_HashRemotoBComZipLocalB_PublicaBEmVezDeRenovarA() {
        service.refresh();
        repository.armazenarZip(zipB);
        repository.armazenarHash(hash(zipB));
        remote(zipB);
        advance(100);
        service.refresh();
        assertGeneration(caB, zipB, NOW.plusSeconds(100));
        verifyDownloads(1, 2);
    }

    @Test
    void testLeituras_ExpiramSemRefreshNoLimiteEIsTrustedRootFalhaFechado() {
        service.refresh();
        advance(3599);
        assertTrue(service.isTrustedRoot(caA));
        advance(3600);
        assertExpired();
        assertFalse(service.isTrustedRoot(caA));
        assertEquals(NOW, cache.getState().orElseThrow().confirmedAt());
        verifyDownloads(1, 1);
    }

    @Test
    @SneakyThrows
    void testColdStartup_StorageLegadoOffline_PreservaFormatoEValidadeOriginal() {
        Instant original = NOW.minusSeconds(1800);
        repository.armazenarZip(zipA);
        repository.armazenarHash(hash(zipA));
        Files.writeString(directory.resolve("confirmation.txt"), original.toString());
        offline();
        service.refresh();
        assertGeneration(caA, zipA, original);
        assertEquals(original.toString(), Files.readString(directory.resolve("confirmation.txt")));
        advance(1800);
        assertExpired();
        service.refresh();
        assertExpired();
        assertEquals(original, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @ParameterizedTest
    @ValueSource(longs = {-3600, 1, 3600})
    void testColdStartup_ConfirmacaoExpiradaOuFuturaOffline_NaoPublica(long offset) {
        repository.armazenarZip(zipA);
        repository.armazenarHash(hash(zipA));
        repository.armazenarUltimaConfirmacao(NOW.plusSeconds(offset));
        offline();
        service.refresh();
        assertExpired();
        assertTrue(cache.getState().isEmpty());
    }

    @Test
    void testColdStartup_FalhaTransitoriaStorageOffline_RecuperaNaSegundaChamadaSemRenovarPrazo() {
        Instant original = NOW.minusSeconds(1800);
        repository.armazenarZip(zipA);
        repository.armazenarHash(hash(zipA));
        repository.armazenarUltimaConfirmacao(original);
        doThrow(new IllegalStateException("storage temporariamente indisponivel"))
                .doCallRealMethod().when(repository).recuperarZip();
        offline();
        service.refresh();
        assertExpired();
        advance(100);
        service.refresh();
        assertGeneration(caA, zipA, original);
        verify(repository, times(2)).recuperarZip();
        verify(repository, times(1)).armazenarUltimaConfirmacao(original);
        assertEquals(original, repository.recuperarUltimaConfirmacao().orElseThrow());
        advance(1800);
        service.refresh();
        assertExpired();
        verify(repository, times(2)).recuperarZip();
        verifyDownloads(0, 3);
    }

    @Test
    void testColdStartup_FalhaTransitoriaSeguidaDeInvalidacao_NaoRecarregaLocal() {
        repository.armazenarZip(zipA);
        repository.armazenarHash(hash(zipA));
        repository.armazenarUltimaConfirmacao(NOW);
        doThrow(new IllegalStateException("storage temporariamente indisponivel"))
                .doCallRealMethod().when(repository).recuperarZip();
        offline();
        service.refresh();
        cache.invalidate();
        service.refresh();
        assertExpired();
        verify(repository, times(1)).recuperarZip();
    }

    @Test
    void testColdStartup_FalhaLocalMasPublicacaoRemotaBemSucedida_NaoSubstituiPorLocalAntigo() {
        doThrow(new IllegalStateException("storage temporariamente indisponivel"))
                .doCallRealMethod().when(repository).recuperarZip();
        remote(zipB);
        service.refresh();
        assertGeneration(caB, zipB, NOW);
        repository.armazenarZip(zipA);
        repository.armazenarHash(hash(zipA));
        repository.armazenarUltimaConfirmacao(NOW.minusSeconds(100));
        offline();
        service.refresh();
        assertGeneration(caB, zipB, NOW);
        verify(repository, times(2)).recuperarZip();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @SneakyThrows
    void testColdStartup_InvalidacaoOuPublicacaoDuranteLeitura_NaoPublicaLocalObsoleto(boolean invalidate) {
        repository.armazenarZip(zipA);
        repository.armazenarHash(hash(zipA));
        repository.armazenarUltimaConfirmacao(NOW.minusSeconds(100));
        offline();
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        doAnswer(invocation -> {
            entered.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return invocation.callRealMethod();
        }).when(repository).recuperarZip();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var task = executor.submit(service::refresh);
            try {
                assertTrue(entered.await(5, TimeUnit.SECONDS));
                if (invalidate) {
                    cache.invalidate();
                } else {
                    assertTrue(cache.publish(provider.parseSnapshot(zipB, hash(zipB)), NOW,
                            config.getCacheTtlMaxMillis(), cache.version(), () -> {}));
                }
            } finally {
                release.countDown();
            }
            task.get(5, TimeUnit.SECONDS);
        }
        service.refresh();
        if (invalidate) {
            assertExpired();
        } else {
            assertGeneration(caB, zipB, NOW);
        }
        verify(repository, times(1)).recuperarZip();
    }

    @Test
    void testColdStartup_ConfirmacaoAusenteOuHashInvalidoOffline_NaoPublica() {
        repository.armazenarZip(zipA);
        repository.armazenarHash(hash(zipB));
        repository.armazenarUltimaConfirmacao(NOW);
        offline();
        service.refresh();
        assertExpired();
        doReturn(Optional.empty()).when(repository).recuperarUltimaConfirmacao();
        repository.armazenarHash(hash(zipA));
        new TrustStoreService(repository, provider, config, cache).refresh();
        assertExpired();
    }

    @Test
    void testClock_AnteriorAConfirmacao_FalhaFechado() {
        service.refresh();
        advance(-1);
        assertExpired();
    }

    @ParameterizedTest
    @ValueSource(strings = {"zip", "hash", "confirmation"})
    void testRefresh_FalhaPersistencia_NaoPublicaNemRenovaA(String step) {
        service.refresh();
        remote(zipB);
        advance(100);
        switch (step) {
            case "zip" -> doThrow(new IllegalStateException("storage offline")).when(repository).armazenarZip(any());
            case "hash" -> doThrow(new IllegalStateException("storage offline")).when(repository).armazenarHash(any());
            default -> doThrow(new IllegalStateException("storage offline")).when(repository).armazenarUltimaConfirmacao(any());
        }
        service.refresh();
        assertGeneration(caA, zipA, NOW);
        assertEquals(NOW, repository.recuperarUltimaConfirmacao().orElseThrow());
        advance(3600);
        assertExpired();
    }

    @Test
    @SneakyThrows
    void testRefresh_InvalidacaoDuranteDownload_NaoPersisteNemRepublica_ProximoRefreshRecupera() {
        service.refresh();
        remote(zipB);
        advance(100);
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        when(downloader.downloadBytes(config.getCertificateUrl())).thenAnswer(invocation -> {
            entered.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return zipB;
        });
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var task = executor.submit(service::refresh);
            try {
                assertTrue(entered.await(5, TimeUnit.SECONDS));
                cache.invalidate();
                assertExpired();
            } finally {
                release.countDown();
            }
            task.get(5, TimeUnit.SECONDS);
        }
        assertExpired();
        assertArrayEquals(zipA, repository.recuperarZip().orElseThrow());
        assertEquals(NOW, repository.recuperarUltimaConfirmacao().orElseThrow());
        remote(zipB);
        service.refresh();
        assertGeneration(caB, zipB, NOW.plusSeconds(100));
    }

    @Test
    @SneakyThrows
    void testRefresh_Concorrentes_SerializamDownloadParsingEPersistencia() {
        var active = new AtomicInteger();
        var maxActive = new AtomicInteger();
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        when(downloader.downloadText(config.getHashUrl())).thenAnswer(invocation -> {
            maxActive.accumulateAndGet(active.incrementAndGet(), Math::max);
            entered.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            active.decrementAndGet();
            return hash(zipA);
        });
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var first = executor.submit(service::refresh);
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            var second = executor.submit(service::refresh);
            release.countDown();
            first.get(5, TimeUnit.SECONDS);
            second.get(5, TimeUnit.SECONDS);
        }
        assertEquals(1, maxActive.get());
        assertGeneration(caA, zipA, NOW);
        verifyDownloads(1, 2);
    }

    @Test
    @SneakyThrows
    void testSnapshot_LeitoresNaoObservamIndiceBComMetadadosA_DurantePersistencia() {
        service.refresh();
        remote(zipB);
        advance(100);
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        doAnswer(invocation -> {
            entered.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return invocation.callRealMethod();
        }).when(repository).armazenarUltimaConfirmacao(any());
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var task = executor.submit(service::refresh);
            try {
                assertTrue(entered.await(5, TimeUnit.SECONDS));
                assertGeneration(caA, zipA, NOW);
            } finally {
                release.countDown();
            }
            task.get(5, TimeUnit.SECONDS);
        }
        assertGeneration(caB, zipB, NOW.plusSeconds(100));
    }

    private void advance(long seconds) {
        when(clock.instant()).thenReturn(NOW.plusSeconds(seconds));
    }

    @SneakyThrows
    private void remote(byte[] zip) {
        when(downloader.downloadText(config.getHashUrl())).thenReturn(hash(zip));
        when(downloader.downloadBytes(config.getCertificateUrl())).thenReturn(zip);
    }

    @SneakyThrows
    private void offline() {
        when(downloader.downloadText(config.getHashUrl())).thenThrow(new IOException("offline"));
        when(downloader.downloadBytes(config.getCertificateUrl())).thenThrow(new IOException("offline"));
    }

    @SneakyThrows
    private void verifyDownloads(int zipCount, int hashCount) {
        verify(downloader, times(zipCount)).downloadBytes(config.getCertificateUrl());
        verify(downloader, times(hashCount)).downloadText(config.getHashUrl());
    }

    private void assertGeneration(X509Certificate certificate, byte[] zip, Instant confirmation) {
        assertTrue(cache.isCacheValid());
        assertEquals(Map.of(CertificateParser.getSubjectKeyIdentifier(certificate), certificate), cache.getAllCertificates());
        assertEquals(new Cache.State(hash(zip), confirmation, confirmation.plusSeconds(3600), 1, true),
                cache.getState().orElseThrow());
    }

    private void assertExpired() {
        assertFalse(service.isCacheValid());
        assertTrue(cache.getAllCertificates().isEmpty());
        assertTrue(cache.getRootCertificates().isEmpty());
        assertNull(cache.getCertificateBySki(CertificateParser.getSubjectKeyIdentifier(caA)));
        assertNull(cache.getCertificateBySki(CertificateParser.getSubjectKeyIdentifier(caB)));
    }
}
