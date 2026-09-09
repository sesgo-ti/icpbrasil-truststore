package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestClock;
import br.gov.go.saude.truststore.icpbrasil.util.HashValidator;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustStoreServiceTest {

    private static final Instant T0 = Instant.parse("2026-01-10T12:00:00Z");
    private static final Duration TTL_MAX = Duration.ofHours(168);
    private static final String ZIP_URL =
            "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip";
    private static final String HASH_URL =
            "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt";

    static X509Certificate rootA;
    static X509Certificate intermediateA;
    static X509Certificate rootB;
    static byte[] zipA;
    static byte[] zipB;
    static String hashA;
    static String hashB;

    @TempDir
    Path baseDir;

    TrustStoreConfig config;
    FilesystemTrustStoreRepository repository;
    Downloader downloader;
    TestClock clock;
    Cache cache;
    TrustStoreService service;

    @BeforeAll
    static void generateBundles() {
        KeyPair rootAKp = TestBundleFactory.newKeyPair();
        rootA = TestBundleFactory.caCert("Raiz A", rootAKp);
        intermediateA = TestBundleFactory.intermediateCaCert("Intermediaria A",
                TestBundleFactory.newKeyPair(), rootA, rootAKp);
        rootB = TestBundleFactory.caCert("Raiz B", TestBundleFactory.newKeyPair());
        zipA = TestBundleFactory.bundleOf(rootA, intermediateA);
        zipB = TestBundleFactory.bundleOf(rootB);
        hashA = HashValidator.computeSha512(zipA);
        hashB = HashValidator.computeSha512(zipB);
    }

    @BeforeEach
    void setUp() {
        config = buildConfig(baseDir);
        repository = new FilesystemTrustStoreRepository(config);
        downloader = mock(Downloader.class);
        clock = new TestClock(T0);
        cache = new Cache(clock);
        service = criarServico(repository);
    }

    @SneakyThrows
    @Test
    void testRefresh_ColdStartSemStorageComRemoto_PublicaEPersiste() {
        remoto(hashA, zipA);

        service.refresh();

        assertTrue(service.isCacheValid());
        assertEquals(rootA, cache.getCertificateBySki(ski(rootA)));
        Cache.State state = cache.getState().orElseThrow();
        assertEquals(hashA, state.hash());
        assertEquals(T0, state.confirmedAt());
        assertEquals(T0.plus(TTL_MAX), state.expiresAt());
        assertArrayEquals(zipA, repository.recuperarZip().orElseThrow());
        assertEquals(hashA, repository.recuperarHash().orElseThrow());
        assertEquals(T0, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_RemotoAnunciaBComZipCorrompido_MantemSnapshotAComPrazoOriginal() {
        remoto(hashA, zipA);
        service.refresh();
        clock.advance(Duration.ofHours(2));
        byte[] zipBCorrompido = zipB.clone();
        zipBCorrompido[zipBCorrompido.length / 2] ^= 0x01;
        remoto(hashB, zipBCorrompido);

        service.refresh();

        assertTrue(service.isCacheValid());
        assertEquals(rootA, cache.getCertificateBySki(ski(rootA)));
        assertNull(cache.getCertificateBySki(ski(rootB)));
        Cache.State state = cache.getState().orElseThrow();
        assertEquals(hashA, state.hash());
        assertEquals(T0, state.confirmedAt());
        assertEquals(T0.plus(TTL_MAX), state.expiresAt());
        assertEquals(hashA, repository.recuperarHash().orElseThrow());
        assertEquals(T0, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_RemotoAnunciaBundleSemCertificados_MantemSnapshotA() {
        remoto(hashA, zipA);
        service.refresh();
        clock.advance(Duration.ofHours(2));
        byte[] zipVazio = TestBundleFactory.zipOf(Map.of());
        remoto(HashValidator.computeSha512(zipVazio), zipVazio);

        service.refresh();

        Cache.State state = cache.getState().orElseThrow();
        assertTrue(state.valid());
        assertEquals(hashA, state.hash());
        assertEquals(T0.plus(TTL_MAX), state.expiresAt());
        assertArrayEquals(zipA, repository.recuperarZip().orElseThrow());
        assertEquals(T0, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_RemotoIgual_RenovaConfirmacaoSemBaixarZip() {
        remoto(hashA, zipA);
        service.refresh();
        Instant t1 = T0.plus(Duration.ofHours(2));
        clock.set(t1);

        service.refresh();

        Cache.State state = cache.getState().orElseThrow();
        assertEquals(hashA, state.hash());
        assertEquals(t1, state.confirmedAt());
        assertEquals(t1.plus(TTL_MAX), state.expiresAt());
        assertEquals(rootA, cache.getCertificateBySki(ski(rootA)));
        assertEquals(t1, repository.recuperarUltimaConfirmacao().orElseThrow());
        verify(downloader, times(1)).downloadBytes(ZIP_URL);
    }

    @SneakyThrows
    @Test
    void testRefresh_RemotoIgualSemSnapshotVigente_BaixaValidaEPublica() {
        // Geração A persistida, mas confirmada há mais que o TTL máximo: não pode ser
        // publicada pela carga local nem reconfirmada só pelo hash.
        storage(zipA, hashA, T0.minus(TTL_MAX).minus(Duration.ofHours(1)));
        remoto(hashA, zipA);

        service.refresh();

        assertTrue(service.isCacheValid());
        Cache.State state = cache.getState().orElseThrow();
        assertEquals(T0, state.confirmedAt());
        assertEquals(T0.plus(TTL_MAX), state.expiresAt());
        verify(downloader).downloadBytes(ZIP_URL);
        assertEquals(T0, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_ColdStartOfflineComStorageValido_PublicaComExpiracaoOriginal() {
        Instant confirmacao = T0.minus(Duration.ofHours(30));
        storage(zipA, hashA, confirmacao);
        remotoIndisponivel();

        service.refresh();

        assertTrue(service.isCacheValid());
        assertEquals(intermediateA, cache.getCertificateBySki(ski(intermediateA)));
        Cache.State state = cache.getState().orElseThrow();
        assertEquals(hashA, state.hash());
        assertEquals(confirmacao, state.confirmedAt());
        assertEquals(confirmacao.plus(TTL_MAX), state.expiresAt());
        assertEquals(confirmacao, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_ConfirmacaoPersistidaFutura_Rejeitada() {
        storage(zipA, hashA, T0.plus(Duration.ofHours(1)));
        remotoIndisponivel();

        service.refresh();

        assertFalse(service.isCacheValid());
        assertTrue(cache.getState().isEmpty());
    }

    @SneakyThrows
    @Test
    void testRefresh_ConfirmacaoPersistidaDentroDaToleranciaDeRelogio_Aceita() {
        Instant confirmacao = T0.plus(Duration.ofMinutes(5));
        storage(zipA, hashA, confirmacao);
        remotoIndisponivel();

        service.refresh();

        assertTrue(service.isCacheValid());
        assertEquals(confirmacao, cache.getState().orElseThrow().confirmedAt());
    }

    @SneakyThrows
    @Test
    void testRefresh_StorageComHashDivergenteDoZip_NaoPublicaCargaLocal() {
        storage(zipA, hashB, T0.minus(Duration.ofHours(1)));
        remotoIndisponivel();

        service.refresh();

        assertFalse(service.isCacheValid());
        assertTrue(cache.getState().isEmpty());
    }

    @SneakyThrows
    @Test
    void testRefresh_StorageComConfirmacaoExpirada_NaoPublicaCargaLocal() {
        storage(zipA, hashA, T0.minus(TTL_MAX));
        remotoIndisponivel();

        service.refresh();

        assertFalse(service.isCacheValid());
        assertTrue(cache.getState().isEmpty());
    }

    @SneakyThrows
    @Test
    void testLeituras_ExpiradoSemRefresh_VaziasEInvalido() {
        remoto(hashA, zipA);
        service.refresh();

        clock.advance(TTL_MAX);

        assertFalse(service.isCacheValid());
        assertNull(cache.getCertificateBySki(ski(rootA)));
        assertTrue(cache.getAllCertificates().isEmpty());
        assertFalse(service.isTrustedRoot(rootA));
    }

    @SneakyThrows
    @Test
    void testRefresh_ParsingFalhoNoPrimeiroRefresh_NadaPublicadoNemPersistido() {
        X509Certificate semSki = TestBundleFactory.caCertWithoutSki("Sem SKI", TestBundleFactory.newKeyPair());
        byte[] zipInvalido = TestBundleFactory.bundleOf(rootA, semSki);
        remoto(HashValidator.computeSha512(zipInvalido), zipInvalido);

        service.refresh();

        assertFalse(service.isCacheValid());
        assertTrue(cache.getState().isEmpty());
        assertTrue(repository.recuperarZip().isEmpty());
        assertTrue(repository.recuperarHash().isEmpty());
        assertTrue(repository.recuperarUltimaConfirmacao().isEmpty());
    }

    @SneakyThrows
    @Test
    void testRefresh_PrimeiraLeituraLocalFalhaESegundaFunciona_Offline_Publica() {
        Instant confirmacao = T0.minus(Duration.ofHours(1));
        storage(zipA, hashA, confirmacao);
        service = criarServico(new RepositorioComFalhaTransitoria(repository, 1));
        remotoIndisponivel();

        service.refresh();
        assertFalse(service.isCacheValid());

        service.refresh();

        assertTrue(service.isCacheValid());
        assertEquals(confirmacao, cache.getState().orElseThrow().confirmedAt());
    }

    @SneakyThrows
    @Test
    void testRefresh_InvalidateDuranteRefresh_NaoRepublicaIndiceAntigo() {
        remoto(hashA, zipA);
        service.refresh();
        clock.advance(Duration.ofHours(2));
        // O ITI reconfirma a geração A, mas o cache é invalidado enquanto o hash é baixado:
        // a reconfirmação não pode reaproveitar o índice descartado.
        when(downloader.downloadText(HASH_URL)).thenAnswer(invocation -> {
            cache.invalidate();
            return hashA + "  ACcompactado.zip\n";
        });
        when(downloader.downloadBytes(ZIP_URL)).thenThrow(new IOException("offline"));

        service.refresh();

        assertFalse(service.isCacheValid());
        assertTrue(cache.getState().isEmpty());
        verify(downloader, times(2)).downloadBytes(ZIP_URL);
    }

    @SneakyThrows
    @Test
    void testRefresh_FalhaDeRedeNoHash_MantemSnapshotSemAlterarPrazo() {
        remoto(hashA, zipA);
        service.refresh();
        clock.advance(Duration.ofHours(2));
        remotoIndisponivel();

        service.refresh();

        Cache.State state = cache.getState().orElseThrow();
        assertTrue(state.valid());
        assertEquals(T0, state.confirmedAt());
        assertEquals(T0.plus(TTL_MAX), state.expiresAt());
        assertEquals(T0, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_RemotoAnunciaNovaGeracaoValida_SubstituiSnapshotEPersiste() {
        remoto(hashA, zipA);
        service.refresh();
        Instant t1 = T0.plus(Duration.ofHours(2));
        clock.set(t1);
        remoto(hashB, zipB);

        service.refresh();

        assertEquals(rootB, cache.getCertificateBySki(ski(rootB)));
        assertNull(cache.getCertificateBySki(ski(rootA)));
        Cache.State state = cache.getState().orElseThrow();
        assertEquals(hashB, state.hash());
        assertEquals(t1, state.confirmedAt());
        assertArrayEquals(zipB, repository.recuperarZip().orElseThrow());
        assertEquals(hashB, repository.recuperarHash().orElseThrow());
        assertEquals(t1, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_PersistenciaFalhaAposValidacao_SnapshotNovoServidoEStorageInalterado() {
        remoto(hashA, zipA);
        service.refresh();
        Instant t1 = T0.plus(Duration.ofHours(2));
        clock.set(t1);
        service = criarServico(repositorioSemEscrita());
        remoto(hashB, zipB);

        service.refresh();

        assertEquals(rootB, cache.getCertificateBySki(ski(rootB)));
        assertNull(cache.getCertificateBySki(ski(rootA)));
        Cache.State state = cache.getState().orElseThrow();
        assertEquals(hashB, state.hash());
        assertEquals(t1, state.confirmedAt());
        assertEquals(t1.plus(TTL_MAX), state.expiresAt());
        assertArrayEquals(zipA, repository.recuperarZip().orElseThrow());
        assertEquals(hashA, repository.recuperarHash().orElseThrow());
        assertEquals(T0, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_RemotoIgualComPersistenciaIndisponivel_RenovaValidadeEmMemoria() {
        remoto(hashA, zipA);
        service.refresh();
        Instant t1 = T0.plus(Duration.ofHours(2));
        clock.set(t1);
        service = criarServico(repositorioSemEscrita());

        service.refresh();

        Cache.State state = cache.getState().orElseThrow();
        assertEquals(hashA, state.hash());
        assertEquals(t1, state.confirmedAt());
        assertEquals(t1.plus(TTL_MAX), state.expiresAt());
        assertEquals(T0, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @SneakyThrows
    @Test
    void testRefresh_AposPersistenciaFalharEmB_ProximoRefreshRegravaRepositorioComB() {
        remoto(hashA, zipA);
        service.refresh();
        clock.set(T0.plus(Duration.ofHours(2)));
        service = criarServico(repositorioSemEscrita());
        remoto(hashB, zipB);
        service.refresh();
        // Repositório ainda em A enquanto o snapshot já é B: a reconfirmação de B não pode
        // apenas renovar a confirmação persistida, que passaria a cobrir a geração A.
        Instant t2 = T0.plus(Duration.ofHours(4));
        clock.set(t2);
        service = criarServico(repository);

        service.refresh();

        Cache.State state = cache.getState().orElseThrow();
        assertEquals(hashB, state.hash());
        assertEquals(t2, state.confirmedAt());
        assertEquals(t2.plus(TTL_MAX), state.expiresAt());
        assertEquals(rootB, cache.getCertificateBySki(ski(rootB)));
        assertArrayEquals(zipB, repository.recuperarZip().orElseThrow());
        assertEquals(hashB, repository.recuperarHash().orElseThrow());
        assertEquals(t2, repository.recuperarUltimaConfirmacao().orElseThrow());
        verify(downloader, times(3)).downloadBytes(ZIP_URL);
    }

    @SneakyThrows
    @Test
    void testRefresh_RemotoIgualMasHashDoRepositorioIlegivel_RegravaRepositorio() {
        remoto(hashA, zipA);
        service.refresh();
        Instant t1 = T0.plus(Duration.ofHours(2));
        clock.set(t1);
        TrustStoreRepository leituraFalha = spy(repository);
        doThrow(new RuntimeException("leitura indisponível")).when(leituraFalha).recuperarHash();
        service = criarServico(leituraFalha);

        service.refresh();

        assertEquals(t1, cache.getState().orElseThrow().confirmedAt());
        assertEquals(t1, repository.recuperarUltimaConfirmacao().orElseThrow());
        verify(downloader, times(2)).downloadBytes(ZIP_URL);
    }

    @SneakyThrows
    @Test
    void testIsTrustedRoot_ApenasRaizesDoAcervoVigente() {
        remoto(hashA, zipA);
        service.refresh();

        assertTrue(service.isTrustedRoot(rootA));
        assertFalse(service.isTrustedRoot(intermediateA));
        assertFalse(service.isTrustedRoot(rootB));
    }

    @Test
    void testRefresh_SemStorageEOffline_NaoLancaENaoPublica() {
        remotoIndisponivel();

        assertDoesNotThrow(service::refresh);

        assertFalse(service.isCacheValid());
        assertFalse(Files.exists(baseDir.resolve("ACcompactado.zip")));
    }

    private TrustStoreService criarServico(TrustStoreRepository repositorio) {
        IcpBrasilCertificateProvider provider = new IcpBrasilCertificateProvider(config, downloader, repositorio);
        return new TrustStoreService(repositorio, provider, config, cache, clock);
    }

    /** Leituras reais; toda escrita falha como um disco cheio ou bucket inacessível. */
    private TrustStoreRepository repositorioSemEscrita() {
        TrustStoreRepository semEscrita = spy(repository);
        doThrow(new RuntimeException("armazenamento indisponível")).when(semEscrita).armazenarZip(any());
        doThrow(new RuntimeException("armazenamento indisponível")).when(semEscrita).armazenarHash(any());
        doThrow(new RuntimeException("armazenamento indisponível")).when(semEscrita).armazenarUltimaConfirmacao(any());
        return semEscrita;
    }

    @SneakyThrows
    private void remoto(String hash, byte[] zip) {
        when(downloader.downloadText(HASH_URL)).thenReturn(hash + "  ACcompactado.zip\n");
        when(downloader.downloadBytes(ZIP_URL)).thenReturn(zip);
    }

    @SneakyThrows
    private void remotoIndisponivel() {
        when(downloader.downloadText(HASH_URL)).thenThrow(new IOException("offline"));
        when(downloader.downloadBytes(ZIP_URL)).thenThrow(new IOException("offline"));
    }

    private void storage(byte[] zip, String hash, Instant confirmacao) {
        repository.armazenarZip(zip);
        repository.armazenarHash(hash);
        repository.armazenarUltimaConfirmacao(confirmacao);
    }

    private static String ski(X509Certificate certificate) {
        return CertificateParser.getSubjectKeyIdentifier(certificate);
    }

    private static TrustStoreConfig buildConfig(Path baseDir) {
        TrustStoreConfig config = new TrustStoreConfig();
        config.setCertificateUrl(ZIP_URL);
        config.setHashUrl(HASH_URL);
        config.setCacheTtlCriticalHours(72);
        config.setCacheTtlMaxHours((int) TTL_MAX.toHours());
        config.setRefreshIntervalHours(2);

        TrustStoreConfig.NetworkConfig network = new TrustStoreConfig.NetworkConfig();
        network.setDownloadTimeoutSeconds(30);
        network.setMaxRetries(3);
        network.setRetryIntervalSeconds(30);
        config.setNetwork(network);

        TrustStoreConfig.StorageConfig storage = new TrustStoreConfig.StorageConfig();
        storage.setType("filesystem");
        storage.setTruststoreArchivePath("ACcompactado.zip");
        storage.setHashFilePath("hash.txt");
        storage.setConfirmationFilePath("ultima_confirmacao.txt");
        config.setStorage(storage);

        TrustStoreConfig.FilesystemConfig filesystem = new TrustStoreConfig.FilesystemConfig();
        filesystem.setBaseDir(baseDir.toString());
        config.setFilesystem(filesystem);

        return config;
    }

    /** Delega ao repositório real, falhando as primeiras leituras do ZIP (I/O transitório). */
    private static final class RepositorioComFalhaTransitoria implements TrustStoreRepository {

        private final TrustStoreRepository delegate;
        private int falhasRestantes;

        RepositorioComFalhaTransitoria(TrustStoreRepository delegate, int falhas) {
            this.delegate = delegate;
            this.falhasRestantes = falhas;
        }

        @Override
        public Optional<byte[]> recuperarZip() {
            if (falhasRestantes-- > 0) {
                throw new RuntimeException("Falha transitória de leitura");
            }
            return delegate.recuperarZip();
        }

        @Override
        public Optional<String> recuperarHash() {
            return delegate.recuperarHash();
        }

        @Override
        public void armazenarZip(byte[] zip) {
            delegate.armazenarZip(zip);
        }

        @Override
        public void armazenarHash(String hash) {
            delegate.armazenarHash(hash);
        }

        @Override
        public Optional<Instant> recuperarUltimaConfirmacao() {
            return delegate.recuperarUltimaConfirmacao();
        }

        @Override
        public void armazenarUltimaConfirmacao(Instant instant) {
            delegate.armazenarUltimaConfirmacao(instant);
        }
    }
}
