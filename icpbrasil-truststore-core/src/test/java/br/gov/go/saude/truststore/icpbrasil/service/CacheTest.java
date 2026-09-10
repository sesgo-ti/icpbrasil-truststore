package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestClock;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class CacheTest {

    private static final Instant T0 = Instant.parse("2026-01-10T12:00:00Z");
    private static final Duration TTL = Duration.ofHours(168);
    private static final String HASH_A = "a".repeat(128);
    private static final String HASH_B = "b".repeat(128);

    static X509Certificate root;
    static X509Certificate intermediate;
    static X509Certificate otherRoot;
    static Map<String, X509Certificate> indexA;
    static Map<String, X509Certificate> indexB;

    TestClock clock;
    Cache cache;

    @BeforeAll
    static void generateCertificates() {
        KeyPair rootKp = TestBundleFactory.newKeyPair();
        KeyPair intermediateKp = TestBundleFactory.newKeyPair();
        KeyPair otherKp = TestBundleFactory.newKeyPair();
        root = TestBundleFactory.caCert("Raiz A", rootKp);
        intermediate = TestBundleFactory.intermediateCaCert("Intermediaria A", intermediateKp, root, rootKp);
        otherRoot = TestBundleFactory.caCert("Raiz B", otherKp);
        indexA = Cache.indexBySki(List.of(root, intermediate));
        indexB = Cache.indexBySki(List.of(otherRoot));
    }

    @BeforeEach
    void setUp() {
        clock = new TestClock(T0);
        cache = new Cache(clock);
    }

    @Test
    void testLeituras_SemSnapshot_RetornamVazio() {
        assertNull(cache.getCertificateBySki(ski(root)));
        assertTrue(cache.getAllCertificates().isEmpty());
        assertTrue(cache.getRootCertificates().isEmpty());
        assertFalse(cache.isCacheValid());
        assertTrue(cache.getState().isEmpty());
    }

    @Test
    void testPublish_SnapshotVigente_ServeIndiceEEstado() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));

        assertTrue(cache.isCacheValid());
        assertEquals(root, cache.getCertificateBySki(ski(root)));
        assertEquals(intermediate, cache.getCertificateBySki(ski(intermediate)));
        assertEquals(indexA.keySet(), cache.getAllCertificates().keySet());

        Cache.State state = cache.getState().orElseThrow();
        assertEquals(HASH_A, state.hash());
        assertEquals(T0, state.confirmedAt());
        assertEquals(T0.plus(TTL), state.expiresAt());
        assertTrue(state.valid());
    }

    @Test
    void testGetRootCertificates_ApenasAutoassinados() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));

        Map<String, X509Certificate> roots = cache.getRootCertificates();

        assertEquals(Set.of(ski(root)), roots.keySet());
        assertFalse(roots.containsKey(ski(intermediate)));
    }

    @Test
    void testGetAllCertificates_RetornaCopiaDefensiva() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));

        cache.getAllCertificates().clear();

        assertEquals(indexA.size(), cache.getAllCertificates().size());
    }

    @Test
    void testLeituras_ExpiradoPeloRelogio_RetornamVazioEEstadoInvalido() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));
        clock.advance(TTL.minusSeconds(1));
        assertTrue(cache.isCacheValid());

        clock.advance(Duration.ofSeconds(1));

        assertFalse(cache.isCacheValid());
        assertNull(cache.getCertificateBySki(ski(root)));
        assertTrue(cache.getAllCertificates().isEmpty());
        assertTrue(cache.getRootCertificates().isEmpty());
        Cache.State state = cache.getState().orElseThrow();
        assertFalse(state.valid());
        assertEquals(HASH_A, state.hash());
    }

    @Test
    void testInvalidate_DescartaSnapshot() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));

        cache.invalidate();

        assertFalse(cache.isCacheValid());
        assertNull(cache.getCertificateBySki(ski(root)));
        assertTrue(cache.getState().isEmpty());
    }

    @Test
    void testRenew_HashIgual_MantemIndiceERenovaValidade() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));
        Instant t1 = T0.plus(Duration.ofHours(2));

        assertTrue(cache.renew(HASH_A, t1, t1.plus(TTL)));

        assertEquals(indexA.keySet(), cache.getAllCertificates().keySet());
        Cache.State state = cache.getState().orElseThrow();
        assertEquals(t1, state.confirmedAt());
        assertEquals(t1.plus(TTL), state.expiresAt());
    }

    @Test
    void testRenew_HashDiferente_NaoAlteraSnapshot() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));

        assertFalse(cache.renew(HASH_B, T0.plus(Duration.ofHours(2)), T0.plus(Duration.ofHours(200))));

        Cache.State state = cache.getState().orElseThrow();
        assertEquals(HASH_A, state.hash());
        assertEquals(T0.plus(TTL), state.expiresAt());
    }

    @Test
    void testRenew_SemSnapshot_RetornaFalseSemPublicar() {
        assertFalse(cache.renew(HASH_A, T0, T0.plus(TTL)));
        assertTrue(cache.getState().isEmpty());
    }

    @Test
    void testCurrentIndex_IdentidadeSegueAGeracao_MantidaEmRenewETrocadaEmPublish() {
        assertSame(Map.of(), cache.currentIndex());
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));
        Map<String, X509Certificate> geracaoA = cache.currentIndex();
        assertEquals(indexA.keySet(), geracaoA.keySet());

        Instant t1 = T0.plus(Duration.ofHours(2));
        assertTrue(cache.renew(HASH_A, t1, t1.plus(TTL)));
        assertSame(geracaoA, cache.currentIndex(), "renew mantém o índice: memoizações continuam válidas");

        cache.publish(indexB, HASH_B, t1, t1.plus(TTL));
        assertNotSame(geracaoA, cache.currentIndex(), "publish troca a geração");
        assertThrows(UnsupportedOperationException.class, () -> cache.currentIndex().clear());
    }

    @Test
    void testCurrentIndex_SnapshotExpirado_Vazio() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));
        clock.advance(TTL);

        assertTrue(cache.currentIndex().isEmpty());
    }

    @Test
    void testRenew_SnapshotExpirado_RenovaSemNovoParse() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));
        clock.advance(TTL.plus(Duration.ofDays(3)));
        assertFalse(cache.isCacheValid());
        Instant agora = clock.instant();

        assertTrue(cache.renew(HASH_A, agora, agora.plus(TTL)));

        assertTrue(cache.isCacheValid());
        assertEquals(root, cache.getCertificateBySki(ski(root)));
    }

    @Test
    void testPublish_SubstituiSnapshot_LeitoresVeemUmaGeracaoInteira() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));

        cache.publish(indexB, HASH_B, T0, T0.plus(TTL));

        assertEquals(indexB.keySet(), cache.getAllCertificates().keySet());
        assertNull(cache.getCertificateBySki(ski(root)));
        assertEquals(HASH_B, cache.getState().orElseThrow().hash());
    }

    @SneakyThrows
    @Test
    void testPublish_Concorrente_NuncaExpoeIndiceMisto() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));
        AtomicBoolean parar = new AtomicBoolean(false);
        AtomicReference<Set<String>> misto = new AtomicReference<>();

        Thread leitor = new Thread(() -> {
            while (!parar.get() && misto.get() == null) {
                Set<String> visto = cache.getAllCertificates().keySet();
                if (!visto.equals(indexA.keySet()) && !visto.equals(indexB.keySet())) {
                    misto.set(visto);
                }
            }
        });
        leitor.start();
        for (int i = 0; i < 2_000; i++) {
            cache.publish(i % 2 == 0 ? indexB : indexA, i % 2 == 0 ? HASH_B : HASH_A, T0, T0.plus(TTL));
        }
        parar.set(true);
        leitor.join();

        assertNull(misto.get(), "leitor observou índice que não corresponde a nenhuma geração");
    }

    @Test
    void testIndexBySki_CertificadoSemSki_Falha() {
        X509Certificate semSki = TestBundleFactory.caCertWithoutSki("Sem SKI", TestBundleFactory.newKeyPair());

        assertThrows(IllegalArgumentException.class, () -> Cache.indexBySki(List.of(root, semSki)));
    }

    @Test
    void testIndexBySki_RetornaMapaImutavelIndexadoPorSki() {
        Map<String, X509Certificate> index = Cache.indexBySki(List.of(root, intermediate));

        assertEquals(2, index.size());
        assertEquals(root, index.get(ski(root)));
        assertThrows(UnsupportedOperationException.class, () -> index.put("x", otherRoot));
    }

    @Test
    void testGetState_SemSnapshot_Vazio() {
        Optional<Cache.State> state = cache.getState();

        assertTrue(state.isEmpty());
    }

    @Test
    void testLookupCertificate_SemSnapshot_Indisponivel() {
        Cache.Lookup lookup = cache.lookupCertificate(ski(root));

        assertFalse(lookup.available());
        assertNull(lookup.certificate());
    }

    @Test
    void testLookupCertificate_SnapshotVigente_DistingueSkiAusenteDeIndisponivel() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));

        Cache.Lookup existente = cache.lookupCertificate(ski(root));
        Cache.Lookup ausente = cache.lookupCertificate(ski(otherRoot));

        assertTrue(existente.available());
        assertEquals(root, existente.certificate());
        assertTrue(ausente.available());
        assertNull(ausente.certificate());
    }

    @Test
    void testLookupCertificate_SnapshotExpirado_Indisponivel() {
        cache.publish(indexA, HASH_A, T0, T0.plus(TTL));
        clock.advance(TTL);

        Cache.Lookup lookup = cache.lookupCertificate(ski(root));

        assertFalse(lookup.available());
        assertNull(lookup.certificate());
    }

    private static String ski(X509Certificate certificate) {
        return CertificateParser.getSubjectKeyIdentifier(certificate);
    }
}
