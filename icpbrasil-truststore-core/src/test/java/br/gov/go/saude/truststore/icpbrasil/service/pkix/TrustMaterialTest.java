package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import br.gov.go.saude.truststore.icpbrasil.service.CacheFixture;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestClock;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.CertStoreException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class TrustMaterialTest {

    private static final Instant T0 = Instant.parse("2026-01-10T12:00:00Z");
    private static final Duration TTL = Duration.ofHours(168);
    private static final String HASH_A = "a".repeat(128);
    private static final String HASH_B = "b".repeat(128);

    static X509Certificate root;
    static X509Certificate intermediate;
    static X509Certificate otherRoot;

    @BeforeAll
    static void generateCertificates() {
        KeyPair rootKp = TestBundleFactory.newKeyPair();
        KeyPair intermediateKp = TestBundleFactory.newKeyPair();
        root = TestBundleFactory.caCert("Raiz A", rootKp);
        intermediate = TestBundleFactory.intermediateCaCert("Intermediaria A", intermediateKp, root, rootKp);
        otherRoot = TestBundleFactory.caCert("Raiz B", TestBundleFactory.newKeyPair());
    }

    @Test
    void testOf_SeparaRaizesAutoassinadasDeIntermediarias() throws CertStoreException {
        TrustMaterial material = TrustMaterial.of(List.of(root, intermediate, otherRoot));

        assertEquals(Set.of(root, otherRoot), trustedCerts(material.anchors()));
        assertEquals(List.of(intermediate), List.copyOf(material.intermediates().getCertificates(new X509CertSelector())));
        assertTrue(material.hasAnchors());
    }

    @Test
    void testOf_SemRaizes_NaoTemAncoras() {
        TrustMaterial material = TrustMaterial.of(List.of(intermediate));

        assertFalse(material.hasAnchors());
    }

    @Test
    void testAnchoredAt_ConfiaDiretamenteNosCertificadosInformados() throws CertStoreException {
        TrustMaterial material = TrustMaterial.anchoredAt(List.of(intermediate));

        assertEquals(Set.of(intermediate), trustedCerts(material.anchors()));
        assertTrue(material.intermediates().getCertificates(new X509CertSelector()).isEmpty());
    }

    @Test
    void testCacheSource_SemAcervoVigente_Vazio() {
        TestClock clock = new TestClock(T0);
        Cache cache = new Cache(clock);
        CacheTrustMaterialSource source = new CacheTrustMaterialSource(cache);

        assertTrue(source.current().isEmpty());

        CacheFixture.publish(cache, List.of(root), HASH_A, T0, T0.plus(TTL));
        assertTrue(source.current().isPresent());

        clock.advance(TTL);
        assertTrue(source.current().isEmpty(), "acervo expirado não fornece âncoras");
    }

    @Test
    void testCacheSource_AcervoSemRaizes_Vazio() {
        Cache cache = new Cache(new TestClock(T0));
        CacheFixture.publish(cache, List.of(intermediate), HASH_A, T0, T0.plus(TTL));

        assertTrue(new CacheTrustMaterialSource(cache).current().isEmpty());
    }

    @Test
    void testCacheSource_MemoizaPorGeracaoPublicada() {
        Cache cache = new Cache(new TestClock(T0));
        CacheTrustMaterialSource source = new CacheTrustMaterialSource(cache);
        CacheFixture.publish(cache, List.of(root, intermediate), HASH_A, T0, T0.plus(TTL));

        Optional<TrustMaterial> primeira = source.current();
        assertTrue(CacheFixture.renew(cache, HASH_A, T0.plus(Duration.ofHours(1)), T0.plus(Duration.ofHours(1)).plus(TTL)));
        assertSame(primeira.orElseThrow(), source.current().orElseThrow(), "renew não refaz o material");

        CacheFixture.publish(cache, List.of(otherRoot), HASH_B, T0, T0.plus(TTL));
        TrustMaterial segunda = source.current().orElseThrow();
        assertNotSame(primeira.orElseThrow(), segunda);
        assertEquals(Set.of(otherRoot), trustedCerts(segunda.anchors()));
    }

    private static Set<X509Certificate> trustedCerts(Set<TrustAnchor> anchors) {
        return anchors.stream().map(TrustAnchor::getTrustedCert).collect(Collectors.toSet());
    }
}
