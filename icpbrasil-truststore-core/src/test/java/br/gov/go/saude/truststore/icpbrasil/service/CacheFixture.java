package br.gov.go.saude.truststore.icpbrasil.service;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * Publica gerações no {@link Cache} a partir de testes de outros pacotes. As escritas do cache
 * são package-private por contrato (só o pipeline publica); este utilitário vive no pacote
 * apenas em escopo de teste.
 */
public final class CacheFixture {

    private CacheFixture() {}

    public static void publish(Cache cache, List<X509Certificate> certificates, String hash,
                               Instant confirmedAt, Instant expiresAt) {
        cache.publish(Cache.indexBySki(certificates), hash, confirmedAt, expiresAt);
    }

    public static boolean renew(Cache cache, String hash, Instant confirmedAt, Instant expiresAt) {
        return cache.renew(hash, confirmedAt, expiresAt);
    }
}
