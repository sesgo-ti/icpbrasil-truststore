package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RevocationCache {

    private final ConcurrentHashMap<String, OcspEntry> ocsp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CrlEntry> crl = new ConcurrentHashMap<>();

    public Optional<byte[]> getOcsp(String key) {
        OcspEntry entry = ocsp.get(key);
        if (entry == null) return Optional.empty();
        if (!entry.isValid()) {
            ocsp.remove(key);
            return Optional.empty();
        }
        return Optional.of(entry.der);
    }

    public void putOcsp(String key, byte[] der, long ttlSeconds) {
        ocsp.put(key, new OcspEntry(der, Instant.now().plusSeconds(ttlSeconds)));
    }

    public Optional<byte[]> getCrl(String url) {
        CrlEntry entry = crl.get(url);
        if (entry == null) return Optional.empty();
        if (!entry.isValid()) {
            crl.remove(url);
            return Optional.empty();
        }
        return Optional.of(entry.der);
    }

    public void putCrl(String url, byte[] der, long ttlSeconds) {
        crl.put(url, new CrlEntry(der, Instant.now().plusSeconds(ttlSeconds)));
    }

    private record OcspEntry(byte[] der, Instant expiry) {
        boolean isValid() {
            return Instant.now().isBefore(expiry);
        }
    }

    private record CrlEntry(byte[] der, Instant expiry) {
        boolean isValid() {
            return Instant.now().isBefore(expiry);
        }
    }
}
