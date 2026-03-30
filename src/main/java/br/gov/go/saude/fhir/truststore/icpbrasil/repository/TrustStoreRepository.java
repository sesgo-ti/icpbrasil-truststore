package br.gov.go.saude.fhir.truststore.icpbrasil.repository;

import java.io.InputStream;
import java.time.Instant;
import java.util.Optional;

public interface TrustStoreRepository {
    Optional<InputStream> recuperarZip();

    Optional<String> recuperarHash();

    void armazenarZip(byte[] zip);

    void armazenarHash(String hash);

    Optional<Instant> recuperarUltimaConfirmacao();

    void armazenarUltimaConfirmacao(Instant instant);
}
