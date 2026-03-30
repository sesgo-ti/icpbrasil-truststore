package br.gov.go.saude.fhir.truststore.icpbrasil.repository;

import java.time.Instant;
import java.util.Optional;

public interface TrustStoreRepository {
    Optional<byte[]> recuperarZip();

    Optional<String> recuperarHash();

    void armazenarZip(byte[] zip);

    void armazenarHash(String hash);

    Optional<Instant> recuperarUltimaConfirmacao();

    void armazenarUltimaConfirmacao(Instant instant);
}
