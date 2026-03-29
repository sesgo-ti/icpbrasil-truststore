package br.gov.go.saude.fhir.truststore.icpbrasil.repository;

import java.io.InputStream;
import java.time.Instant;

public interface TrustStoreRepository {
    InputStream recuperarZip();

    String recuperarHash();

    void armazenarZip(byte[] zip);

    void armazenarHash(String hash);

    Instant recuperarUltimaConfirmacao();

    void armazenarUltimaConfirmacao(Instant instant);
}
