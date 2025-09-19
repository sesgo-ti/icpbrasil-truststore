package com.github.nogueiralegacy.truststore.repository;

import java.time.Instant;

public interface TrustStoreRepository {
    Byte[] recuperarZip();

    String recuperarHash();

    void armazenarZip(Byte[] zip);

    void armazenarHash(String hash);

    Instant recuperarUltimaConfirmacao();

    void armazenarUltimaConfirmacao(Instant instant);
}
