package com.github.nogueiralegacy.truststore.repository;

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
