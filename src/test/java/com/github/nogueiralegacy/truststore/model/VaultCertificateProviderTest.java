package com.github.nogueiralegacy.truststore.model;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
public class VaultCertificateProviderTest {
    @Autowired
    VaultCertificateProvider vaultCertificateProvider;

    @Test
    void getCertificatesNotNullAndNotEmpty() {
        var certificates = vaultCertificateProvider.getCertificates();
        assert(certificates != null && !certificates.isEmpty());
    }
}
