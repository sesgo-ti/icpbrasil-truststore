package com.github.nogueiralegacy.truststore.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.vault.core.VaultTemplate;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
@ActiveProfiles("test")
public class VaultTest {
    @Autowired
    private VaultTemplate vaultTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    private final String DEFAULT_CERT_PATH = "certificates";


    @Test
    @SneakyThrows
    void testConnectionWithVault() {
        var kvOps = vaultTemplate.opsForVersionedKeyValue("kv");
        var versionedSecret = kvOps.get(DEFAULT_CERT_PATH);
        assertNotNull(versionedSecret, "Resposta do Vault não deve ser nula");
    }
}
