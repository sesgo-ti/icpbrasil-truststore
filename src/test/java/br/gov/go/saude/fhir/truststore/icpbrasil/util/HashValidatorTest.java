package br.gov.go.saude.fhir.truststore.icpbrasil.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class HashValidatorTest {

    @Test
    void testComputeSha512() {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        String hash = HashValidator.computeSha512(data);

        assertNotNull(hash);
        assertEquals(128, hash.length());
        assertTrue(HashValidator.validateSha512(data, hash));
    }

    @Test
    void testComputeSha512Consistencia() {
        byte[] data = "dados consistentes".getBytes(StandardCharsets.UTF_8);

        assertEquals(HashValidator.computeSha512(data), HashValidator.computeSha512(data));
    }
}
