package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class RevocationCacheTest {

    private RevocationCache cache;

    @BeforeEach
    void setUp() {
        cache = new RevocationCache();
    }

    @Test
    void testGetOcsp_ComCacheMiss_DeveRetornarVazio() {
        Optional<byte[]> result = cache.getOcsp("chave-inexistente", 3600);

        assertTrue(result.isEmpty());
    }

    @Test
    void testPutOcsp_ComEntradaValida_DeveRetornarDados() {
        // Given
        byte[] der = new byte[]{1, 2, 3};
        cache.putOcsp("chave-ocsp", der, 3600);

        // When
        Optional<byte[]> result = cache.getOcsp("chave-ocsp", 3600);

        // Then
        assertTrue(result.isPresent());
        assertArrayEquals(der, result.get());
    }

    @Test
    void testGetOcsp_ComEntradaExpirada_DeveRetornarVazio() {
        // Given - TTL de 0 segundos (já expirado no momento da leitura)
        byte[] der = new byte[]{1, 2, 3};
        cache.putOcsp("chave-expirada", der, 0);

        // When
        Optional<byte[]> result = cache.getOcsp("chave-expirada", 0);

        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void testGetCrl_ComCacheMiss_DeveRetornarVazio() {
        Optional<byte[]> result = cache.getCrl("http://url-inexistente", 3600);

        assertTrue(result.isEmpty());
    }

    @Test
    void testPutCrl_ComEntradaValida_DeveRetornarDados() {
        // Given
        byte[] der = new byte[]{4, 5, 6};
        cache.putCrl("http://crl.example.com", der, 3600);

        // When
        Optional<byte[]> result = cache.getCrl("http://crl.example.com", 3600);

        // Then
        assertTrue(result.isPresent());
        assertArrayEquals(der, result.get());
    }

    @Test
    void testGetCrl_ComEntradaExpirada_DeveRetornarVazio() {
        // Given
        byte[] der = new byte[]{4, 5, 6};
        cache.putCrl("http://crl-expirada.example.com", der, 0);

        // When
        Optional<byte[]> result = cache.getCrl("http://crl-expirada.example.com", 0);

        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void testPutOcsp_ComMesmaChave_DeveSobrescrever() {
        // Given
        cache.putOcsp("chave", new byte[]{1}, 3600);
        cache.putOcsp("chave", new byte[]{2}, 3600);

        // When
        Optional<byte[]> result = cache.getOcsp("chave", 3600);

        // Then
        assertTrue(result.isPresent());
        assertArrayEquals(new byte[]{2}, result.get());
    }

    @Test
    void testPutCrl_ComMesmaUrl_DeveSobrescrever() {
        // Given
        String url = "http://crl.example.com";
        cache.putCrl(url, new byte[]{1}, 3600);
        cache.putCrl(url, new byte[]{2}, 3600);

        // When
        Optional<byte[]> result = cache.getCrl(url, 3600);

        // Then
        assertTrue(result.isPresent());
        assertArrayEquals(new byte[]{2}, result.get());
    }
}
