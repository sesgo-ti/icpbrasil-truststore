package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class RevocationCacheTest {

    private RevocationCache cache;

    @BeforeEach
    void setUp() {
        TrustStoreConfig config = new TrustStoreConfig();
        TrustStoreConfig.RevocationConfig revocationConfig = new TrustStoreConfig.RevocationConfig();
        revocationConfig.setOcspCacheTtlSeconds(3600);
        revocationConfig.setCrlCacheTtlSeconds(3600);
        revocationConfig.setOcspCacheMaxSize(1000);
        revocationConfig.setCrlCacheMaxSize(500);
        config.setRevocation(revocationConfig);

        cache = new RevocationCache(config);
    }

    @Test
    void testGetOcsp_ComCacheMiss_DeveRetornarVazio() {
        Optional<byte[]> result = cache.getOcsp("chave-inexistente");

        assertTrue(result.isEmpty());
    }

    @Test
    void testPutOcsp_ComEntradaValida_DeveRetornarDados() {
        byte[] der = new byte[]{1, 2, 3};
        cache.putOcsp("chave-ocsp", der);

        Optional<byte[]> result = cache.getOcsp("chave-ocsp");

        assertTrue(result.isPresent());
        assertArrayEquals(der, result.get());
    }

    @Test
    void testGetCrl_ComCacheMiss_DeveRetornarVazio() {
        Optional<byte[]> result = cache.getCrl("http://url-inexistente");

        assertTrue(result.isEmpty());
    }

    @Test
    void testPutCrl_ComEntradaValida_DeveRetornarDados() {
        byte[] der = new byte[]{4, 5, 6};
        cache.putCrl("http://crl.example.com", der);

        Optional<byte[]> result = cache.getCrl("http://crl.example.com");

        assertTrue(result.isPresent());
        assertArrayEquals(der, result.get());
    }

    @Test
    void testPutOcsp_ComMesmaChave_DeveSobrescrever() {
        cache.putOcsp("chave", new byte[]{1});
        cache.putOcsp("chave", new byte[]{2});

        Optional<byte[]> result = cache.getOcsp("chave");

        assertTrue(result.isPresent());
        assertArrayEquals(new byte[]{2}, result.get());
    }

    @Test
    void testPutCrl_ComMesmaUrl_DeveSobrescrever() {
        String url = "http://crl.example.com";
        cache.putCrl(url, new byte[]{1});
        cache.putCrl(url, new byte[]{2});

        Optional<byte[]> result = cache.getCrl(url);

        assertTrue(result.isPresent());
        assertArrayEquals(new byte[]{2}, result.get());
    }
}
