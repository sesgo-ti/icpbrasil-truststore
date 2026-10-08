package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509CRL;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class RevocationCacheTest {

    private RevocationCache cache;

    @BeforeEach
    void setUp() {
        TrustStoreConfig config = new TrustStoreConfig();
        TrustStoreConfig.RevocationConfig revocationConfig = new TrustStoreConfig.RevocationConfig();
        revocationConfig.setOcspCacheTtlSeconds(3600);
        revocationConfig.setCrlCacheTtlSeconds(3600);
        revocationConfig.setOcspCacheMaxBytes(1000);
        revocationConfig.setCrlCacheMaxBytes(1000);
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
        Optional<X509CRL> result = cache.getCrl("http://url-inexistente");

        assertTrue(result.isEmpty());
    }

    @Test
    void testPutCrl_ComEntradaValida_DeveRetornarAMesmaInstancia() {
        X509CRL crl = mock(X509CRL.class);
        cache.putCrl("http://crl.example.com", crl, 10);

        Optional<X509CRL> result = cache.getCrl("http://crl.example.com");

        assertTrue(result.isPresent());
        assertSame(crl, result.get());
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
        X509CRL antiga = mock(X509CRL.class);
        X509CRL nova = mock(X509CRL.class);
        cache.putCrl(url, antiga, 10);
        cache.putCrl(url, nova, 10);

        Optional<X509CRL> result = cache.getCrl(url);

        assertTrue(result.isPresent());
        assertSame(nova, result.get());
    }

    @Test
    void testPutCrl_AcimaDoOrcamentoEmBytes_EvictaPorPeso() {
        cache.putCrl("http://a", mock(X509CRL.class), 600);
        cache.putCrl("http://b", mock(X509CRL.class), 600);
        cache.cleanUp();

        long presentes = Stream.of("http://a", "http://b").filter(url -> cache.getCrl(url).isPresent()).count();
        assertEquals(1, presentes);
    }

    @Test
    void testPutCrl_MaiorQueOOrcamentoInteiro_NaoRetida() {
        cache.putCrl("http://enorme", mock(X509CRL.class), 1001);
        cache.cleanUp();

        assertTrue(cache.getCrl("http://enorme").isEmpty());
    }

    @Test
    void testPutOcsp_PesoEOTamanhoDoDer_EvictaPorPeso() {
        cache.putOcsp("a", new byte[600]);
        cache.putOcsp("b", new byte[600]);
        cache.cleanUp();

        long presentes = Stream.of("a", "b").filter(key -> cache.getOcsp(key).isPresent()).count();
        assertEquals(1, presentes);
    }

    @Test
    void testPutOcsp_DentroDoOrcamento_MantemTodas() {
        cache.putOcsp("a", new byte[400]);
        cache.putOcsp("b", new byte[400]);
        cache.cleanUp();

        assertTrue(cache.getOcsp("a").isPresent());
        assertTrue(cache.getOcsp("b").isPresent());
    }
}
