package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CrlClientTest {

    private static final String CRL_URL = "http://ca.example.com/crl.crl";

    HttpClient mockHttpClient;
    DownloadPolicy downloadPolicy;
    RevocationCache cache;
    RetryPolicy retryPolicy;
    CrlClient client;

    KeyPair rootKeyPair;
    KeyPair leafKeyPair;
    X509Certificate rootCert;
    X509Certificate leafCert;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rootKeyPair = kpg.generateKeyPair();
        leafKeyPair = kpg.generateKeyPair();

        rootCert = generateRootCert(rootKeyPair);
        leafCert = generateLeafCert(leafKeyPair, rootKeyPair, rootCert);

        mockHttpClient = mock(HttpClient.class);
        when(mockHttpClient.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        downloadPolicy = mock(DownloadPolicy.class);
        when(downloadPolicy.getMaxCrlResponseBytes()).thenReturn(52_428_800L);
        cache = mock(RevocationCache.class);
        when(cache.getCrl(any())).thenReturn(Optional.empty());

        TrustStoreConfig.RevocationConfig revocationConfig = new TrustStoreConfig.RevocationConfig();
        revocationConfig.setCrlTimeoutSeconds(10);
        revocationConfig.setMaxRetries(0);
        revocationConfig.setRetryIntervalSeconds(0);

        TrustStoreConfig trustStoreConfig = new TrustStoreConfig();
        TrustStoreConfig.NetworkConfig networkConfig = new TrustStoreConfig.NetworkConfig();
        networkConfig.setDownloadTimeoutSeconds(30);
        networkConfig.setMaxRetries(1);
        networkConfig.setRetryIntervalSeconds(0);
        trustStoreConfig.setNetwork(networkConfig);

        retryPolicy = new RetryPolicy(trustStoreConfig);
        client = new CrlClient(cache, retryPolicy, revocationConfig, mockHttpClient, downloadPolicy);
    }

    @Test
    void testCheckUrlBloqueadaRetornaCrlUnavailable() {
        doThrow(new DownloadPolicyException("URL bloqueada: " + CRL_URL))
                .when(downloadPolicy).validateUrl(CRL_URL);

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.CrlUnavailable.class, status);
        verify(mockHttpClient, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeRetornaCrlUnavailable() {
        mockHttpFailure(new DownloadPolicyException("Resposta CRL muito grande"));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.CrlUnavailable.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeNaoRetenta() {
        TrustStoreConfig.RevocationConfig comRetries = new TrustStoreConfig.RevocationConfig();
        comRetries.setCrlTimeoutSeconds(10);
        comRetries.setMaxRetries(2);
        comRetries.setRetryIntervalSeconds(0);
        CrlClient clientComRetries =
                new CrlClient(cache, retryPolicy, comRetries, mockHttpClient, downloadPolicy);
        mockHttpFailure(new DownloadPolicyException("Resposta CRL muito grande"));

        clientComRetries.check(leafCert, rootCert, CRL_URL);

        // Violação de política não é transitória: uma única requisição mesmo com retries configurados
        verify(mockHttpClient, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    // --- Helpers: HTTP mock ---

    /**
     * Simula a falha assíncrona que o transporte observa: o cancelamento por excesso de
     * tamanho chega como future completado excepcionalmente.
     */
    @SuppressWarnings("unchecked")
    private void mockHttpFailure(Exception failure) {
        doReturn(CompletableFuture.failedFuture(failure))
                .when(mockHttpClient).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }
}
