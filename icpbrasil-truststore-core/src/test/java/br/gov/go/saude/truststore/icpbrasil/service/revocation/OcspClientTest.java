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

class OcspClientTest {

    private static final String OCSP_URL = "http://ocsp.example.com/status";

    HttpClient mockHttpClient;
    DownloadPolicy downloadPolicy;
    RevocationCache cache;
    RetryPolicy retryPolicy;
    OcspClient client;

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
        when(downloadPolicy.getMaxOcspResponseBytes()).thenReturn(1_048_576L);
        cache = mock(RevocationCache.class);
        when(cache.getOcsp(any())).thenReturn(Optional.empty());

        TrustStoreConfig.RevocationConfig revocationConfig = new TrustStoreConfig.RevocationConfig();
        revocationConfig.setOcspTimeoutSeconds(10);
        revocationConfig.setMaxRetries(0);
        revocationConfig.setRetryIntervalSeconds(0);

        TrustStoreConfig trustStoreConfig = new TrustStoreConfig();
        TrustStoreConfig.NetworkConfig networkConfig = new TrustStoreConfig.NetworkConfig();
        networkConfig.setDownloadTimeoutSeconds(30);
        networkConfig.setMaxRetries(1);
        networkConfig.setRetryIntervalSeconds(0);
        trustStoreConfig.setNetwork(networkConfig);

        retryPolicy = new RetryPolicy(trustStoreConfig);
        client = new OcspClient(cache, retryPolicy, revocationConfig, mockHttpClient, downloadPolicy);
    }

    @Test
    void testCheckUrlBloqueadaRetornaOcspUnavailable() {
        doThrow(new DownloadPolicyException("URL bloqueada: " + OCSP_URL))
                .when(downloadPolicy).validateUrl(OCSP_URL);

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.OcspUnavailable.class, status);
        verify(mockHttpClient, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeRetornaOcspUnavailable() {
        mockHttpFailure(new DownloadPolicyException("Resposta OCSP muito grande"));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.OcspUnavailable.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeNaoRetenta() {
        TrustStoreConfig.RevocationConfig comRetries = new TrustStoreConfig.RevocationConfig();
        comRetries.setOcspTimeoutSeconds(10);
        comRetries.setMaxRetries(2);
        comRetries.setRetryIntervalSeconds(0);
        OcspClient clientComRetries =
                new OcspClient(cache, retryPolicy, comRetries, mockHttpClient, downloadPolicy);
        mockHttpFailure(new DownloadPolicyException("Resposta OCSP muito grande"));

        clientComRetries.check(leafCert, rootCert, OCSP_URL);

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
