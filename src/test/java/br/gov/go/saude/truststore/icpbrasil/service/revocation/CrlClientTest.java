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

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class CrlClientTest {

    private static final String CRL_URL = "http://ca.example.com/crl.crl";

    HttpClient mockHttpClient;
    DownloadPolicy downloadPolicy;
    RevocationCache cache;
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
        downloadPolicy = mock(DownloadPolicy.class);
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

        RetryPolicy retryPolicy = new RetryPolicy(trustStoreConfig);
        client = new CrlClient(cache, retryPolicy, revocationConfig, mockHttpClient, downloadPolicy);
    }

    @Test
    void testCheckUrlBloqueadaRetornaCrlUnavailable() {
        doThrow(new DownloadPolicyException("URL bloqueada: " + CRL_URL))
                .when(downloadPolicy).validateUrl(CRL_URL);

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.CrlUnavailable.class, status);
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeRetornaCrlUnavailable() {
        mockHttpResponse(new byte[]{1, 2, 3});

        doThrow(new DownloadPolicyException("Resposta CRL muito grande"))
                .when(downloadPolicy).validateCrlResponseSize(any(byte[].class), eq(CRL_URL));

        RevocationStatus status = client.check(leafCert, rootCert, CRL_URL);

        assertInstanceOf(RevocationStatus.CrlUnavailable.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeNaoRetenta() {
        mockHttpResponse(new byte[]{1, 2, 3});

        doThrow(new DownloadPolicyException("Resposta CRL muito grande"))
                .when(downloadPolicy).validateCrlResponseSize(any(byte[].class), eq(CRL_URL));

        client.check(leafCert, rootCert, CRL_URL);

        verify(mockHttpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    // --- Helpers: HTTP mock ---

    @SneakyThrows
    @SuppressWarnings("unchecked")
    private void mockHttpResponse(byte[] body) {
        HttpResponse<byte[]> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(body);

        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);
    }
}
