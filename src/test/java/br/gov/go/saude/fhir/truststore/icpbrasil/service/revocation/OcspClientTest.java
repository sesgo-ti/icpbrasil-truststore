package br.gov.go.saude.fhir.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
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

import static br.gov.go.saude.fhir.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class OcspClientTest {

    private static final String OCSP_URL = "http://ocsp.example.com/status";

    HttpClient mockHttpClient;
    DownloadPolicy downloadPolicy;
    RevocationCache cache;
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
        downloadPolicy = mock(DownloadPolicy.class);
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

        RetryPolicy retryPolicy = new RetryPolicy(trustStoreConfig);
        client = new OcspClient(cache, retryPolicy, revocationConfig, mockHttpClient, downloadPolicy);
    }

    @Test
    void testCheckUrlBloqueadaRetornaOcspUnavailable() {
        doThrow(new DownloadPolicyException("URL bloqueada: " + OCSP_URL))
                .when(downloadPolicy).validateUrl(OCSP_URL);

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.OcspUnavailable.class, status);
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeRetornaOcspUnavailable() {
        mockHttpResponse(new byte[]{1, 2, 3});

        doThrow(new DownloadPolicyException("Resposta OCSP muito grande"))
                .when(downloadPolicy).validateOcspResponseSize(any(byte[].class), eq(OCSP_URL));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.OcspUnavailable.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckRespostaMuitoGrandeNaoRetenta() {
        mockHttpResponse(new byte[]{1, 2, 3});

        doThrow(new DownloadPolicyException("Resposta OCSP muito grande"))
                .when(downloadPolicy).validateOcspResponseSize(any(byte[].class), eq(OCSP_URL));

        client.check(leafCert, rootCert, OCSP_URL);

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
