package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.math.BigInteger;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OcspClientTest {

    private static final String OCSP_URL = "http://ocsp.example.com/status";
    private static final X500Name RESPONDER_NAME = new X500Name("CN=Test OCSP Responder, O=Test, C=BR");

    HttpClient mockHttpClient;
    DownloadPolicy downloadPolicy;
    RevocationCache cache;
    RetryPolicy retryPolicy;
    OcspClient client;

    KeyPairGenerator kpg;
    KeyPair rootKeyPair;
    KeyPair leafKeyPair;
    X509Certificate rootCert;
    X509Certificate leafCert;

    // Instante fixo, com precisão de segundos como o GeneralizedTime das respostas
    Instant now;
    DigestCalculatorProvider digests;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rootKeyPair = kpg.generateKeyPair();
        leafKeyPair = kpg.generateKeyPair();

        rootCert = generateRootCert(rootKeyPair);
        leafCert = generateLeafCert(leafKeyPair, rootKeyPair, rootCert);

        now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        digests = new JcaDigestCalculatorProviderBuilder().build();

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
        client = new OcspClient(cache, retryPolicy, revocationConfig, mockHttpClient, downloadPolicy,
                Clock.fixed(now, ZoneOffset.UTC));
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

    // --- Status do certificado ---

    @Test
    @SneakyThrows
    void testCheckRespostaGoodRetornaGoodECacheia() {
        byte[] response = issuerSigned(single(leafCertId(), CertificateStatus.GOOD));
        mockHttpResponse(response);

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        RevocationStatus.Good good = assertInstanceOf(RevocationStatus.Good.class, status);
        assertArrayEquals(response, good.responseDer());
        verify(cache).putOcsp(anyString(), eq(response));
    }

    @Test
    @SneakyThrows
    void testCheckRespostaRevokedRetornaRevoked() {
        mockHttpResponse(issuerSigned(single(leafCertId(),
                new RevokedStatus(Date.from(now.minus(1, ChronoUnit.DAYS))))));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Revoked.class, status);
        verify(cache).putOcsp(anyString(), any());
    }

    @Test
    @SneakyThrows
    void testLookupRespostaRevokedRetornaEvidenciaComOsBytesDaResposta() {
        byte[] response = issuerSigned(single(leafCertId(),
                new RevokedStatus(Date.from(now.minus(1, ChronoUnit.DAYS)))));
        mockHttpResponse(response);

        RevocationLookup lookup = client.lookup(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Revoked.class, lookup.status());
        RevocationEvidence.OcspResponse evidence =
                assertInstanceOf(RevocationEvidence.OcspResponse.class, lookup.evidence());
        assertArrayEquals(response, evidence.der());
    }

    @Test
    @SneakyThrows
    void testLookupRespostaUnknownNaoTemEvidencia() {
        mockHttpResponse(issuerSigned(single(leafCertId(), new UnknownStatus())));

        RevocationLookup lookup = client.lookup(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.OcspUnavailable.class, lookup.status());
        assertNull(lookup.evidence());
    }

    @Test
    @SneakyThrows
    void testCheckRespostaUnknownRetornaOcspUnavailable() {
        mockHttpResponse(issuerSigned(single(leafCertId(), new UnknownStatus())));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.OcspUnavailable.class, status);
        verify(cache, never()).putOcsp(anyString(), any());
    }

    // --- Correspondência do CertID ---

    @Test
    @SneakyThrows
    void testCheckCertIdComOutroSerialRetornaMalformed() {
        CertificateID outroSerial = CertificateID.deriveCertificateID(leafCertId(),
                leafCert.getSerialNumber().add(BigInteger.ONE));
        mockHttpResponse(issuerSigned(single(outroSerial, CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckCertIdComChaveDeOutraCaRetornaMalformed() {
        // Mesmo DN do emissor, outra chave: issuerNameHash coincide, issuerKeyHash não
        X509Certificate outraCa = generateRootCert(kpg.generateKeyPair());
        CertificateID certIdOutraCa = certIdFor(outraCa, leafCert.getSerialNumber());
        mockHttpResponse(issuerSigned(single(certIdOutraCa, CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckAlvoNaSegundaPosicaoRetornaGood() {
        CertificateID outroSerial = CertificateID.deriveCertificateID(leafCertId(), BigInteger.valueOf(999));
        mockHttpResponse(issuerSigned(
                single(outroSerial, new RevokedStatus(Date.from(now.minus(1, ChronoUnit.DAYS)))),
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckCertIdDuplicadoRetornaMalformed() {
        mockHttpResponse(issuerSigned(
                single(leafCertId(), CertificateStatus.GOOD),
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckCertIdComSha256RetornaGood() {
        CertificateID sha256Id = new CertificateID(digests.get(sha256()),
                new JcaX509CertificateHolder(rootCert), leafCert.getSerialNumber());
        mockHttpResponse(issuerSigned(single(sha256Id, CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    // --- Janela temporal ---

    @Test
    @SneakyThrows
    void testCheckNextUpdateVencidoRetornaMalformed() {
        mockHttpResponse(issuerSigned(single(leafCertId(), CertificateStatus.GOOD,
                now.minus(2, ChronoUnit.HOURS), now.minus(1, ChronoUnit.HOURS))));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
        verify(cache, never()).putOcsp(anyString(), any());
    }

    @Test
    @SneakyThrows
    void testCheckThisUpdateFuturoRetornaMalformed() {
        mockHttpResponse(issuerSigned(single(leafCertId(), CertificateStatus.GOOD,
                now.plus(1, ChronoUnit.HOURS), now.plus(2, ChronoUnit.HOURS))));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckThisUpdateFuturoDentroDaToleranciaRetornaGood() {
        mockHttpResponse(issuerSigned(single(leafCertId(), CertificateStatus.GOOD,
                now.plus(10, ChronoUnit.MINUTES), now.plus(1, ChronoUnit.HOURS))));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckProducedAtFuturoRetornaMalformed() {
        mockHttpResponse(ocspResponse(byName(rootCert), rootKeyPair, null, now.plus(1, ChronoUnit.HOURS),
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckSemNextUpdateRecenteRetornaGoodSemCachear() {
        mockHttpResponse(issuerSigned(single(leafCertId(), CertificateStatus.GOOD,
                now.minus(1, ChronoUnit.MINUTES), null)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
        verify(cache, never()).putOcsp(anyString(), any());
    }

    @Test
    @SneakyThrows
    void testCheckSemNextUpdateAntigoRetornaMalformed() {
        mockHttpResponse(issuerSigned(single(leafCertId(), CertificateStatus.GOOD,
                now.minus(1, ChronoUnit.HOURS), null)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    // --- Assinante ---

    @Test
    @SneakyThrows
    void testCheckResponderIdByKeyDoEmissorRetornaGood() {
        mockHttpResponse(ocspResponse(byKey(rootCert), rootKeyPair, null, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckDelegadoValidoRetornaGood() {
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, rootKeyPair, rootCert,
                now.minus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), ekuOcspSigning());
        mockHttpResponse(ocspResponse(byName(delegado), delegadoKeyPair, new X509Certificate[]{delegado}, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckDelegadoIdentificadoByKeyRetornaGood() {
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, rootKeyPair, rootCert,
                now.minus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), ekuOcspSigning());
        mockHttpResponse(ocspResponse(byKey(delegado), delegadoKeyPair, new X509Certificate[]{delegado}, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckDelegadoComOcspNoCheckRetornaGood() {
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, rootKeyPair, rootCert,
                now.minus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), ekuOcspSigning(), ocspNoCheck());
        mockHttpResponse(ocspResponse(byName(delegado), delegadoKeyPair, new X509Certificate[]{delegado}, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckDelegadoExpiradoRetornaMalformed() {
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, rootKeyPair, rootCert,
                now.minus(30, ChronoUnit.DAYS), now.minus(1, ChronoUnit.DAYS), ekuOcspSigning());
        mockHttpResponse(ocspResponse(byName(delegado), delegadoKeyPair, new X509Certificate[]{delegado}, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckDelegadoAindaNaoValidoRetornaMalformed() {
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, rootKeyPair, rootCert,
                now.plus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), ekuOcspSigning());
        mockHttpResponse(ocspResponse(byName(delegado), delegadoKeyPair, new X509Certificate[]{delegado}, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckDelegadoSemEkuRetornaMalformed() {
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, rootKeyPair, rootCert,
                now.minus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS));
        mockHttpResponse(ocspResponse(byName(delegado), delegadoKeyPair, new X509Certificate[]{delegado}, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckAssinanteNaoAutorizadoRetornaMalformed() {
        // Delegado com EKU cujo emissor tem o mesmo DN da CA, mas assinado por outra chave
        KeyPair outraCaKeyPair = kpg.generateKeyPair();
        X509Certificate outraCa = generateRootCert(outraCaKeyPair);
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, outraCaKeyPair, outraCa,
                now.minus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), ekuOcspSigning());
        mockHttpResponse(ocspResponse(byName(delegado), delegadoKeyPair, new X509Certificate[]{delegado}, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckResponderIdDesconhecidoRetornaMalformed() {
        // Assinatura do emissor, mas ResponderID de um nome que não identifica nenhum assinante
        mockHttpResponse(ocspResponse(new RespID(RESPONDER_NAME), rootKeyPair, null, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    @Test
    @SneakyThrows
    void testCheckResponderIdDoEmissorComAssinaturaDoDelegadoRetornaMalformed() {
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, rootKeyPair, rootCert,
                now.minus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), ekuOcspSigning());
        mockHttpResponse(ocspResponse(byName(rootCert), delegadoKeyPair, new X509Certificate[]{delegado}, now,
                single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Malformed.class, status);
    }

    // --- Cache ---

    @Test
    @SneakyThrows
    void testCheckHitDeCacheVencidoRefazConsultaERefleteNovaResposta() {
        byte[] vencida = issuerSigned(single(leafCertId(), CertificateStatus.GOOD,
                now.minus(2, ChronoUnit.HOURS), now.minus(1, ChronoUnit.HOURS)));
        when(cache.getOcsp(anyString())).thenReturn(Optional.of(vencida));
        byte[] atual = issuerSigned(single(leafCertId(),
                new RevokedStatus(Date.from(now.minus(1, ChronoUnit.DAYS)))));
        mockHttpResponse(atual);

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Revoked.class, status);
        verify(mockHttpClient, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        verify(cache).putOcsp(anyString(), eq(atual));
    }

    @Test
    @SneakyThrows
    void testCheckHitDeCacheComDelegadoExpiradoRefazConsulta() {
        KeyPair delegadoKeyPair = kpg.generateKeyPair();
        X509Certificate delegado = generateResponderCert(delegadoKeyPair, rootKeyPair, rootCert,
                now.minus(30, ChronoUnit.DAYS), now.minus(1, ChronoUnit.DAYS), ekuOcspSigning());
        byte[] assinadaPorDelegadoExpirado = ocspResponse(byName(delegado), delegadoKeyPair,
                new X509Certificate[]{delegado}, now, single(leafCertId(), CertificateStatus.GOOD));
        when(cache.getOcsp(anyString())).thenReturn(Optional.of(assinadaPorDelegadoExpirado));
        mockHttpResponse(issuerSigned(single(leafCertId(), CertificateStatus.GOOD)));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
        verify(mockHttpClient, times(1)).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testCheckHitDeCacheValidoRetornaGoodSemHttp() {
        when(cache.getOcsp(anyString()))
                .thenReturn(Optional.of(issuerSigned(single(leafCertId(), CertificateStatus.GOOD))));

        RevocationStatus status = client.check(leafCert, rootCert, OCSP_URL);

        assertInstanceOf(RevocationStatus.Good.class, status);
        verify(mockHttpClient, never()).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testCheckChaveDeCacheDistingueEmissoresComMesmoNome() {
        KeyPair outraCaKeyPair = kpg.generateKeyPair();
        X509Certificate outraCa = generateRootCert(outraCaKeyPair);
        X509Certificate outraFolha = generateLeafCert(kpg.generateKeyPair(), outraCaKeyPair, outraCa);
        assertEquals(leafCert.getSerialNumber(), outraFolha.getSerialNumber());
        assertEquals(leafCert.getIssuerX500Principal(), outraFolha.getIssuerX500Principal());

        mockHttpResponse(issuerSigned(single(leafCertId(), CertificateStatus.GOOD)));
        client.check(leafCert, rootCert, OCSP_URL);
        mockHttpResponse(ocspResponse(byName(outraCa), outraCaKeyPair, null, now,
                single(certIdFor(outraCa, outraFolha.getSerialNumber()), CertificateStatus.GOOD)));
        client.check(outraFolha, outraCa, OCSP_URL);

        ArgumentCaptor<String> chaves = ArgumentCaptor.forClass(String.class);
        verify(cache, times(2)).putOcsp(chaves.capture(), any());
        assertNotEquals(chaves.getAllValues().get(0), chaves.getAllValues().get(1));
    }

    // --- Helpers: certificados ---

    /**
     * Certificado de responder OCSP emitido por {@code issuerCert}, com período de validade
     * explícito e as extensões adicionais informadas (ver {@link #ekuOcspSigning()} e
     * {@link #ocspNoCheck()}).
     */
    @SneakyThrows
    private X509Certificate generateResponderCert(KeyPair subjectKeyPair, KeyPair issuerKeyPair,
                                                  X509Certificate issuerCert, Instant notBefore,
                                                  Instant notAfter, Extension... extensoes) {
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, BigInteger.valueOf(20), Date.from(notBefore), Date.from(notAfter),
                RESPONDER_NAME, subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        addSki(builder, subjectKeyPair);
        addAki(builder, issuerKeyPair);
        for (Extension extensao : extensoes) {
            builder.addExtension(extensao);
        }
        return sign(builder, issuerKeyPair);
    }

    @SneakyThrows
    private static Extension ekuOcspSigning() {
        return new Extension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning).getEncoded());
    }

    @SneakyThrows
    private static Extension ocspNoCheck() {
        return new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE.getEncoded());
    }

    // --- Helpers: respostas OCSP ---

    private record SingleResponseSpec(CertificateID certId, CertificateStatus status,
                                      Instant thisUpdate, Instant nextUpdate) {}

    /** SingleResponse recém-emitido e válido por uma hora. */
    private SingleResponseSpec single(CertificateID certId, CertificateStatus status) {
        return single(certId, status, now.minus(1, ChronoUnit.MINUTES), now.plus(1, ChronoUnit.HOURS));
    }

    private SingleResponseSpec single(CertificateID certId, CertificateStatus status,
                                      Instant thisUpdate, Instant nextUpdate) {
        return new SingleResponseSpec(certId, status, thisUpdate, nextUpdate);
    }

    /** Resposta assinada diretamente pela CA emissora, identificada por nome e produzida agora. */
    private byte[] issuerSigned(SingleResponseSpec... singles) {
        return ocspResponse(byName(rootCert), rootKeyPair, null, now, singles);
    }

    @SneakyThrows
    private byte[] ocspResponse(RespID responderId, KeyPair signerKeyPair, X509Certificate[] includedCerts,
                                Instant producedAt, SingleResponseSpec... singles) {
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(responderId);
        for (SingleResponseSpec spec : singles) {
            builder.addResponse(spec.certId(), spec.status(), Date.from(spec.thisUpdate()),
                    spec.nextUpdate() == null ? null : Date.from(spec.nextUpdate()), null);
        }
        X509CertificateHolder[] chain = null;
        if (includedCerts != null) {
            chain = new X509CertificateHolder[includedCerts.length];
            for (int i = 0; i < includedCerts.length; i++) {
                chain[i] = new JcaX509CertificateHolder(includedCerts[i]);
            }
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(signerKeyPair.getPrivate());
        BasicOCSPResp basic = builder.build(signer, chain, Date.from(producedAt));
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    private CertificateID leafCertId() {
        return certIdFor(rootCert, leafCert.getSerialNumber());
    }

    @SneakyThrows
    private CertificateID certIdFor(X509Certificate issuer, BigInteger serial) {
        return new CertificateID(digests.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuer), serial);
    }

    @SneakyThrows
    private RespID byName(X509Certificate signer) {
        return new RespID(new JcaX509CertificateHolder(signer).getSubject());
    }

    @SneakyThrows
    private RespID byKey(X509Certificate signer) {
        return new RespID(new JcaX509CertificateHolder(signer).getSubjectPublicKeyInfo(),
                digests.get(RespID.HASH_SHA1));
    }

    private static AlgorithmIdentifier sha256() {
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    }

    // --- Helpers: HTTP mock ---

    /** Simula um 200 com o corpo informado; o transporte só consome status e corpo da resposta. */
    @SuppressWarnings("unchecked")
    private void mockHttpResponse(byte[] body) {
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(body);
        doReturn(CompletableFuture.completedFuture(response))
                .when(mockHttpClient).sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

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
