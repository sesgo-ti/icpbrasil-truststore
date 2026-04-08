package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.CollectionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static br.gov.go.saude.fhir.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class CertificateChainResolverTest {

    private static final String ROOT_AIA_URL = "http://test.example.com/root.cer";
    private static final String INTERMEDIATE_AIA_URL = "http://test.example.com/intermediate.p7b";

    HttpClient mockHttpClient;
    DownloadPolicy downloadPolicy;
    CertificateChainResolver resolver;

    KeyPair rootKeyPair;
    KeyPair intermediateKeyPair;
    KeyPair leafKeyPair;
    X509Certificate rootCert;
    X509Certificate intermediateCert;
    X509Certificate leafCert;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rootKeyPair = kpg.generateKeyPair();
        intermediateKeyPair = kpg.generateKeyPair();
        leafKeyPair = kpg.generateKeyPair();

        rootCert = generateRootCert(rootKeyPair);
        intermediateCert = generateIntermediateCert(
                intermediateKeyPair, rootKeyPair, rootCert, ROOT_AIA_URL);
        leafCert = generateLeafCert(
                leafKeyPair, intermediateKeyPair, intermediateCert, INTERMEDIATE_AIA_URL);

        mockHttpClient = mock(HttpClient.class);

        TrustStoreConfig.ChainConfig chainConfig = new TrustStoreConfig.ChainConfig();
        chainConfig.setDownloadTimeoutSeconds(10);
        chainConfig.setMaxRetries(0);
        chainConfig.setRetryIntervalSeconds(0);

        TrustStoreConfig trustStoreConfig = new TrustStoreConfig();
        TrustStoreConfig.NetworkConfig networkConfig = new TrustStoreConfig.NetworkConfig();
        networkConfig.setDownloadTimeoutSeconds(30);
        networkConfig.setMaxRetries(1);
        networkConfig.setRetryIntervalSeconds(0);
        trustStoreConfig.setNetwork(networkConfig);

        downloadPolicy = mock(DownloadPolicy.class); // permissivo: não bloqueia nada

        RetryPolicy retryPolicy = new RetryPolicy(trustStoreConfig);
        resolver = new CertificateChainResolver(retryPolicy, chainConfig, mockHttpClient, downloadPolicy);
    }

    @Test
    @SneakyThrows
    void testResolveChainCadeiaCompleta() {
        mockHttpResponse(INTERMEDIATE_AIA_URL, buildP7b(List.of(intermediateCert, rootCert)));

        List<X509Certificate> chain = resolver.resolveChain(leafCert);

        assertEquals(3, chain.size());
        assertEquals(leafCert, chain.get(0));
        assertEquals(intermediateCert, chain.get(1));
        assertEquals(rootCert, chain.get(2));
    }

    @Test
    @SneakyThrows
    void testResolveChainAkiSkiRelacionamento() {
        mockHttpResponse(INTERMEDIATE_AIA_URL, buildP7b(List.of(intermediateCert, rootCert)));

        List<X509Certificate> chain = resolver.resolveChain(leafCert);

        for (int i = 0; i < chain.size() - 1; i++) {
            String aki = CertificateParser.getAuthorityKeyIdentifier(chain.get(i));
            String issuerSki = CertificateParser.getSubjectKeyIdentifier(chain.get(i + 1));
            assertEquals(aki, issuerSki,
                    "AKI do certificado [%d] deve ser igual ao SKI do certificado [%d]".formatted(i, i + 1));
        }
    }

    @Test
    void testResolveChainCertificadoRaiz() {
        List<X509Certificate> chain = resolver.resolveChain(rootCert);

        assertEquals(1, chain.size());
        assertEquals(rootCert, chain.getFirst());
    }

    @Test
    @SneakyThrows
    void testResolveChainSemAiaLancaExcecao() {
        X509Certificate certSemAia = generateCertWithoutAia(
                leafKeyPair, intermediateKeyPair, intermediateCert);

        IncompleteChainException ex = assertThrows(IncompleteChainException.class,
                () -> resolver.resolveChain(certSemAia));

        assertEquals(1, ex.getPartialChain().size());
        assertEquals(certSemAia, ex.getPartialChain().getFirst());
        assertTrue(ex.getMessage().contains("CA Issuers"));
    }

    @Test
    @SneakyThrows
    void testResolveChainDownloadFalhaLancaExcecao() {
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("Conexão recusada"));

        IncompleteChainException ex = assertThrows(IncompleteChainException.class,
                () -> resolver.resolveChain(leafCert));

        assertEquals(1, ex.getPartialChain().size());
        assertEquals(leafCert, ex.getPartialChain().getFirst());
    }

    @Test
    @SneakyThrows
    void testResolveChainAssinaturaInvalidaLancaExcecao() {
        X509Certificate certComSkiForjado = generateCertWithSpoofedSki(intermediateCert);

        mockHttpResponse(INTERMEDIATE_AIA_URL, certComSkiForjado.getEncoded());

        IncompleteChainException ex = assertThrows(IncompleteChainException.class,
                () -> resolver.resolveChain(leafCert));

        assertTrue(ex.getMessage().contains("Assinatura inválida"));
    }

    @Test
    @SneakyThrows
    void testResolveChainVerificaAssinaturaDaCadeia() {
        mockHttpResponse(INTERMEDIATE_AIA_URL, buildP7b(List.of(intermediateCert, rootCert)));

        List<X509Certificate> chain = resolver.resolveChain(leafCert);

        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate cert = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            assertDoesNotThrow(() -> cert.verify(issuer.getPublicKey()));
        }

        X509Certificate root = chain.getLast();
        assertDoesNotThrow(() -> root.verify(root.getPublicKey()));
    }

    @Test
    @SneakyThrows
    void testResolveChainPoolReutilizaCertificadosDoP7b() {
        mockHttpResponse(INTERMEDIATE_AIA_URL, buildP7b(List.of(intermediateCert, rootCert)));

        resolver.resolveChain(leafCert);

        verify(mockHttpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testResolveChainDerUnicoCertificado() {
        mockHttpResponse(INTERMEDIATE_AIA_URL, intermediateCert.getEncoded());
        mockHttpResponse(ROOT_AIA_URL, rootCert.getEncoded());

        List<X509Certificate> chain = resolver.resolveChain(leafCert);

        assertEquals(3, chain.size());
        verify(mockHttpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }


    @Test
    @SneakyThrows
    void testResolveChainUrlBloqueadaTentaProximaUrl() {
        // Bloqueia a URL do intermediário
        doThrow(new DownloadPolicyException("URL bloqueada: " + INTERMEDIATE_AIA_URL))
                .when(downloadPolicy).validateUrl(INTERMEDIATE_AIA_URL);

        IncompleteChainException ex = assertThrows(IncompleteChainException.class,
                () -> resolver.resolveChain(leafCert));

        assertEquals(1, ex.getPartialChain().size());
        assertEquals(leafCert, ex.getPartialChain().getFirst());
        verify(mockHttpClient, never()).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SneakyThrows
    void testResolveChainRespostaMuitoGrandeBloqueada() {
        mockHttpResponse(INTERMEDIATE_AIA_URL, buildP7b(List.of(intermediateCert, rootCert)));

        doThrow(new DownloadPolicyException("Resposta AIA muito grande"))
                .when(downloadPolicy).validateAiaResponseSize(any(byte[].class), eq(INTERMEDIATE_AIA_URL));

        IncompleteChainException ex = assertThrows(IncompleteChainException.class,
                () -> resolver.resolveChain(leafCert));

        assertEquals(1, ex.getPartialChain().size());
        assertEquals(leafCert, ex.getPartialChain().getFirst());
    }

    @Test
    @SneakyThrows
    void testResolveChainRespostaMuitoGrandeNaoRetenta() {
        mockHttpResponse(INTERMEDIATE_AIA_URL, buildP7b(List.of(intermediateCert, rootCert)));

        doThrow(new DownloadPolicyException("Resposta AIA muito grande"))
                .when(downloadPolicy).validateAiaResponseSize(any(byte[].class), eq(INTERMEDIATE_AIA_URL));

        assertThrows(IncompleteChainException.class,
                () -> resolver.resolveChain(leafCert));

        // Deve ter feito apenas 1 request HTTP — a validação de tamanho é após o retry,
        // portanto não há retentativa
        verify(mockHttpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    // --- Helpers: HTTP mock ---

    @SneakyThrows
    @SuppressWarnings("unchecked")
    private void mockHttpResponse(String url, byte[] body) {
        HttpResponse<byte[]> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(body);

        when(mockHttpClient.send(
                argThat(req -> req != null && req.uri().toString().equals(url)),
                any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);
    }

    // --- Helpers: geração de certificados ---

    @SneakyThrows
    private X509Certificate generateIntermediateCert(KeyPair subjectKeyPair, KeyPair issuerKeyPair,
                                                     X509Certificate issuerCert, String aiaUrl) {
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=Test Intermediate CA, O=Test, C=BR");

        X509v3CertificateBuilder builder = createBuilder(issuerName, subject, 2, subjectKeyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        addSki(builder, subjectKeyPair);
        addAki(builder, issuerKeyPair);
        addAia(builder, aiaUrl);

        return sign(builder, issuerKeyPair);
    }

    @SneakyThrows
    private X509Certificate generateLeafCert(KeyPair subjectKeyPair, KeyPair issuerKeyPair,
                                             X509Certificate issuerCert, String aiaUrl) {
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=Test Leaf, O=Test, C=BR");

        X509v3CertificateBuilder builder = createBuilder(issuerName, subject, 3, subjectKeyPair);
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        addSki(builder, subjectKeyPair);
        addAki(builder, issuerKeyPair);
        addAia(builder, aiaUrl);

        return sign(builder, issuerKeyPair);
    }

    @SneakyThrows
    private X509Certificate generateCertWithoutAia(KeyPair subjectKeyPair, KeyPair issuerKeyPair,
                                                   X509Certificate issuerCert) {
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=Test No AIA, O=Test, C=BR");

        X509v3CertificateBuilder builder = createBuilder(issuerName, subject, 4, subjectKeyPair);
        addSki(builder, subjectKeyPair);
        addAki(builder, issuerKeyPair);

        return sign(builder, issuerKeyPair);
    }

    @SneakyThrows
    private X509Certificate generateCertWithSpoofedSki(X509Certificate certToSpoof) {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair fakeKeyPair = kpg.generateKeyPair();

        X500Name subject = new X500Name("CN=Fake Cert, O=Test, C=BR");

        X509v3CertificateBuilder builder = createBuilder(subject, subject, 99, fakeKeyPair);

        String spoofedSkiHex = CertificateParser.getSubjectKeyIdentifier(certToSpoof);
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(HexFormat.of().parseHex(spoofedSkiHex)));

        return sign(builder, fakeKeyPair);
    }

    @SneakyThrows
    private void addAia(X509v3CertificateBuilder builder, String url) {
        AccessDescription ad = new AccessDescription(
                AccessDescription.id_ad_caIssuers,
                new GeneralName(GeneralName.uniformResourceIdentifier, url));
        builder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(ad));
    }

    @SneakyThrows
    private byte[] buildP7b(List<X509Certificate> certs) {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        List<X509CertificateHolder> holders = new ArrayList<>();
        for (X509Certificate cert : certs) {
            holders.add(new JcaX509CertificateHolder(cert));
        }
        generator.addCertificates(new CollectionStore<>(holders));
        CMSSignedData signedData = generator.generate(
                new CMSProcessableByteArray(new byte[0]), false);
        return signedData.getEncoded();
    }
}
