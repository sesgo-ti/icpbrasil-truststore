package br.gov.go.saude.truststore.icpbrasil.http.tls;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Hierarquia sintética raiz (âncora) → intermediária → folha; a intermediária só é obtida pelo
 * AIA da folha, servida por um HTTP local, e o servidor HTTPS local apresenta apenas a folha,
 * como o servidor do ITI.
 */
class ItiTrustManagerTest {

    private static final AtomicLong SERIAL = new AtomicLong(50_000);
    private static final Instant CAPTURA_CADEIA_REAL = Instant.parse("2026-09-29T00:00:00Z");

    private final List<AutoCloseable> recursos = new ArrayList<>();
    private final AtomicInteger requisicoesAia = new AtomicInteger();

    private X509Certificate root;
    private KeyPair rootKeyPair;
    private KeyPair intermediarioKeyPair;
    private X509Certificate intermediario;
    private X509Certificate intermediarioDeOutraRaiz;
    private volatile X509Certificate intermediarioServido;
    private String aiaUrl;

    @BeforeEach
    @SneakyThrows
    void setUp() {
        rootKeyPair = TestBundleFactory.newKeyPair();
        root = TestBundleFactory.caCert("Raiz TLS Teste", rootKeyPair);
        intermediarioKeyPair = TestBundleFactory.newKeyPair();
        intermediario = TestBundleFactory.intermediateCaCert("Intermediaria TLS Teste", intermediarioKeyPair,
                root, rootKeyPair);
        KeyPair outraRaizKeyPair = TestBundleFactory.newKeyPair();
        X509Certificate outraRaiz = TestBundleFactory.caCert("Outra Raiz", outraRaizKeyPair);
        // Mesmo subject e mesma chave: assina a folha, mas encadeia numa raiz que não é âncora.
        intermediarioDeOutraRaiz = TestBundleFactory.intermediateCaCert("Intermediaria TLS Teste",
                intermediarioKeyPair, outraRaiz, outraRaizKeyPair);
        intermediarioServido = intermediario;

        HttpServer aiaServer = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
        aiaServer.createContext("/int.crt", exchange -> {
            requisicoesAia.incrementAndGet();
            byte[] body = encoded(intermediarioServido);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        aiaServer.start();
        recursos.add(() -> aiaServer.stop(0));
        aiaUrl = "http://127.0.0.1:" + aiaServer.getAddress().getPort() + "/int.crt";
    }

    @AfterEach
    @SneakyThrows
    void tearDown() {
        for (AutoCloseable recurso : recursos) {
            recurso.close();
        }
    }

    @Test
    @SneakyThrows
    void testHandshake_SoAFolhaComAiaValido_CompletaCadeiaEConecta() {
        String httpsUrl = iniciarHttps(folhaPara127());
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolverPermissivo(), Clock.systemUTC());

        assertEquals(200, get(trustManager, httpsUrl + "/ok").statusCode());
        assertEquals(1, requisicoesAia.get());
    }

    @Test
    @SneakyThrows
    void testHandshake_SegundaConexao_ReusaIntermediariaSemNovaBuscaAia() {
        String httpsUrl = iniciarHttps(folhaPara127());
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolverPermissivo(), Clock.systemUTC());

        get(trustManager, httpsUrl + "/ok");
        assertEquals(200, get(trustManager, httpsUrl + "/ok").statusCode());

        assertEquals(1, requisicoesAia.get());
    }

    @Test
    void testHandshake_AiaComCertificadoQueNaoEncadeia_RecusaConexao() {
        intermediarioServido = intermediarioDeOutraRaiz;
        String httpsUrl = iniciarHttps(folhaPara127());
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolverPermissivo(), Clock.systemUTC());

        assertThrows(SSLHandshakeException.class, () -> get(trustManager, httpsUrl + "/ok"));
        assertTrue(requisicoesAia.get() >= 1, "a intermediária deveria ter sido baixada e recusada pelo PKIX");
    }

    @Test
    void testHandshake_AiaForaDaAllowlist_RecusaSemRequisicao() {
        String httpsUrl = iniciarHttps(folhaPara127());
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root),
                resolverCom(DownloadPolicy.aiaLetsEncrypt()), Clock.systemUTC());

        assertThrows(SSLHandshakeException.class, () -> get(trustManager, httpsUrl + "/ok"));
        assertEquals(0, requisicoesAia.get());
    }

    @Test
    @SneakyThrows
    void testHandshake_HostnameDivergente_RecusaConexao() {
        KeyPair keyPair = TestBundleFactory.newKeyPair();
        X509Certificate folhaOutroHost = folha("outro.example", new GeneralName(GeneralName.dNSName, "outro.example"),
                keyPair);
        String httpsUrl = iniciarHttps(new Folha(folhaOutroHost, keyPair));
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolverPermissivo(), Clock.systemUTC());
        // Sem SSLEngine/Socket não há verificação de hostname: a cadeia em si é aceita, e o pool já fica completo.
        trustManager.checkServerTrusted(new X509Certificate[]{folhaOutroHost}, "ECDHE_RSA");

        assertThrows(SSLHandshakeException.class, () -> get(trustManager, httpsUrl + "/ok"));
    }

    @Test
    void testCheckServerTrusted_AiaComCertificadoQueNaoEncadeia_RelancaComAPrimeiraFalhaSuprimida() {
        intermediarioServido = intermediarioDeOutraRaiz;
        X509Certificate folha = folhaPara127().certificado();
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolverPermissivo(), Clock.systemUTC());

        CertificateException ex = assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{folha}, "ECDHE_RSA"));

        assertEquals(1, ex.getSuppressed().length);
        assertTrue(ex.getSuppressed()[0] instanceof CertificateException, ex.getSuppressed()[0].toString());
    }

    @Test
    @SneakyThrows
    void testCheckServerTrusted_IntermediariaVencidaNoPool_DescartadaNaInsercao() {
        Instant agora = Instant.now();
        X509Certificate folha = folhaPara127().certificado();
        X509Certificate venceLogo = intermediariaValidaAte(agora.plus(Duration.ofDays(1)));
        X509Certificate venceDepois = intermediariaValidaAte(agora.plus(Duration.ofDays(30)));
        CertificateChainResolver resolver = mock(CertificateChainResolver.class);
        when(resolver.resolveChain(folha)).thenReturn(List.of(folha, venceLogo), List.of(folha, venceDepois));
        RelogioAjustavel relogio = new RelogioAjustavel(agora);
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolver, relogio);

        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{folha}, "ECDHE_RSA"));
        assertEquals(1, trustManager.tamanhoDoPool());
        relogio.agora = agora.plus(Duration.ofDays(2));
        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{folha}, "ECDHE_RSA"));

        assertEquals(1, trustManager.tamanhoDoPool());
    }

    @Test
    @SneakyThrows
    void testCheckServerTrusted_ResolverLancaRuntimeException_LancaCertificateException() {
        X509Certificate folha = folhaPara127().certificado();
        CertificateChainResolver resolver = mock(CertificateChainResolver.class);
        when(resolver.resolveChain(folha)).thenThrow(new IllegalStateException("falha inesperada"));
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolver, Clock.systemUTC());

        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{folha}, "ECDHE_RSA"));
        assertEquals(0, trustManager.tamanhoDoPool());
    }

    @Test
    @SneakyThrows
    void testCheckServerTrusted_AiaComMaisDe64Intermediarias_PoolLimitadoA64() {
        X509Certificate folha = folhaPara127().certificado();
        List<X509Certificate> cadeia = new ArrayList<>(List.of(folha));
        for (int i = 0; i < 70; i++) {
            cadeia.add(TestBundleFactory.intermediateCaCert("Intermediaria " + i, intermediarioKeyPair, root, rootKeyPair));
        }
        CertificateChainResolver resolver = mock(CertificateChainResolver.class);
        when(resolver.resolveChain(folha)).thenReturn(cadeia);
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolver, Clock.systemUTC());

        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{folha}, "ECDHE_RSA"));

        assertEquals(64, trustManager.tamanhoDoPool());
    }

    @Test
    @SneakyThrows
    void testHandshake_PoolCheioDeIntermediariasInuteis_EsvaziaEConecta() {
        X509Certificate lixo = folhaPara127().certificado();
        List<X509Certificate> cadeiaInutil = new ArrayList<>(List.of(lixo));
        for (int i = 0; i < 64; i++) {
            cadeiaInutil.add(TestBundleFactory.intermediateCaCert("Inutil " + i, intermediarioKeyPair, root, rootKeyPair));
        }
        Folha folha = folhaPara127();
        CertificateChainResolver resolver = mock(CertificateChainResolver.class);
        when(resolver.resolveChain(lixo)).thenReturn(cadeiaInutil);
        when(resolver.resolveChain(folha.certificado())).thenReturn(List.of(folha.certificado(), intermediario));
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolver, Clock.systemUTC());
        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{lixo}, "ECDHE_RSA"));
        assertEquals(64, trustManager.tamanhoDoPool());

        assertEquals(200, get(trustManager, iniciarHttps(folha) + "/ok").statusCode());
        assertEquals(1, trustManager.tamanhoDoPool());
    }

    @Test
    void testSanitizarParaLog_CaracteresDeControle_SubstituidosPorInterrogacao() {
        assertEquals("http://x/?? WARN forjado?fim",
                ItiTrustManager.sanitizarParaLog("http://x/\r\n WARN forjado\u2028fim", 200));
    }

    @Test
    void testSanitizarParaLog_ControleC1_SubstituidoPorInterrogacao() {
        assertEquals("a?b", ItiTrustManager.sanitizarParaLog("a\u0085b", 200));
    }

    @Test
    void testSanitizarParaLog_AcimaDoLimite_Trunca() {
        assertEquals("abc...", ItiTrustManager.sanitizarParaLog("abcdef", 3));
        assertEquals("abc", ItiTrustManager.sanitizarParaLog("abc", 3));
    }

    @Test
    void testSanitizarParaLog_Nulo_RetornaTextoNull() {
        assertEquals("null", ItiTrustManager.sanitizarParaLog(null, 10));
    }

    @Test
    @SneakyThrows
    void testCheckServerTrusted_CadeiaRealDoIti_ValidaComRelogioFixo() {
        ItiTrustManager trustManager = new ItiTrustManager(ItiTlsAnchors.load(), resolverDaCadeiaReal(),
                Clock.fixed(CAPTURA_CADEIA_REAL, ZoneOffset.UTC));

        trustManager.checkServerTrusted(new X509Certificate[]{folhaReal()}, "ECDHE_ECDSA");
    }

    @Test
    @SneakyThrows
    void testCheckServerTrusted_CadeiaRealDoItiComRelogioAposVencimentoDaFolha_LancaCertificateException() {
        ItiTrustManager trustManager = new ItiTrustManager(ItiTlsAnchors.load(), resolverDaCadeiaReal(),
                Clock.fixed(Instant.parse("2026-10-20T00:00:00Z"), ZoneOffset.UTC));

        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{folhaReal()}, "ECDHE_ECDSA"));
    }

    @Test
    @SneakyThrows
    void testCheckServerTrusted_CadeiaRealDoItiComRelogioAntesDaEmissaoDaFolha_LancaCertificateException() {
        ItiTrustManager trustManager = new ItiTrustManager(ItiTlsAnchors.load(), resolverDaCadeiaReal(),
                Clock.fixed(Instant.parse("2026-07-01T00:00:00Z"), ZoneOffset.UTC));

        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{folhaReal()}, "ECDHE_ECDSA"));
    }

    @Test
    void testCheckClientTrusted_QualquerCadeia_LancaCertificateException() {
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolverPermissivo(), Clock.systemUTC());

        assertThrows(CertificateException.class,
                () -> trustManager.checkClientTrusted(new X509Certificate[]{root}, "RSA"));
    }

    @Test
    void testGetAcceptedIssuers_DevolveSomenteAsAncoras() {
        ItiTrustManager trustManager = new ItiTrustManager(List.of(root), resolverPermissivo(), Clock.systemUTC());

        assertArrayEquals(new X509Certificate[]{root}, trustManager.getAcceptedIssuers());
    }

    @Test
    void testProducao_AncorasIsrg() {
        ItiTrustManager trustManager = ItiTrustManager.producao(Clock.systemUTC());

        assertEquals(ItiTlsAnchors.load(), List.of(trustManager.getAcceptedIssuers()));
    }

    @Test
    @SneakyThrows
    void testProducao_BuscaAiaPelaPoliticaDoLetsEncrypt() {
        X509Certificate folha = folhaPara127().certificado();
        DownloadPolicy politica = mock(DownloadPolicy.class);
        doThrow(new DownloadPolicyException("recusada")).when(politica).validateUrl(anyString());
        ItiTrustManager trustManager = producaoCom(politica);

        assertThrows(CertificateException.class,
                () -> trustManager.checkServerTrusted(new X509Certificate[]{folha}, "ECDHE_RSA"));

        verify(politica).validateUrl(aiaUrl);
        assertEquals(0, requisicoesAia.get());
    }

    /** {@link ItiTrustManager#producao} com {@link DownloadPolicy#aiaLetsEncrypt()} devolvendo {@code politica}. */
    private static ItiTrustManager producaoCom(DownloadPolicy politica) {
        try (MockedStatic<DownloadPolicy> fabrica = mockStatic(DownloadPolicy.class)) {
            fabrica.when(DownloadPolicy::aiaLetsEncrypt).thenReturn(politica);
            return ItiTrustManager.producao(Clock.systemUTC());
        }
    }

    private record Folha(X509Certificate certificado, KeyPair keyPair) {
    }

    private static final class RelogioAjustavel extends Clock {
        private volatile Instant agora;

        private RelogioAjustavel(Instant agora) {
            this.agora = agora;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Instant instant() {
            return agora;
        }
    }

    @SneakyThrows
    private X509Certificate intermediariaValidaAte(Instant notAfter) {
        X500Name subject = new X500Name("CN=Intermediaria " + SERIAL.incrementAndGet() + ", O=Test, C=BR");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(TestCertificateFactory.issuerNameOf(root),
                BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(Instant.now().minus(Duration.ofDays(1))),
                Date.from(notAfter), subject, intermediarioKeyPair.getPublic());
        return TestCertificateFactory.sign(builder, rootKeyPair);
    }

    private Folha folhaPara127() {
        KeyPair keyPair = TestBundleFactory.newKeyPair();
        return new Folha(folha("127.0.0.1", new GeneralName(GeneralName.iPAddress, "127.0.0.1"), keyPair), keyPair);
    }

    @SneakyThrows
    private X509Certificate folha(String cn, GeneralName san, KeyPair keyPair) {
        X500Name subject = new X500Name("CN=" + cn + ", O=Test, C=BR");
        X509v3CertificateBuilder builder = TestCertificateFactory.createBuilder(
                TestCertificateFactory.issuerNameOf(intermediario), subject, SERIAL.incrementAndGet(), keyPair);
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(san));
        TestCertificateFactory.addSki(builder, keyPair);
        TestCertificateFactory.addAki(builder, intermediarioKeyPair);
        TestCertificateFactory.addAia(builder, aiaUrl);
        return TestCertificateFactory.sign(builder, intermediarioKeyPair);
    }

    /** Servidor HTTPS em 127.0.0.1 que apresenta só a folha, sem intermediária. */
    @SneakyThrows
    private String iniciarHttps(Folha folha) {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", folha.keyPair().getPrivate(), new char[0],
                new Certificate[]{folha.certificado()});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        ExecutorService executor = Executors.newCachedThreadPool();
        server.setExecutor(executor);
        server.createContext("/ok", exchange -> {
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        recursos.add(() -> {
            server.stop(0);
            executor.shutdownNow();
        });
        return "https://127.0.0.1:" + server.getAddress().getPort();
    }

    /** GET por {@link HttpClient}, que liga a verificação de hostname (endpoint identification HTTPS). */
    private static HttpResponse<String> get(ItiTrustManager trustManager, String url)
            throws IOException, InterruptedException, GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{trustManager}, null);
        try (HttpClient client = HttpClient.newBuilder()
                .sslContext(context)
                .connectTimeout(Duration.ofSeconds(5))
                .build()) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15)).build();
            return client.send(request, HttpResponse.BodyHandlers.ofString());
        }
    }

    private static CertificateChainResolver resolverCom(DownloadPolicy policy) {
        TrustStoreConfig.ChainConfig chainConfig = new TrustStoreConfig.ChainConfig();
        chainConfig.setMaxRetries(0);
        chainConfig.setDownloadTimeoutSeconds(5);
        HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        return new CertificateChainResolver(new RetryPolicy(new TrustStoreConfig()), chainConfig, httpClient, policy);
    }

    /** O servidor AIA local está em loopback, que qualquer política real bloquearia. */
    private static CertificateChainResolver resolverPermissivo() {
        DownloadPolicy policy = mock(DownloadPolicy.class);
        when(policy.getMaxAiaResponseBytes()).thenReturn(1_048_576L);
        return resolverCom(policy);
    }

    @SneakyThrows
    private static CertificateChainResolver resolverDaCadeiaReal() {
        X509Certificate leaf = folhaReal();
        CertificateChainResolver resolver = mock(CertificateChainResolver.class);
        when(resolver.resolveChain(leaf)).thenReturn(List.of(leaf, fixture("tls/le-ye1.crt"),
                fixture("tls/le-root-ye-x2.crt")));
        return resolver;
    }

    private static X509Certificate folhaReal() {
        return fixture("tls/acraiz-icpbrasil-gov-br-2026-07-21.crt");
    }

    @SneakyThrows
    private static X509Certificate fixture(String recurso) {
        try (InputStream in = ItiTrustManagerTest.class.getClassLoader().getResourceAsStream(recurso)) {
            return CertificateParser.parse(in);
        }
    }

    @SneakyThrows
    private static byte[] encoded(X509Certificate certificate) {
        return certificate.getEncoded();
    }
}
