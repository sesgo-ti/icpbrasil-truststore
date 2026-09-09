package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.CrlClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.OcspClient;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationCache;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import br.gov.go.saude.truststore.icpbrasil.support.TestChain;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validador com os clientes reais sobre um servidor HTTP local que publica as evidências nas
 * URLs embutidas nos certificados. O servidor conta as requisições por caminho: como todas as
 * URLs apontam para ele, qualquer conexão aberta pelo JDK por conta própria apareceria na contagem.
 */
class PkixCertificateValidatorHttpTest {

    static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    HttpServer server;
    String base;
    TestChain chain;
    Map<String, AtomicInteger> requests;
    Map<String, byte[]> responses;
    Map<String, Integer> statuses;
    PkixCertificateValidator validator;

    @BeforeEach
    void setUp() throws IOException {
        requests = new ConcurrentHashMap<>();
        responses = new ConcurrentHashMap<>();
        statuses = new ConcurrentHashMap<>();
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            requests.computeIfAbsent(path, p -> new AtomicInteger()).incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] body = responses.getOrDefault(path, new byte[0]);
            int status = statuses.getOrDefault(path, 200);
            exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        chain = TestChain.create(new TestChain.Endpoints(base + "/root.crl", base + "/root-ocsp"),
                new TestChain.Endpoints(base + "/intermediate.crl", base + "/intermediate-ocsp"));

        // Loopback é bloqueado pela política real; aqui o destino é o servidor do teste.
        DownloadPolicy policy = mock(DownloadPolicy.class);
        when(policy.getMaxOcspResponseBytes()).thenReturn(1_048_576L);
        when(policy.getMaxCrlResponseBytes()).thenReturn(52_428_800L);
        when(policy.getMaxAiaResponseBytes()).thenReturn(10_485_760L);
        HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        CertificateHttpTransport transport = new CertificateHttpTransport(policy, httpClient);

        TrustStoreConfig config = new TrustStoreConfig();
        config.getNetwork().setMaxRetries(1);
        config.getNetwork().setRetryIntervalSeconds(0);
        config.getRevocation().setMaxRetries(0);
        config.getRevocation().setRetryIntervalSeconds(0);
        RetryPolicy retryPolicy = new RetryPolicy(config);
        RevocationCache cache = new RevocationCache(config);
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        OcspClient ocspClient = new OcspClient(cache, retryPolicy, config.getRevocation(), httpClient, policy, clock);
        CrlClient crlClient = new CrlClient(cache, retryPolicy, config.getRevocation(), httpClient, policy, clock);
        RevocationService revocationService = new RevocationService(ocspClient, crlClient);
        CertificateChainResolver resolver = new CertificateChainResolver(retryPolicy, config, transport);

        validator = new PkixCertificateValidator(() -> Optional.of(TrustMaterial.of(chain.authorities())),
                resolver, revocationService, clock);
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void testValidate_RespondersOcspDisponiveis_ValidPorOcspECacheNaSegundaConsulta() {
        responses.put("/intermediate-ocsp", chain.intermediateOcsp(NOW, CertificateStatus.GOOD));
        responses.put("/root-ocsp", chain.rootOcsp(NOW, CertificateStatus.GOOD));

        ValidationResult primeira = validator.validate(chain.leaf());
        ValidationResult segunda = validator.validate(chain.leaf());

        ValidationResult.Valid valid = assertInstanceOf(ValidationResult.Valid.class, primeira);
        assertTrue(valid.evidence().stream().allMatch(e -> e instanceof RevocationEvidence.OcspResponse));
        assertInstanceOf(ValidationResult.Valid.class, segunda);
        assertEquals(1, requests.get("/intermediate-ocsp").get(), "segunda consulta servida pelo cache");
        assertEquals(1, requests.get("/root-ocsp").get());
        assertEquals(Map.of("/intermediate-ocsp", 1, "/root-ocsp", 1), counts(),
                "nenhuma requisição além das duas consultas OCSP da biblioteca: o JDK não abriu conexões");
    }

    @Test
    void testValidate_RespondersOcspIndisponiveis_CaiParaCrlPorCertificado() {
        statuses.put("/intermediate-ocsp", 500);
        statuses.put("/root-ocsp", 500);
        responses.put("/intermediate.crl", chain.intermediateCrl(NOW, Map.of()));
        responses.put("/root.crl", chain.rootCrl(NOW, Map.of()));

        ValidationResult result = validator.validate(chain.leaf());

        ValidationResult.Valid valid = assertInstanceOf(ValidationResult.Valid.class, result);
        assertTrue(valid.evidence().stream().allMatch(e -> e instanceof RevocationEvidence.Crl));
        assertEquals(Map.of("/intermediate-ocsp", 1, "/root-ocsp", 1, "/intermediate.crl", 1, "/root.crl", 1), counts());
    }

    @Test
    void testValidate_FolhaRevogadaNaCrl_RevokedSemConsultarAIntermediaria() {
        statuses.put("/intermediate-ocsp", 500);
        responses.put("/intermediate.crl",
                chain.intermediateCrl(NOW, Map.of(chain.leaf().getSerialNumber(), NOW.minusSeconds(600))));

        ValidationResult result = validator.validate(chain.leaf());

        assertEquals(chain.leaf(), assertInstanceOf(ValidationResult.Revoked.class, result).certificate());
        assertEquals(Map.of("/intermediate-ocsp", 1, "/intermediate.crl", 1), counts());
    }

    private Map<String, Integer> counts() {
        Map<String, Integer> counts = new ConcurrentHashMap<>();
        requests.forEach((path, count) -> counts.put(path, count.get()));
        return counts;
    }
}
