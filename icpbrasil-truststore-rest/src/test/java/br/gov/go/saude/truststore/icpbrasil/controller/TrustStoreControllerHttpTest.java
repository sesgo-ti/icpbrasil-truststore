package br.gov.go.saude.truststore.icpbrasil.controller;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.util.HashValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Contrato HTTP do serviço em função do acervo: sem snapshot vigente a consulta responde 503 e a
 * readiness fica DOWN (liveness segue UP); após a carga, PEM/DER são servidos com
 * {@code Cache-Control: no-store} e a readiness sobe. O contexto é compartilhado e o cache só
 * pode ser populado pelo pipeline, por isso a ordem dos testes é explícita: o estado vazio é
 * verificado antes da carga.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "icpbrasil-truststore.bootstrap.enabled=false",
        "icpbrasil-truststore.scheduling.enabled=false",
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TrustStoreControllerHttpTest {

    @TempDir
    static Path baseDir;

    static X509Certificate root;
    static byte[] zip;
    static String hash;

    @MockitoBean
    Downloader downloader;

    @Autowired
    TestRestTemplate http;

    @Autowired
    TrustStoreService service;

    @Autowired
    TrustStoreConfig config;

    @DynamicPropertySource
    static void storageTemporario(DynamicPropertyRegistry registry) {
        registry.add("icpbrasil-truststore.filesystem.base-dir", () -> baseDir.toString());
    }

    @BeforeAll
    static void generateBundle() {
        root = TestBundleFactory.caCert("Raiz A", TestBundleFactory.newKeyPair());
        zip = TestBundleFactory.bundleOf(root);
        hash = HashValidator.computeSha512(zip);
    }

    @Test
    @Order(1)
    void testSemAcervo_CertificateIndisponivelEReadinessDown_LivenessUp() {
        ResponseEntity<String> certificado = http.getForEntity("/certificate?ski=" + ski(root), String.class);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, certificado.getStatusCode());
        assertEquals("no-store", certificado.getHeaders().getCacheControl());

        ResponseEntity<String> readiness = http.getForEntity("/actuator/health/readiness", String.class);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, readiness.getStatusCode());
        JsonNode grupo = json(readiness);
        assertEquals("UP", grupo.at("/components/readinessState/status").asText());
        assertEquals("DOWN", grupo.at("/components/trustStoreCache/status").asText());
        assertEquals("UNAVAILABLE", grupo.at("/components/trustStoreCache/details/status").asText());

        assertEquals(HttpStatus.OK, http.getForEntity("/actuator/health/liveness", String.class).getStatusCode());
    }

    @SneakyThrows
    @Test
    @Order(2)
    void testAposCarga_ServePemEDerSemCacheHttp_ReadinessUp() {
        when(downloader.downloadText(config.getHashUrl())).thenReturn(hash + "  ACcompactado.zip\n");
        when(downloader.downloadBytes(config.getCertificateUrl())).thenReturn(zip);
        service.refresh();
        assertTrue(service.isCacheValid(), "pré-condição: acervo publicado");

        ResponseEntity<String> pem = http.getForEntity("/certificate?ski=" + ski(root) + "&type=pem", String.class);
        assertEquals(HttpStatus.OK, pem.getStatusCode());
        assertNotNull(pem.getBody());
        assertTrue(pem.getBody().startsWith("-----BEGIN CERTIFICATE-----"));
        assertEquals("no-store", pem.getHeaders().getCacheControl());

        ResponseEntity<byte[]> der = http.getForEntity("/certificate?ski=" + ski(root) + "&type=der", byte[].class);
        assertEquals(HttpStatus.OK, der.getStatusCode());
        assertNotNull(der.getHeaders().getContentType());
        assertEquals("application/x-x509-ca-cert", der.getHeaders().getContentType().toString());
        assertArrayEquals(root.getEncoded(), der.getBody());
        assertEquals("no-store", der.getHeaders().getCacheControl());

        ResponseEntity<String> inexistente = http.getForEntity("/certificate?ski=" + "0".repeat(40), String.class);
        assertEquals(HttpStatus.NOT_FOUND, inexistente.getStatusCode());
        assertEquals("no-store", inexistente.getHeaders().getCacheControl());

        ResponseEntity<String> readiness = http.getForEntity("/actuator/health/readiness", String.class);
        assertEquals(HttpStatus.OK, readiness.getStatusCode());
        assertEquals("VALID", json(readiness).at("/components/trustStoreCache/details/status").asText());
    }

    @SneakyThrows
    private static JsonNode json(ResponseEntity<String> resposta) {
        assertNotNull(resposta.getBody());
        return new ObjectMapper().readTree(resposta.getBody());
    }

    private static String ski(X509Certificate certificate) {
        return CertificateParser.getSubjectKeyIdentifier(certificate);
    }
}
