package br.gov.go.saude.truststore.icpbrasil.service.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Registro de produção {@code src/main/resources/registries/certificates}: âncoras do
 * {@code SSLContext} dedicado ao download do acervo do ITI.
 *
 * <p>{@code acraiz.icpbrasil.gov.br} não envia a intermediária no handshake TLS; como o JDK não
 * busca emissores via AIA, a intermediária que emitiu o certificado do servidor precisa constar
 * do registro. O teste de cadeia usa um snapshot do certificado do ITI e data fixa, sem rede.
 */
class EmbeddedTrustedCertsTest {

    private static final Path REGISTRY = Path.of("src/main/resources/registries/certificates");
    private static final String ITI_TLS_SNAPSHOT = "tls/acraiz-icpbrasil-gov-br-2026-07-21.crt";
    private static final Date ITI_SNAPSHOT_VALID_AT = Date.from(Instant.parse("2026-09-29T00:00:00Z"));

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static List<JsonNode> documents;
    private static List<X509Certificate> certificates;

    @BeforeAll
    static void carregarRegistro() throws IOException {
        documents = new ArrayList<>();
        try (Stream<Path> files = Files.list(REGISTRY)) {
            for (Path file : files.filter(f -> f.toString().endsWith(".json")).sorted().toList()) {
                documents.add(MAPPER.readTree(file.toFile()));
            }
        }
        List<byte[]> raw = new ArrayList<>();
        for (JsonNode document : documents) {
            raw.add(MAPPER.writeValueAsBytes(document));
        }
        certificates = new TrustedCertsProvider(raw).getCertificates();
    }

    @Test
    void testRegistro_ContemCertificados_TodosCarregados() {
        assertFalse(documents.isEmpty());
        assertEquals(documents.size(), certificates.size());
    }

    @Test
    void testRegistro_MetadadosDeclarados_CorrespondemAoCertificado() throws Exception {
        for (int i = 0; i < documents.size(); i++) {
            JsonNode document = documents.get(i);
            X509Certificate certificate = certificates.get(i);
            String fingerprint = HexFormat.ofDelimiter(":").withUpperCase()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));

            assertEquals(document.get("fingerprintSha256").asText(), fingerprint);
            assertEquals(Instant.parse(document.get("notBefore").asText()), certificate.getNotBefore().toInstant());
            assertEquals(Instant.parse(document.get("notAfter").asText()), certificate.getNotAfter().toInstant());
            assertTrue(certificate.getSubjectX500Principal().getName().contains("CN=" + document.get("subject").asText()));
            assertTrue(certificate.getIssuerX500Principal().getName().contains("CN=" + document.get("issuer").asText()));
        }
    }

    @Test
    void testRegistro_Certificados_SaoSomenteIntermediariasGenYDaLetsEncrypt() {
        Set<String> issuers = Set.of("Root YE", "Root YR");
        for (X509Certificate certificate : certificates) {
            String issuer = certificate.getIssuerX500Principal().getName();
            assertTrue(certificate.getSubjectX500Principal().getName().contains("O=Let's Encrypt"));
            assertTrue(issuers.stream().anyMatch(cn -> issuer.contains("CN=" + cn)));
            // Intermediária que só emite certificados finais: cA=true e pathLenConstraint=0
            assertEquals(0, certificate.getBasicConstraints());
        }
    }

    @Test
    void testRegistro_CertificadoTlsAtualDoIti_ValidaSemIntermediariaDoServidor() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate itiTls;
        try (InputStream in = EmbeddedTrustedCertsTest.class.getClassLoader().getResourceAsStream(ITI_TLS_SNAPSHOT)) {
            itiTls = (X509Certificate) factory.generateCertificate(in);
        }
        // Mesmo modelo do TrustManager do SSLContext interno: toda entrada do registro é âncora
        Set<TrustAnchor> anchors = certificates.stream()
                .map(certificate -> new TrustAnchor(certificate, null))
                .collect(Collectors.toSet());
        PKIXParameters parameters = new PKIXParameters(anchors);
        parameters.setRevocationEnabled(false);
        parameters.setDate(ITI_SNAPSHOT_VALID_AT);
        CertPath path = factory.generateCertPath(List.of(itiTls));

        CertPathValidator.getInstance("PKIX").validate(path, parameters);
    }
}
