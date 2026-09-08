package br.gov.go.saude.truststore.icpbrasil.service.provider;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustedCertsProviderTest {

    private static final Path CERTS_DIR =
            Path.of("src/test/resources/registries/certificates");

    @SneakyThrows
    @Test
    void testGetCertificates_DocumentosValidos_RetornaCertificados() {
        List<byte[]> docs = List.of(
                Files.readAllBytes(CERTS_DIR.resolve("isrgrootx1.json")),
                Files.readAllBytes(CERTS_DIR.resolve("isrgrootx2.json")),
                Files.readAllBytes(CERTS_DIR.resolve("letsencrypt_e7.json"))
        );

        TrustedCertsProvider provider = new TrustedCertsProvider(docs);
        List<X509Certificate> certificates = provider.getCertificates();

        assertFalse(certificates.isEmpty());
        assertEquals(3, certificates.size());
        assertTrue(certificates.get(0).getSubjectX500Principal().getName().contains("ISRG Root X1"));
    }

    @Test
    void testGetCertificates_ListaVazia_RetornaVazio() {
        TrustedCertsProvider provider = new TrustedCertsProvider(List.of());
        List<X509Certificate> certificates = provider.getCertificates();

        assertTrue(certificates.isEmpty());
    }

    @SneakyThrows
    @Test
    void testGetCertificates_DocumentoSemCampoPem_Ignorado() {
        byte[] semPem = "{\"sourceUrl\":\"http://example.com\",\"format\":\"pem\"}".getBytes();

        TrustedCertsProvider provider = new TrustedCertsProvider(List.of(semPem));
        List<X509Certificate> certificates = provider.getCertificates();

        assertTrue(certificates.isEmpty());
    }
}
