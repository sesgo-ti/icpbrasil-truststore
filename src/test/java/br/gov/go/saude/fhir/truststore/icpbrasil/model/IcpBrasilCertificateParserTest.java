package br.gov.go.saude.fhir.truststore.icpbrasil.model;

import br.gov.go.saude.fhir.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class IcpBrasilCertificateParserTest {
    X509Certificate certificate;

    X509Certificate authorityCertificate;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        this.certificate = CertificateParser.parse(TestResourceLoader.getResource("DANIEL_NOGUEIRA_DA_COSTA-02057377148.cer"));
        this.authorityCertificate = CertificateParser.parse(TestResourceLoader.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testGetCpf() {
        assertEquals("02057377148", IcpBrasilCertificateParser.getCpf(certificate));
    }

    @Test
    void testGetDataNascimento() {
        assertEquals("2002-12-24", IcpBrasilCertificateParser.getDataNascimento(certificate).toString());
    }
}
