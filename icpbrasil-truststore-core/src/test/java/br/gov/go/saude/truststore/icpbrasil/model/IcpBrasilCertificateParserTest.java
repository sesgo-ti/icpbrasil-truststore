package br.gov.go.saude.truststore.icpbrasil.model;

import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IcpBrasilCertificateParserTest {
    static X509Certificate certificate;

    @SneakyThrows
    @BeforeAll
    static void generateSyntheticCert() {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        var caKeyPair = kpg.generateKeyPair();
        var leafKeyPair = kpg.generateKeyPair();
        X509Certificate testCa = TestCertificateFactory.generateIcpBrasilTestCa(caKeyPair);
        certificate = TestCertificateFactory.generateIcpBrasilPersonCert(leafKeyPair, caKeyPair, testCa);
    }

    @Test
    void testGetCpf() {
        assertEquals(TestCertificateFactory.CPF_TESTE, IcpBrasilCertificateParser.getCpf(certificate));
    }

    @Test
    void testGetDataNascimento() {
        assertEquals("1990-01-01", IcpBrasilCertificateParser.getDataNascimento(certificate).toString());
    }
}
