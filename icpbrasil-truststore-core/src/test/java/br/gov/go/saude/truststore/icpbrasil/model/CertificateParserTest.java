package br.gov.go.saude.truststore.icpbrasil.model;

import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CertificateParserTest {
    static X509Certificate certificate;
    static X509Certificate testCa;

    X509Certificate authorityCertificate;

    @SneakyThrows
    @BeforeAll
    static void generateSyntheticPair() {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        var caKeyPair = kpg.generateKeyPair();
        var leafKeyPair = kpg.generateKeyPair();
        testCa = TestCertificateFactory.generateIcpBrasilTestCa(caKeyPair);
        certificate = TestCertificateFactory.generateIcpBrasilPersonCert(leafKeyPair, caKeyPair, testCa);
    }

    @SneakyThrows
    @BeforeEach
    void setUp() {
        this.authorityCertificate = CertificateParser.parse(TestResourceLoader.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testGetSubjectCommonName() {
        assertEquals(TestCertificateFactory.CN_TITULAR_TESTE, CertificateParser.getSubjectCommonName(certificate));
    }

    @Test
    void testGetIssuerCommonName() {
        assertEquals(TestCertificateFactory.CN_AC_TESTE, CertificateParser.getIssuerCommonName(certificate));
    }

    @Test
    void testGetSubjectOrganization() {
        assertEquals("ICP-Brasil", CertificateParser.getSubjectOrganization(certificate));
    }

    @Test
    void testGetIssuerOrganization() {
        assertEquals("ICP-Brasil", CertificateParser.getIssuerOrganization(certificate));
    }

    @Test
    void testGetSubjectCountry() {
        assertEquals("BR", CertificateParser.getSubjectCountry(certificate));
    }

    @Test
    void testGetIssuerCountry() {
        assertEquals("BR", CertificateParser.getIssuerCountry(certificate));
    }

    @Test
    void testGetSubjectKeyIdentifier() {
        assertNotNull(CertificateParser.getSubjectKeyIdentifier(certificate));
        assertEquals(40, CertificateParser.getSubjectKeyIdentifier(certificate).length()); // SHA-1 em hex
    }

    @Test
    void testAuthorityKeyIdentifierCorrespondeAoSkiDoEmissor() {
        assertEquals(
                CertificateParser.getSubjectKeyIdentifier(testCa),
                CertificateParser.getAuthorityKeyIdentifier(certificate)
        );
    }

    @Test
    void testSubjectAlternativeNamesDeveConterQuatroEntradas() {
        GeneralNames generalNames = CertificateParser.getSubjectAlternativeNames(certificate);

        assertEquals(4, generalNames.getNames().length);
    }

    @Test
    void testGetCrlDistributionPoints() {
        DistributionPoint[] crlDistributionPoints = CertificateParser.getCrlDistributionPoints(certificate);
        assertEquals(2, crlDistributionPoints.length);
    }

    @Test
    void testAuthorityInformationAccessDeveConterUmaDescricao() {

        AccessDescription[] accessDescriptions = CertificateParser.getCertificateAuthorityInformationAccess(certificate);

        assertEquals(1, accessDescriptions.length);
    }

    @SneakyThrows
    @Test
    void testParseBase64() {
        byte[] derBytes = certificate.getEncoded();
        String base64 = Base64.getEncoder().encodeToString(derBytes);

        X509Certificate parsed = CertificateParser.parseBase64(base64);

        assertEquals(certificate, parsed);
    }

    @Test
    void testParseBase64InvalidThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> CertificateParser.parseBase64("!!!not-base64!!!"));
    }

    @Test
    void testParseBase64NullThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> CertificateParser.parseBase64(null));
    }

    @Test
    void testGetCertificatePolicies() {
        List<String> policies = CertificateParser.getCertificatePolicies(certificate);

        assertFalse(policies.isEmpty());
        assertTrue(policies.stream().anyMatch(oid -> oid.startsWith("2.16.76.1")));
    }

    @Test
    void testGetKeyUsage() {
        boolean[] keyUsage = CertificateParser.getKeyUsage(certificate);

        assertNotNull(keyUsage);
        assertEquals(9, keyUsage.length);
        assertTrue(keyUsage[0]); // digitalSignature
        assertTrue(keyUsage[1]); // nonRepudiation
    }

    @Test
    void testGetCrlUrls() {
        List<String> crlUrls = CertificateParser.getCrlUrls(certificate);

        assertNotNull(crlUrls);
        assertEquals(2, crlUrls.size());
        assertTrue(crlUrls.get(0).contains("http://crl.teste.example/ac-teste-1.crl"));
        assertTrue(crlUrls.get(1).contains("http://crl2.teste.example/ac-teste-2.crl"));
    }

    @Test
    void testGetCrlUrlsCertificadoIntermediario() {
        List<String> crlUrls = CertificateParser.getCrlUrls(authorityCertificate);

        assertNotNull(crlUrls);
        assertEquals(2, crlUrls.size());
        assertTrue(crlUrls.get(0).contains("http://ccd.acsoluti.com.br/lcr/ac-soluti-v5-g2.crl"));
        assertTrue(crlUrls.get(1).contains("http://ccd2.acsoluti.com.br/lcr/ac-soluti-v5-g2.crl"));
    }

    @Test
    void testGetCrlDistributionPointDaUrlDoSegundoDp() {
        Optional<DistributionPoint> dp = CertificateParser.getCrlDistributionPoint(
                certificate, "http://crl2.teste.example/ac-teste-2.crl");

        assertTrue(dp.isPresent());
        assertEquals(CertificateParser.getCrlDistributionPoints(certificate)[1], dp.get());
    }

    @Test
    void testGetCrlDistributionPointUrlAusenteRetornaVazio() {
        Optional<DistributionPoint> dp = CertificateParser.getCrlDistributionPoint(
                certificate, "http://crl3.teste.example/ac-teste-3.crl");

        assertTrue(dp.isEmpty());
    }

    @Test
    void testGetCrlDistributionPointCertificadoSemExtensaoRetornaVazio() {
        Optional<DistributionPoint> dp = CertificateParser.getCrlDistributionPoint(
                testCa, "http://crl.teste.example/ac-teste-1.crl");

        assertTrue(dp.isEmpty());
    }

    @Test
    void testGetOcspUrlsCertificadoSemOcsp() {
        // Reproduz certificados ICP-Brasil (ex.: Soluti) que não possuem OCSP na AIA
        List<String> ocspUrls = CertificateParser.getOcspUrls(certificate);

        assertNotNull(ocspUrls);
        assertTrue(ocspUrls.isEmpty());
    }
}
