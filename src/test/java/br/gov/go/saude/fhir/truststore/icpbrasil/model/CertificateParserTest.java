package br.gov.go.saude.fhir.truststore.icpbrasil.model;

import br.gov.go.saude.fhir.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CertificateParserTest {
    X509Certificate certificate;

    X509Certificate authorityCertificate;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        this.certificate = CertificateParser.parse(TestResourceLoader.getResource("DANIEL_NOGUEIRA_DA_COSTA-02057377148.cer"));
        this.authorityCertificate = CertificateParser.parse(TestResourceLoader.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testGetSubjectCommonName() {
        assertEquals("DANIEL NOGUEIRA DA COSTA:02057377148", CertificateParser.getSubjectCommonName(certificate));
    }

    @Test
    void testGetIssuerCommonName() {
        assertEquals("AC SOLUTI Multipla v5 G2", CertificateParser.getIssuerCommonName(certificate));
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
        assertEquals("6cc3193238e71499dfa2e40708a68f9c7ed09647", CertificateParser.getSubjectKeyIdentifier(certificate));
    }

    @Test
    void testGetAuthorityKeyIdentifier() {
        assertEquals("962738fb529fa23d34d35dc82bf741ad825eb08f", CertificateParser.getAuthorityKeyIdentifier(certificate));
    }


    @Test
    void testAuthorityKeyIdentifier() {
        assertEquals(
                CertificateParser.getAuthorityKeyIdentifier(certificate),
                CertificateParser.getSubjectKeyIdentifier(authorityCertificate)
        );
    }

    @Test
    void testSubjectAlternativeNames() {
        GeneralNames generalNames = CertificateParser.getSubjectAlternativeNames(certificate);

        assertEquals(4, generalNames.getNames().length);
    }

    @Test
    void testGetCrlDistributionPoints() {
        DistributionPoint[] crlDistributionPoints = CertificateParser.getCrlDistributionPoints(certificate);
        assertEquals(2, crlDistributionPoints.length);
    }

    @Test
    void testAuthorityInformationAccess() {

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
        assertTrue(crlUrls.get(0).contains("http://ccd.acsoluti.com.br/lcr/ac-soluti-multipla-v5-g2.crl"));
        assertTrue(crlUrls.get(1).contains("http://ccd2.acsoluti.com.br/lcr/ac-soluti-multipla-v5-g2.crl"));
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
    void testGetOcspUrlsCertificadoSemOcsp() {
        // Certificados ICP-Brasil Soluti não possuem OCSP na AIA
        List<String> ocspUrls = CertificateParser.getOcspUrls(certificate);

        assertNotNull(ocspUrls);
        assertTrue(ocspUrls.isEmpty());
    }
}
