package br.gov.go.saude.fhir.truststore.icpbrasil.model;

import br.gov.go.saude.fhir.truststore.icpbrasil.util.Util;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class CertificateParserTest {
    X509Certificate certificate;

    X509Certificate authorityCertificate;

    @Autowired
    Util util;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        this.certificate = CertificateParser.parse(util.getResource("DANIEL_NOGUEIRA_DA_COSTA-02057377148.cer"));
        this.authorityCertificate = CertificateParser.parse(util.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
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
}
