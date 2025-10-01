package com.github.nogueiralegacy.truststore.model;

import com.github.nogueiralegacy.truststore.util.Util;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.yaml")
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

    @SneakyThrows
    @Test
    void testParse() {
        assertNotNull(certificate);
        assertEquals("DANIEL NOGUEIRA DA COSTA:02057377148", CertificateParser.getSubjectCommonName(certificate));
    }

    @Test
    void testGetSubjectKeyIdentifier() {
        assertNotNull(certificate);
        assertEquals("6cc3193238e71499dfa2e40708a68f9c7ed09647", CertificateParser.getSubjectKeyIdentifier(certificate));
    }

    @Test
    void testGetAuthorityKeyIdentifier() {
        assertNotNull(certificate);
        assertEquals("962738fb529fa23d34d35dc82bf741ad825eb08f", CertificateParser.getAuthorityKeyIdentifier(certificate));
    }


    @Test
    void testAuthorityKeyIdentifier() {
        assertNotNull(certificate);

        assertEquals(
                CertificateParser.getAuthorityKeyIdentifier(certificate),
                CertificateParser.getSubjectKeyIdentifier(authorityCertificate)
        );
    }

    @Test
    void testSubjectAlternativeNames() {
        GeneralNames generalNames = CertificateParser.getSubjectAlternativeNames(certificate);

        assertEquals(4, generalNames.getNames().length);
        assertEquals("daniel.nogueira.dacosta@gmail.com", generalNames.getNames()[0].getName().toString());
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
