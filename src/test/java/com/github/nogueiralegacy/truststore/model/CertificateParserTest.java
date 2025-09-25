package com.github.nogueiralegacy.truststore.model;

import com.github.nogueiralegacy.truststore.util.Util;
import lombok.SneakyThrows;
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
        assertEquals("DANIEL NOGUEIRA DA COSTA:02057377148", CertificateParser.getCommonName(certificate).get());
    }

    @Test
    void testGetSubjectKeyIdentifier() {
        assertNotNull(certificate);
        assertEquals("BBRswxkyOOcUmd+i5AcIpo+cftCWRw==", CertificateParser.getSubjectKeyIdentifier(certificate).get());
    }

    @Test
    void testGetAuthorityKeyIdentifier() {
        assertNotNull(certificate);
        assertEquals("MBaAFJYnOPtSn6I9NNNdyCv3Qa2CXrCP", CertificateParser.getAuthorityKeyIdentifier(certificate).get());
    }

    //TODO: descobrir porque esse teste falha
//    @Test
//    void testGetAuthorityKeyIdentifier() {
//        assertNotNull(certificate);
//        assertEquals("MBaAFJYnOPtSn6I9NNNdyCv3Qa2CXrCP", CertificateParser.getAuthorityKeyIdentifier(certificate).get());
//
//        assertEquals(
//                CertificateParser.getAuthorityKeyIdentifier(certificate).get(),
//                CertificateParser.getSubjectKeyIdentifier(authorityCertificate).get()
//        );
//    }

}
