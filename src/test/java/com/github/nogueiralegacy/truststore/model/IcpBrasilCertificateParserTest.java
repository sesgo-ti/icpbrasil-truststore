package com.github.nogueiralegacy.truststore.model;

import com.github.nogueiralegacy.truststore.util.Util;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@ActiveProfiles("test")
public class IcpBrasilCertificateParserTest {
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
    void testGetCpf() {
        assertEquals("02057377148", IcpBrasilCertificateParser.getCpf(certificate));
    }

    @Test
    void testGetDataNascimento() {
        assertEquals("2002-12-24", IcpBrasilCertificateParser.getDataNascimento(certificate).toString());
    }
}
