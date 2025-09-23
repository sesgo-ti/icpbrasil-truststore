package com.github.nogueiralegacy.truststore.model;

import com.github.nogueiralegacy.truststore.config.LetsEncryptProperties;
import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import com.github.nogueiralegacy.truststore.util.Downloader;
import com.github.nogueiralegacy.truststore.util.Util;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

@Slf4j
@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.yaml")
public class IcpBrasilCertificateProviderTest {

    private IcpBrasilCertificateProvider icpBrasilCertificateProvider;

    @Autowired
    TrustStoreConfig trustStoreConfig;

    @Autowired
    Util util;

    X509Certificate testCertificate;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        icpBrasilCertificateProvider = new IcpBrasilCertificateProvider(
                trustStoreConfig,
                new DownloaderTest(trustStoreConfig, new LetsEncryptProperties()));

        testCertificate = CertificateParser.parse(util.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testGetCertificates() {
        List<X509Certificate> certificates = icpBrasilCertificateProvider.getCertificates();

        assertThat(certificates).isNotEmpty();
        assertThat(certificates).hasSize(159);
        assertThat(certificates).contains(testCertificate);
    }

    class DownloaderTest extends Downloader {

        public DownloaderTest(TrustStoreConfig trustStoreConfig, LetsEncryptProperties letsEncryptProperties) {
            super(trustStoreConfig, letsEncryptProperties);
        }

        @SneakyThrows
        @Override
        public byte[] downloadBytes(String url) {
            String zipName = "ACcompactado.zip";

            return util.getResource(zipName).readAllBytes();
        }

        @SneakyThrows
        @Override
        public String downloadText(String url) {
            String hashName = "hashsha512.txt";

            return new String(util.getResource(hashName).readAllBytes());
        }
    }
}
