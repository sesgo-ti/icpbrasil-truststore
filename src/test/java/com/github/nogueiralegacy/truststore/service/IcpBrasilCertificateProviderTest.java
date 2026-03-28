package com.github.nogueiralegacy.truststore.service;

import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import com.github.nogueiralegacy.truststore.model.CertificateParser;
import com.github.nogueiralegacy.truststore.repository.TrustStoreRepository;
import com.github.nogueiralegacy.truststore.util.Downloader;
import com.github.nogueiralegacy.truststore.util.Util;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.Mockito.when;

@Slf4j
@SpringBootTest
@ActiveProfiles("test")
public class IcpBrasilCertificateProviderTest {

    private IcpBrasilCertificateProvider icpBrasilCertificateProvider;

    @Autowired
    TrustStoreConfig trustStoreConfig;

    @Autowired
    Util util;

    @Autowired
    TrustStoreRepository trustStoreRepository;

    @MockitoBean
    Downloader downloader;

    X509Certificate testCertificate;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        // Configurar o mock do downloader para retornar os recursos locais
        byte[] zipBytes = util.getResource("ACcompactado.zip").readAllBytes();
        String hashContent = new String(util.getResource("hashsha512.txt").readAllBytes());
        
        when(downloader.downloadBytes(trustStoreConfig.getCertificateUrl())).thenReturn(zipBytes);
        when(downloader.downloadText(trustStoreConfig.getHashUrl())).thenReturn(hashContent);
        
        icpBrasilCertificateProvider = new IcpBrasilCertificateProvider(
                trustStoreConfig,
                downloader,
                trustStoreRepository
        );

        testCertificate = CertificateParser.parse(util.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testGetCertificates() {
        List<X509Certificate> certificates = icpBrasilCertificateProvider.getCertificates();

        assertThat(certificates).isNotEmpty();
        assertThat(certificates).contains(testCertificate);
    }
}
