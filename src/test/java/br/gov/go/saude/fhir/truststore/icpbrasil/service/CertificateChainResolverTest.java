package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.fhir.truststore.icpbrasil.util.Downloader;
import br.gov.go.saude.fhir.truststore.icpbrasil.util.Util;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@SpringBootTest
class CertificateChainResolverTest {
    @Autowired
    TrustStoreConfig trustStoreConfig;

    @MockitoBean
    Downloader downloader;

    @Autowired
    Util util;

    @Autowired
    TrustStoreRepository trustStoreRepository;

    @Autowired
    CertificateChainResolver certificateChainResolver;

    X509Certificate leafCertificate;
    X509Certificate intermediaryCertificate;

    @SneakyThrows
    @BeforeEach
    void setUp() {
        byte[] zipBytes = util.getResource("ACcompactado.zip").readAllBytes();
        String hashContent = new String(util.getResource("hashsha512.txt").readAllBytes());

        when(downloader.downloadBytes(trustStoreConfig.getCertificateUrl())).thenReturn(zipBytes);
        when(downloader.downloadText(trustStoreConfig.getHashUrl())).thenReturn(hashContent);

        var icpBrasilCertificateProvider = new IcpBrasilCertificateProvider(
                trustStoreConfig,
                downloader,
                trustStoreRepository
        );
        Cache.setCacheValid(true);
        Cache.refreshCache(icpBrasilCertificateProvider.getCertificates());

        leafCertificate = CertificateParser.parse(util.getResource("DANIEL_NOGUEIRA_DA_COSTA-02057377148.cer"));
        intermediaryCertificate = CertificateParser.parse(util.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));
    }

    @Test
    void testResolverCadeiaComLeaf() {
        List<X509Certificate> chain = certificateChainResolver.resolver(leafCertificate);

        assertFalse(chain.isEmpty());
        assertEquals(leafCertificate, chain.getFirst());
        assertTrue(chain.size() >= 3, "Cadeia do leaf deve conter ao menos leaf, intermediário e raiz");

        assertEquals(intermediaryCertificate, chain.get(1));

        X509Certificate root = chain.getLast();
        assertEquals(root.getSubjectX500Principal(), root.getIssuerX500Principal());
        assertDoesNotThrow(() -> root.verify(root.getPublicKey()));
    }

    @Test
    void testResolverCadeiaAkiSkiRelacionamento() {
        List<X509Certificate> chain = certificateChainResolver.resolver(leafCertificate);

        for (int i = 0; i < chain.size() - 1; i++) {
            String aki = CertificateParser.getAuthorityKeyIdentifier(chain.get(i));
            String issuerSki = CertificateParser.getSubjectKeyIdentifier(chain.get(i + 1));
            assertEquals(aki, issuerSki,
                    "AKI do certificado [%d] deve ser igual ao SKI do certificado [%d]".formatted(i, i + 1));
        }
    }

    @Test
    void testResolverCadeiaParaCertificadoRaiz() {
        Map<String, X509Certificate> roots = Cache.getRootCertificates();
        X509Certificate rootCert = roots.values().iterator().next();

        List<X509Certificate> chain = certificateChainResolver.resolver(rootCert);

        assertEquals(1, chain.size());
        assertEquals(rootCert, chain.getFirst());
    }

    @Test
    void testResolverCadeiaSemDuplicatas() {
        List<X509Certificate> chain = certificateChainResolver.resolver(leafCertificate);

        long distinctCount = chain.stream()
                .map(CertificateParser::getSubjectKeyIdentifier)
                .distinct()
                .count();
        assertEquals(chain.size(), distinctCount, "A cadeia não deve conter certificados duplicados");
    }
}
