package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Âncoras do SSLContext dedicado ao download: o alias do KeyStore deriva do fingerprint do
 * certificado, então nomes repetidos, truncados ou ausentes não sobrescrevem âncoras.
 */
class TrustStoreManagerTest {

    private static Set<X509Certificate> anchors(List<X509Certificate> certificates) {
        return Set.of(new TrustStoreManager(() -> certificates).getAcceptedIssuers());
    }

    @Test
    void testAncoras_MesmoCnComChavesDiferentes_Coexistem() {
        X509Certificate first = TestBundleFactory.caCert("YE1", TestBundleFactory.newKeyPair());
        X509Certificate second = TestBundleFactory.caCert("YE1", TestBundleFactory.newKeyPair());

        assertEquals(Set.of(first, second), anchors(List.of(first, second)));
    }

    @Test
    void testAncoras_CnsQueColidemAposSanitizacaoETruncamento_Coexistem() {
        String prefix = "A".repeat(50);
        X509Certificate first = TestBundleFactory.caCert(prefix + " um", TestBundleFactory.newKeyPair());
        X509Certificate second = TestBundleFactory.caCert(prefix + " dois", TestBundleFactory.newKeyPair());

        assertEquals(Set.of(first, second), anchors(List.of(first, second)));
    }

    @Test
    void testAncoras_CertificadoSemCn_ECarregado() {
        KeyPair keyPair = TestBundleFactory.newKeyPair();
        X500Name subject = new X500Name("O=Sem CN, C=BR");
        X509v3CertificateBuilder builder = TestCertificateFactory.createBuilder(subject, subject, 77, keyPair);
        TestCertificateFactory.addSki(builder, keyPair);
        addCa(builder);
        X509Certificate withoutCn = TestCertificateFactory.sign(builder, keyPair);

        assertEquals(Set.of(withoutCn), anchors(List.of(withoutCn)));
    }

    @Test
    void testAncoras_DuplicataIdentica_CarregadaUmaVez() {
        X509Certificate certificate = TestBundleFactory.caCert("YR1", TestBundleFactory.newKeyPair());

        X509Certificate[] accepted = new TrustStoreManager(() -> List.of(certificate, certificate)).getAcceptedIssuers();

        assertEquals(1, accepted.length);
    }

    @Test
    void testAlias_DerivadoDoFingerprintSha256() {
        X509Certificate certificate = TestBundleFactory.caCert("YE2", TestBundleFactory.newKeyPair());

        String alias = TrustStoreManager.aliasOf(certificate);

        assertTrue(alias.matches("sha256-[0-9a-f]{64}"));
        assertEquals(alias, TrustStoreManager.aliasOf(certificate));
    }

    private static void addCa(X509v3CertificateBuilder builder) {
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
