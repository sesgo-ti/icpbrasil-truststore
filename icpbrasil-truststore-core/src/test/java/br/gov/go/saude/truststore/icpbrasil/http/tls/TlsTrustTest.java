package br.gov.go.saude.truststore.icpbrasil.http.tls;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsTrustTest {

    @Test
    void testDedicatedCa_CertificadosComMesmoCn_MantemTodasAsAncoras() {
        X509Certificate a = TestBundleFactory.caCert("Mesmo CN", TestBundleFactory.newKeyPair());
        X509Certificate b = TestBundleFactory.caCert("Mesmo CN", TestBundleFactory.newKeyPair());

        TlsTrust trust = TlsTrust.dedicatedCa(List.of(a, b));

        assertEquals(2, trust.trustManager().getAcceptedIssuers().length);
    }

    @Test
    void testDedicatedCa_DuplicataIdentica_EntraUmaVez() {
        X509Certificate a = TestBundleFactory.caCert("Raiz", TestBundleFactory.newKeyPair());

        assertEquals(1, TlsTrust.dedicatedCa(List.of(a, a)).trustManager().getAcceptedIssuers().length);
    }

    @Test
    void testDedicatedCa_SemCertificados_LancaIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> TlsTrust.dedicatedCa(List.of()));
    }

    @Test
    void testDescribe_DedicatedCa_ListaSubjectEFingerprint() {
        X509Certificate a = TestBundleFactory.caCert("Raiz Descrita", TestBundleFactory.newKeyPair());

        String descricao = TlsTrust.dedicatedCa(List.of(a)).describe();

        assertTrue(descricao.contains("CN=Raiz Descrita"), descricao);
        assertTrue(descricao.contains(CertificateParser.getFingerprintSha256(a)), descricao);
    }

    @Test
    void testDescribe_JvmDefault_IndicaCacerts() {
        assertEquals("cacerts da JVM", TlsTrust.jvmDefault().describe());
    }
}
