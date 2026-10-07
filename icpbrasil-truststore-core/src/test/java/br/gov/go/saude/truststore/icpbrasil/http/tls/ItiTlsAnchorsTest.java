package br.gov.go.saude.truststore.icpbrasil.http.tls;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ItiTlsAnchorsTest {

    @Test
    void testLoad_RecursosDeProducao_CarregaAsDuasRaizesIsrg() {
        List<X509Certificate> anchors = ItiTlsAnchors.load();

        assertEquals(Set.of("CN=ISRG Root X1,O=Internet Security Research Group,C=US",
                        "CN=ISRG Root X2,O=Internet Security Research Group,C=US"),
                anchors.stream().map(a -> a.getSubjectX500Principal().getName()).collect(Collectors.toSet()));
    }

    @Test
    void testLoad_FingerprintDivergente_LancaIllegalStateException() {
        Map<String, String> esperado = Map.of("tls/iti/isrg-root-x1.pem", "00".repeat(32));

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> ItiTlsAnchors.load(esperado, ItiTlsAnchors.class.getClassLoader()));
        assertTrue(e.getMessage().contains("isrg-root-x1.pem"), e.getMessage());
    }

    @Test
    void testLoad_RecursoAusente_LancaIllegalStateException() {
        assertThrows(IllegalStateException.class,
                () -> ItiTlsAnchors.load(Map.of("tls/iti/inexistente.pem", "00"), ItiTlsAnchors.class.getClassLoader()));
    }
}
