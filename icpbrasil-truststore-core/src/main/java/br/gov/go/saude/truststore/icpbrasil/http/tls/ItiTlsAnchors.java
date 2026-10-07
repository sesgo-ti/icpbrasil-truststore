package br.gov.go.saude.truststore.icpbrasil.http.tls;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Âncoras do TLS do download do acervo: as raízes ISRG embutidas na biblioteca.
 *
 * <p>O fingerprint de cada PEM é fixado no código; um recurso trocado no classpath (outro JAR
 * com o mesmo caminho) não bate com a constante e impede a inicialização. Trocar âncoras exige
 * release.</p>
 */
public final class ItiTlsAnchors {

    /** Caminho do recurso no classpath mapeado para o SHA-256 esperado (hex minúsculo, sem separadores). */
    public static final Map<String, String> FINGERPRINTS = Map.of(
            "tls/iti/isrg-root-x1.pem", "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
            "tls/iti/isrg-root-x2.pem", "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470");

    private ItiTlsAnchors() {
    }

    /**
     * Carrega as raízes embutidas, na ordem do caminho do recurso.
     *
     * @return lista imutável de certificados
     * @throws IllegalStateException se algum recurso estiver ausente, ilegível ou com fingerprint divergente
     */
    public static List<X509Certificate> load() {
        return load(FINGERPRINTS, ItiTlsAnchors.class.getClassLoader());
    }

    static List<X509Certificate> load(Map<String, String> expected, ClassLoader loader) {
        List<X509Certificate> anchors = new ArrayList<>();
        for (Map.Entry<String, String> entry : new TreeMap<>(expected).entrySet()) {
            try (InputStream in = loader.getResourceAsStream(entry.getKey())) {
                if (in == null) {
                    throw new IllegalStateException("Âncora TLS ausente: " + entry.getKey());
                }
                X509Certificate certificate = CertificateParser.parse(in);
                String actual = CertificateParser.getFingerprintSha256(certificate);
                if (!actual.equals(entry.getValue())) {
                    throw new IllegalStateException("Âncora TLS " + entry.getKey()
                            + " com fingerprint divergente: " + actual);
                }
                anchors.add(certificate);
            } catch (IOException | CertificateParsingException e) {
                throw new IllegalStateException("Âncora TLS ilegível: " + entry.getKey(), e);
            }
        }
        return List.copyOf(anchors);
    }
}
