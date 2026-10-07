package br.gov.go.saude.truststore.icpbrasil.http.tls;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Ponto único de construção da confiança TLS de um canal de saída da biblioteca.
 *
 * <p>Cada canal recebe o próprio {@link SSLContext}; nada é instalado como padrão da JVM.</p>
 */
public sealed interface TlsTrust permits TlsTrust.JvmDefault, TlsTrust.DedicatedCa {

    /** Confiança nos certificados raiz padrão da JVM (cacerts). */
    static TlsTrust jvmDefault() {
        return new JvmDefault();
    }

    /**
     * Confia somente nos certificados informados, todos como âncoras. Certificados idênticos entram uma vez.
     *
     * @throws IllegalArgumentException se {@code anchors} for vazio
     */
    static TlsTrust dedicatedCa(Collection<X509Certificate> anchors) {
        return new DedicatedCa(List.copyOf(new LinkedHashSet<>(anchors)));
    }

    X509TrustManager trustManager();

    /** Âncoras da confiança dedicada; vazio para {@link JvmDefault}. */
    List<X509Certificate> anchors();

    /** Texto para log: em quem o canal confia, com fingerprint SHA-256 de cada âncora. */
    String describe();

    /** Novo {@link SSLContext} TLS que usa apenas o {@link #trustManager()} desta confiança. */
    default SSLContext sslContext() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{trustManager()}, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Falha ao criar SSLContext", e);
        }
    }

    record JvmDefault() implements TlsTrust {
        @Override
        public X509TrustManager trustManager() {
            return fromKeyStore(null);
        }

        @Override
        public List<X509Certificate> anchors() {
            return List.of();
        }

        @Override
        public String describe() {
            return "cacerts da JVM";
        }
    }

    record DedicatedCa(List<X509Certificate> anchors) implements TlsTrust {
        public DedicatedCa {
            if (anchors.isEmpty()) {
                throw new IllegalArgumentException("Confiança dedicada exige ao menos uma âncora");
            }
        }

        @Override
        public X509TrustManager trustManager() {
            try {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                for (X509Certificate anchor : anchors) {
                    // O alias é só rótulo do KeyStore: o fingerprint evita que certificados de mesmo CN se sobrescrevam.
                    keyStore.setCertificateEntry("sha256-" + CertificateParser.getFingerprintSha256(anchor), anchor);
                }
                return fromKeyStore(keyStore);
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("Falha ao montar o KeyStore de âncoras", e);
            }
        }

        @Override
        public String describe() {
            return anchors.size() + " âncora(s): " + anchors.stream()
                    .map(a -> a.getSubjectX500Principal().getName() + " (sha256 " + CertificateParser.getFingerprintSha256(a) + ")")
                    .collect(Collectors.joining("; "));
        }
    }

    private static X509TrustManager fromKeyStore(KeyStore keyStore) {
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(keyStore);
            return Arrays.stream(factory.getTrustManagers())
                    .filter(X509TrustManager.class::isInstance)
                    .map(X509TrustManager.class::cast)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Nenhum X509TrustManager disponível"));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Falha ao criar TrustManager", e);
        }
    }
}
