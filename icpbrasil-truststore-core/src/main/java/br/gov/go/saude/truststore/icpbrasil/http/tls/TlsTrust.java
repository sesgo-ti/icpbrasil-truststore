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
import java.time.Clock;
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
public sealed interface TlsTrust permits TlsTrust.JvmDefault, TlsTrust.DedicatedCa, TlsTrust.PinnedRoots {

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

    /**
     * Confiança do download do acervo: raízes ISRG embutidas como únicas âncoras e intermediárias
     * buscadas via AIA restrito a {@code i.lencr.org}.
     *
     * @param clock data de validação das cadeias
     */
    static TlsTrust pinnedRoots(Clock clock) {
        ItiTrustManager trustManager = ItiTrustManager.producao(clock);
        return new PinnedRoots(List.of(trustManager.getAcceptedIssuers()), trustManager);
    }

    /**
     * {@link X509TrustManager} desta confiança; o chamador pode guardá-lo e reutilizá-lo.
     * {@link PinnedRoots} devolve sempre a mesma instância, para que as intermediárias já
     * buscadas sirvam a todas as conexões; as demais variantes criam um novo a cada chamada.
     */
    X509TrustManager trustManager();

    /** Âncoras da confiança dedicada, sem duplicatas e em ordem de inserção; vazio para {@link JvmDefault}. */
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

    /** Confiança nos certificados raiz da JVM; não possui âncoras próprias. */
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

    /** Confiança restrita às âncoras informadas; exige ao menos uma e não consulta o cacerts. */
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

    /**
     * Âncoras fixadas com intermediárias via AIA.
     *
     * @throws IllegalArgumentException se {@code anchors} diferir das âncoras do {@code trustManager}
     */
    record PinnedRoots(List<X509Certificate> anchors, ItiTrustManager trustManager) implements TlsTrust {
        public PinnedRoots {
            anchors = List.copyOf(anchors);
            if (!anchors.equals(List.of(trustManager.getAcceptedIssuers()))) {
                throw new IllegalArgumentException("As âncoras devem ser as do ItiTrustManager");
            }
        }

        @Override
        public String describe() {
            return new DedicatedCa(anchors).describe() + "; intermediárias via AIA";
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
