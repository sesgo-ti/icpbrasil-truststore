package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;

import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Âncoras e intermediárias que fundamentam uma validação PKIX.
 *
 * <p>Do acervo, apenas certificados auto-assinados viram âncoras; todos os demais são oferecidos
 * ao construtor de caminhos como candidatos e revalidados criptograficamente — constar do acervo
 * não substitui a validação PKIX.</p>
 */
public final class TrustMaterial {

    private final Set<TrustAnchor> anchors;
    private final CertStore intermediates;

    private TrustMaterial(Set<TrustAnchor> anchors, List<X509Certificate> intermediates) {
        this.anchors = Set.copyOf(anchors);
        this.intermediates = collectionStore(intermediates);
    }

    /** Separa raízes (auto-assinadas) de intermediárias a partir de um acervo. */
    public static TrustMaterial of(Collection<X509Certificate> certificates) {
        Set<TrustAnchor> anchors = new LinkedHashSet<>();
        List<X509Certificate> intermediates = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            if (CertificateParser.isSelfSigned(certificate)) {
                anchors.add(new TrustAnchor(certificate, null));
            } else {
                intermediates.add(certificate);
            }
        }
        return new TrustMaterial(anchors, intermediates);
    }

    /**
     * Confia diretamente nos certificados informados, sem intermediárias adicionais — para
     * hierarquias fora do acervo em que o chamador confia por outros meios (ex.: homologação).
     */
    public static TrustMaterial anchoredAt(Collection<X509Certificate> trustedCertificates) {
        Set<TrustAnchor> anchors = new LinkedHashSet<>();
        for (X509Certificate certificate : trustedCertificates) {
            anchors.add(new TrustAnchor(certificate, null));
        }
        return new TrustMaterial(anchors, List.of());
    }

    public Set<TrustAnchor> anchors() {
        return anchors;
    }

    public CertStore intermediates() {
        return intermediates;
    }

    public boolean hasAnchors() {
        return !anchors.isEmpty();
    }

    static CertStore collectionStore(Collection<?> entries) {
        try {
            return CertStore.getInstance("Collection", new CollectionCertStoreParameters(entries));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("CertStore Collection indisponível nesta JVM", e);
        }
    }
}
