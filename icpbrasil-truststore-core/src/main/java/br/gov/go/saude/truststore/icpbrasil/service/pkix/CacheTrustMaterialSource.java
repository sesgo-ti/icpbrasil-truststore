package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.service.Cache;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Deriva o material PKIX do acervo ICP-Brasil em memória, memoizado por geração publicada: a
 * separação raiz/intermediária custa uma verificação de assinatura por certificado e só é refeita
 * quando {@link Cache#currentCertificates()} passa a devolver outra referência. Todos os
 * certificados entram, inclusive os que compartilham SKI (raiz autoassinada e sua versão
 * cross-signed), para que o construtor PKIX tenha todos os caminhos candidatos.
 *
 * <p>Acervo indisponível, expirado ou sem raízes resulta em vazio — nenhuma validação prossegue
 * sem âncoras confirmadas (fail-closed).</p>
 */
public final class CacheTrustMaterialSource implements TrustMaterialSource {

    private record Derived(List<X509Certificate> certificates, TrustMaterial material) {}

    private final Cache cache;
    private volatile Derived derived;

    public CacheTrustMaterialSource(Cache cache) {
        this.cache = Objects.requireNonNull(cache, "cache");
    }

    @Override
    public Optional<TrustMaterial> current() {
        List<X509Certificate> certificates = cache.currentCertificates();
        if (certificates.isEmpty()) {
            return Optional.empty();
        }
        Derived current = derived;
        if (current == null || current.certificates() != certificates) {
            current = new Derived(certificates, TrustMaterial.of(certificates));
            derived = current;
        }
        return current.material().hasAnchors() ? Optional.of(current.material()) : Optional.empty();
    }
}
