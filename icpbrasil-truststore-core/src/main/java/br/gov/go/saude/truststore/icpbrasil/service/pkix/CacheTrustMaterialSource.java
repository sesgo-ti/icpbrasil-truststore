package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.service.Cache;

import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Deriva o material PKIX do acervo ICP-Brasil em memória, memoizado por geração publicada: a
 * separação raiz/intermediária custa uma verificação de assinatura por certificado e só é refeita
 * quando {@link Cache#currentIndex()} passa a devolver outra referência.
 *
 * <p>Acervo indisponível, expirado ou sem raízes resulta em vazio — nenhuma validação prossegue
 * sem âncoras confirmadas (fail-closed).</p>
 */
public final class CacheTrustMaterialSource implements TrustMaterialSource {

    private record Derived(Map<String, X509Certificate> index, TrustMaterial material) {}

    private final Cache cache;
    private volatile Derived derived;

    public CacheTrustMaterialSource(Cache cache) {
        this.cache = Objects.requireNonNull(cache, "cache");
    }

    @Override
    public Optional<TrustMaterial> current() {
        Map<String, X509Certificate> index = cache.currentIndex();
        if (index.isEmpty()) {
            return Optional.empty();
        }
        Derived current = derived;
        if (current == null || current.index() != index) {
            current = new Derived(index, TrustMaterial.of(index.values()));
            derived = current;
        }
        return current.material().hasAnchors() ? Optional.of(current.material()) : Optional.empty();
    }
}
