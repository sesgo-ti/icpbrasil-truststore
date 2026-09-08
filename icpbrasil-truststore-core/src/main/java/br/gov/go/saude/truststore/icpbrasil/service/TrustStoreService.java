package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider.ParsedSnapshot;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;

/** Pipeline serial de validacao, persistencia e publicacao do acervo ICP-Brasil. */
@Slf4j
public class TrustStoreService {
    private final TrustStoreRepository repository;
    private final IcpBrasilCertificateProvider provider;
    private final Cache cache;
    private final long ttlMillis;

    /** Uma instancia por cache/repositorio; o relogio do cache governa toda a validade. */
    public TrustStoreService(TrustStoreRepository repository, IcpBrasilCertificateProvider provider,
                             TrustStoreConfig config, Cache cache) {
        this.repository = repository;
        this.provider = provider;
        this.cache = cache;
        this.ttlMillis = config.getCacheTtlMaxMillis();
        if (ttlMillis <= 0) {
            throw new IllegalArgumentException("TTL maximo do acervo deve ser positivo");
        }
    }

    /** Reflete a validade em memoria neste instante, sem consultar storage. */
    public boolean isCacheValid() {
        return cache.isCacheValid();
    }

    /**
     * Serializa refreshes. Falhas conservam somente a validade original da geracao anterior.
     * Enquanto o cache nunca foi carregado ou invalidado, tenta o formato local legado
     * (ZIP, SHA-512, Instant ISO-8601), inclusive apos falhas transitorias. Rejeita confirmacao
     * futura ou expirada. Somente evidencia remota pode renovar o prazo.
     */
    public synchronized void refresh() {
        long version = cache.version();
        if (version == 0 && cache.getState().isEmpty()) {
            try {
                var zip = repository.recuperarZip();
                var hash = repository.recuperarHash();
                var confirmation = repository.recuperarUltimaConfirmacao();
                if (zip.isPresent() && hash.isPresent() && confirmation.isPresent()) {
                    ParsedSnapshot local = provider.parseSnapshot(zip.get(), hash.get());
                    cache.publishInitial(local, confirmation.get(), ttlMillis);
                }
            } catch (Exception e) {
                log.warn("Acervo local indisponivel ou invalido", e);
            }
        }
        try {
            String remoteHash = provider.baixarHashIcpBrasil();
            ParsedSnapshot parsed = null;
            try {
                var localZip = repository.recuperarZip();
                if (localZip.isPresent()) {
                    // O hash do storage nao comprova que seus bytes ou o indice servido sejam os mesmos.
                    parsed = provider.parseSnapshot(localZip.get(), remoteHash);
                }
            } catch (Exception e) {
                log.debug("ZIP local nao corresponde a uma geracao remota valida", e);
            }
            if (parsed == null) {
                parsed = provider.parseSnapshot(provider.baixarZipIcpBrasil(), remoteHash);
            }
            ParsedSnapshot candidate = parsed;
            Instant confirmedAt = cache.now();
            cache.publish(candidate, confirmedAt, ttlMillis, version, () -> {
                // O formato existente nao e transacional. Confirmacao por ultimo limita falhas parciais;
                // qualquer carga futura revalida os bytes, o hash e o conteudo antes de servir.
                repository.armazenarZip(candidate.zip());
                repository.armazenarHash(candidate.hash());
                repository.armazenarUltimaConfirmacao(confirmedAt);
            });
        } catch (Exception e) {
            log.warn("Refresh falhou; preservando apenas o prazo original do snapshot anterior", e);
        }
    }

    /** Compara o DER com as raizes auto-assinadas do acervo ainda valido. */
    public boolean isTrustedRoot(X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            return cache.getRootCertificates().values().stream().anyMatch(trusted -> {
                try {
                    return Arrays.equals(trusted.getEncoded(), encoded);
                } catch (Exception e) {
                    return false;
                }
            });
        } catch (Exception e) {
            return false;
        }
    }
}
