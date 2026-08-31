package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Cache de respostas OCSP e CRLs com TTL e limite de tamanho configuráveis.
 *
 * <p>Utiliza Caffeine para eviction automática por TTL ({@code expireAfterWrite})
 * e por tamanho ({@code maximumSize}), eliminando a necessidade de limpeza manual.</p>
 *
 * <p>Parâmetros configuráveis via {@code truststore-icpbrasil.revocation.*}
 * em {@code application.yaml}.</p>
 */
@Service
public class RevocationCache {

    private final Cache<String, byte[]> ocspCache;
    private final Cache<String, byte[]> crlCache;

    public RevocationCache(TrustStoreConfig trustStoreConfig) {
        TrustStoreConfig.RevocationConfig config = trustStoreConfig.getRevocation();

        this.ocspCache = Caffeine.newBuilder()
                .expireAfterWrite(config.getOcspCacheTtlSeconds(), TimeUnit.SECONDS)
                .maximumSize(config.getOcspCacheMaxSize())
                .build();

        this.crlCache = Caffeine.newBuilder()
                .expireAfterWrite(config.getCrlCacheTtlSeconds(), TimeUnit.SECONDS)
                .maximumSize(config.getCrlCacheMaxSize())
                .build();
    }

    public Optional<byte[]> getOcsp(String key) {
        return Optional.ofNullable(ocspCache.getIfPresent(key));
    }

    public void putOcsp(String key, byte[] der) {
        ocspCache.put(key, der);
    }

    public Optional<byte[]> getCrl(String url) {
        return Optional.ofNullable(crlCache.getIfPresent(url));
    }

    public void putCrl(String url, byte[] der) {
        crlCache.put(url, der);
    }
}
