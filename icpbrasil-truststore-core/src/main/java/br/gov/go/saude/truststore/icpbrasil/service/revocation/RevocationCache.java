package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.security.cert.X509CRL;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Cache de respostas OCSP e CRLs com TTL e limite de tamanho configuráveis.
 *
 * <p>Utiliza Caffeine para eviction automática por TTL ({@code expireAfterWrite})
 * e por tamanho ({@code maximumSize}), eliminando a necessidade de limpeza manual.</p>
 *
 * <p>Respostas OCSP são guardadas em DER: são pequenas e o cliente as reinterpreta a cada uso.
 * CRLs são guardadas já decodificadas ({@link X509CRL}): listas da ICP-Brasil chegam a vários
 * megabytes, e decodificá-las a cada consulta custaria mais que a própria verificação.</p>
 *
 * <p>Parâmetros configuráveis via {@code icpbrasil-truststore.revocation.*}
 * em {@code application.yaml}.</p>
 */
public class RevocationCache {

    private final Cache<String, byte[]> ocspCache;
    private final Cache<String, X509CRL> crlCache;

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

    public Optional<X509CRL> getCrl(String url) {
        return Optional.ofNullable(crlCache.getIfPresent(url));
    }

    public void putCrl(String url, X509CRL crl) {
        crlCache.put(url, crl);
    }
}
