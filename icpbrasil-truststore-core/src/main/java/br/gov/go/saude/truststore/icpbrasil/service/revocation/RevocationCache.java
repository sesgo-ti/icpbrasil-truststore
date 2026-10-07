package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.security.cert.X509CRL;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Cache de respostas OCSP e CRLs com TTL e orçamento de memória em bytes configuráveis.
 *
 * <p>Utiliza Caffeine para eviction automática por TTL ({@code expireAfterWrite}) e por peso
 * ({@code maximumWeight}): o peso de cada entrada é o tamanho em bytes da evidência em DER. Uma
 * contagem de entradas não limitaria a memória, porque uma CRL da ICP-Brasil pode ter de poucos
 * kilobytes a dezenas de megabytes. Para CRLs, guardadas decodificadas, o DER é uma aproximação
 * por baixo do espaço ocupado, proporcional à quantidade de entradas revogadas.</p>
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
    private final Cache<String, WeightedCrl> crlCache;

    private record WeightedCrl(X509CRL crl, int encodedLength) {}

    public RevocationCache(TrustStoreConfig trustStoreConfig) {
        TrustStoreConfig.RevocationConfig config = trustStoreConfig.getRevocation();

        this.ocspCache = Caffeine.newBuilder()
                .expireAfterWrite(config.getOcspCacheTtlSeconds(), TimeUnit.SECONDS)
                .maximumWeight(config.getOcspCacheMaxBytes())
                .weigher((String key, byte[] der) -> der.length)
                .build();

        this.crlCache = Caffeine.newBuilder()
                .expireAfterWrite(config.getCrlCacheTtlSeconds(), TimeUnit.SECONDS)
                .maximumWeight(config.getCrlCacheMaxBytes())
                .weigher((String url, WeightedCrl entry) -> entry.encodedLength())
                .build();
    }

    public Optional<byte[]> getOcsp(String key) {
        return Optional.ofNullable(ocspCache.getIfPresent(key));
    }

    public void putOcsp(String key, byte[] der) {
        ocspCache.put(key, der);
    }

    public Optional<X509CRL> getCrl(String url) {
        return Optional.ofNullable(crlCache.getIfPresent(url)).map(WeightedCrl::crl);
    }

    /** Guarda a CRL com peso igual a {@code encodedLength}, o tamanho do DER de onde foi decodificada. */
    public void putCrl(String url, X509CRL crl, int encodedLength) {
        crlCache.put(url, new WeightedCrl(crl, encodedLength));
    }

    /** Aplica já a eviction e a expiração pendentes, que o Caffeine faz de forma assíncrona; usado pelos testes. */
    void cleanUp() {
        ocspCache.cleanUp();
        crlCache.cleanUp();
    }
}
