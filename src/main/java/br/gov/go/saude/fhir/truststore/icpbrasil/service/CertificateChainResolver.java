package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Monta a cadeia de certificados X.509 a partir de um certificado folha (leaf),
 * baixando os emissores via extensão AIA (Authority Information Access) — CA Issuers.
 *
 * <p>O download pode retornar um certificado único (DER/PEM) ou um pacote PKCS#7 (.p7b)
 * contendo a cadeia inteira. Todos os certificados baixados são armazenados em um pool
 * indexado por SKI para evitar downloads redundantes.</p>
 *
 * <p>Após montar a cadeia via AKI→SKI, cada assinatura é verificada criptograficamente
 * contra o emissor, garantindo integridade da cadeia.</p>
 *
 * <p>O HttpClient usa o trust store padrão da JVM, pois os endpoints AIA são
 * acessados via CAs públicas.</p>
 */
@Slf4j
@Service
public class CertificateChainResolver {
    private static final int MAX_CHAIN_DEPTH = 10;

    private final HttpClient httpClient;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.ChainConfig chainConfig;

    @Autowired
    public CertificateChainResolver(RetryPolicy retryPolicy, TrustStoreConfig trustStoreConfig) {
        this.retryPolicy = retryPolicy;
        this.chainConfig = trustStoreConfig.getChain();
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(chainConfig.getDownloadTimeoutSeconds()))
                .build();
    }

    // Package-private para testes
    CertificateChainResolver(RetryPolicy retryPolicy, TrustStoreConfig.ChainConfig chainConfig,
                             HttpClient httpClient) {
        this.retryPolicy = retryPolicy;
        this.chainConfig = chainConfig;
        this.httpClient = httpClient;
    }

    /**
     * Constrói a cadeia de certificados a partir de um certificado folha (leaf),
     * baixando emissores via AIA CA Issuers até encontrar um auto-assinado (raiz)
     * ou não haver mais URLs AIA disponíveis.
     *
     * @param leaf certificado folha (end-entity) a partir do qual a cadeia será montada
     * @return Lista ordenada [leaf, intermediário1, ..., raiz] terminando em auto-assinado
     * @throws IncompleteChainException se não for possível alcançar um certificado raiz (auto-assinado)
     */
    public List<X509Certificate> mountChain(X509Certificate leaf) {
        List<X509Certificate> chain = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Map<String, X509Certificate> pool = new HashMap<>();

        X509Certificate current = leaf;
        chain.add(current);

        for (int i = 0; i < MAX_CHAIN_DEPTH; i++) {
            if (CertificateParser.isSelfSigned(current)) {
                return chain;
            }

            String aki;
            try {
                aki = CertificateParser.getAuthorityKeyIdentifier(current);
            } catch (RuntimeException e) {
                log.warn("Não foi possível extrair AKI do certificado: {}", e.getMessage());
                throw new IncompleteChainException(
                        "Não foi possível extrair AKI do certificado", chain);
            }

            if (visited.contains(aki)) {
                log.warn("Referência circular detectada na cadeia de certificados (AKI: {})", aki);
                throw new IncompleteChainException(
                        "Referência circular detectada (AKI: " + aki + ")", chain);
            }

            X509Certificate issuer = pool.get(aki);

            if (issuer == null) {
                List<String> caIssuersUrls = CertificateParser.getCaIssuersUrls(current);
                if (caIssuersUrls.isEmpty()) {
                    log.info("Certificado sem URLs de CA Issuers no AIA.");
                    throw new IncompleteChainException(
                            "Certificado sem URLs de CA Issuers no AIA", chain);
                }

                List<X509Certificate> downloaded = downloadCertificates(caIssuersUrls);
                for (X509Certificate cert : downloaded) {
                    try {
                        String ski = CertificateParser.getSubjectKeyIdentifier(cert);
                        pool.put(ski, cert);
                    } catch (RuntimeException e) {
                        log.debug("Certificado baixado sem SKI, ignorando: {}", e.getMessage());
                    }
                }

                issuer = pool.get(aki);
            }

            if (issuer == null) {
                log.info("Emissor com AKI {} não encontrado nos certificados baixados.", aki);
                throw new IncompleteChainException(
                        "Emissor com AKI " + aki + " não encontrado", chain);
            }

            if (!verifySignature(current, issuer)) {
                log.warn("Assinatura do certificado não confere com o emissor (AKI: {}).", aki);
                throw new IncompleteChainException(
                        "Assinatura inválida para emissor com AKI " + aki, chain);
            }

            chain.add(issuer);
            visited.add(aki);
            current = issuer;
        }

        // Saiu do loop sem encontrar auto-assinado — profundidade máxima
        throw new IncompleteChainException(
                "Profundidade máxima (" + MAX_CHAIN_DEPTH + ") excedida sem alcançar raiz", chain);
    }

    /**
     * Tenta baixar certificados de cada URL CA Issuers.
     * Suporta DER, PEM e PKCS#7 (.p7b).
     */
    private List<X509Certificate> downloadCertificates(List<String> urls) {
        for (String url : urls) {
            try {
                byte[] data = retryPolicy.executeWithRetry(
                        "AIA CA Issuers " + url,
                        chainConfig.getMaxRetries(),
                        chainConfig.getRetryIntervalSeconds() * 1000L,
                        () -> downloadBytes(url));

                List<X509Certificate> certs = CertificateParser.parseAll(data);
                if (!certs.isEmpty()) {
                    log.debug("Baixados {} certificados de {}", certs.size(), url);
                    return certs;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("Download de CA Issuers interrompido para {}", url);
                return List.of();
            } catch (Exception e) {
                log.warn("Falha ao baixar certificados de {}: {}", url, e.getMessage());
            }
        }
        return List.of();
    }

    private byte[] downloadBytes(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(chainConfig.getDownloadTimeoutSeconds()))
                .GET()
                .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("HTTP " + response.statusCode() + " para " + url);
        }
        return response.body();
    }

    /**
     * Verifica se a assinatura do certificado é válida usando a chave pública do emissor.
     */
    private boolean verifySignature(X509Certificate cert, X509Certificate issuer) {
        try {
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            log.debug("Verificação de assinatura falhou: {}", e.getMessage());
            return false;
        }
    }
}
