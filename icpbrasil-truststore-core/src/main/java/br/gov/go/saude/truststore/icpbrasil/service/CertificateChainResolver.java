package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicyException;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.http.HttpClient;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Monta a cadeia de certificados X.509 a partir de um certificado folha (leaf),
 * baixando os emissores via extensão AIA (Authority Information Access) — CA Issuers.
 *
 * <p>O download pode retornar um certificado único (DER/PEM) ou um pacote PKCS#7 (.p7b)
 * contendo a cadeia inteira. Todos os certificados baixados são armazenados em um pool
 * indexado por SKI para evitar downloads redundantes; um SKI pode ter vários candidatos
 * (raiz autoassinada e sua versão cross-signed, ou um certificado com SKI forjado).</p>
 *
 * <p>O emissor é escolhido entre os candidatos com SKI igual ao AKI cujo subject é o issuer
 * do certificado e cuja chave verifica sua assinatura, preferindo o autoassinado — o
 * resultado não depende da ordem dos certificados nem das URLs. As URLs CA Issuers são
 * tentadas em ordem até alguma fornecer um emissor utilizável.</p>
 *
 * <p>O transporte HTTP usa o trust store padrão da JVM, pois os endpoints AIA são
 * acessados via CAs públicas.</p>
 */
@Slf4j
public class CertificateChainResolver {
    private static final int MAX_CHAIN_DEPTH = 10;

    private final CertificateHttpTransport transport;
    private final RetryPolicy retryPolicy;
    private final TrustStoreConfig.ChainConfig chainConfig;

    /**
     * Construtor de produção: o transporte é compartilhado com os clientes OCSP e CRL e traz
     * consigo a {@link DownloadPolicy} aplicada a cada requisição.
     */
    public CertificateChainResolver(RetryPolicy retryPolicy, TrustStoreConfig trustStoreConfig,
                                    CertificateHttpTransport transport) {
        this(retryPolicy, trustStoreConfig.getChain(), transport);
    }

    public CertificateChainResolver(RetryPolicy retryPolicy, TrustStoreConfig.ChainConfig chainConfig,
                                    HttpClient httpClient, DownloadPolicy downloadPolicy) {
        this(retryPolicy, chainConfig, new CertificateHttpTransport(downloadPolicy, httpClient));
    }

    private CertificateChainResolver(RetryPolicy retryPolicy, TrustStoreConfig.ChainConfig chainConfig,
                                     CertificateHttpTransport transport) {
        this.retryPolicy = retryPolicy;
        this.chainConfig = chainConfig;
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    /**
     * Resolve a cadeia de certificados a partir de um certificado folha (leaf),
     * baixando emissores via AIA CA Issuers até encontrar um auto-assinado (raiz)
     * ou não haver mais URLs AIA disponíveis.
     *
     * @param leaf certificado folha (end-entity) a partir do qual a cadeia será montada
     * @return Lista ordenada [leaf, intermediário1, ..., raiz] terminando em auto-assinado
     * @throws IncompleteChainException se não for possível alcançar um certificado raiz (auto-assinado)
     */
    public List<X509Certificate> resolveChain(X509Certificate leaf) throws IncompleteChainException {
        List<X509Certificate> chain = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Map<String, List<X509Certificate>> pool = new HashMap<>();

        X509Certificate current = leaf;
        chain.add(current);

        for (int i = 0; i < MAX_CHAIN_DEPTH; i++) {
            if (CertificateParser.isSelfSigned(current)) {
                return List.copyOf(chain);
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

            X509Certificate issuer = selectIssuer(current, pool.get(aki));

            if (issuer == null) {
                List<String> caIssuersUrls = CertificateParser.getCaIssuersUrls(current);
                if (caIssuersUrls.isEmpty()) {
                    log.info("Certificado sem URLs de CA Issuers no AIA.");
                    throw new IncompleteChainException(
                            "Certificado sem URLs de CA Issuers no AIA", chain);
                }
                for (String url : caIssuersUrls) {
                    addToPool(pool, download(url));
                    issuer = selectIssuer(current, pool.get(aki));
                    if (issuer != null) {
                        break;
                    }
                    if (Thread.currentThread().isInterrupted()) {
                        break;
                    }
                }
            }

            if (issuer == null && pool.containsKey(aki)) {
                log.warn("Nenhum candidato com SKI {} é o emissor ou tem assinatura que confira.", aki);
                throw new IncompleteChainException(
                        "Assinatura inválida para emissor com AKI " + aki, chain);
            }
            if (issuer == null) {
                log.info("Emissor com AKI {} não encontrado nos certificados baixados.", aki);
                throw new IncompleteChainException(
                        "Emissor com AKI " + aki + " não encontrado", chain);
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
     * Candidato utilizável: subject igual ao issuer do certificado e chave que verifica sua
     * assinatura. Entre vários, o autoassinado encerra a cadeia e é preferido.
     */
    private X509Certificate selectIssuer(X509Certificate certificate, List<X509Certificate> candidates) {
        if (candidates == null) {
            return null;
        }
        return candidates.stream()
                .filter(candidate -> candidate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()))
                .filter(candidate -> verifySignature(certificate, candidate))
                .min(Comparator.comparing((X509Certificate candidate) -> !CertificateParser.isSelfSigned(candidate)))
                .orElse(null);
    }

    private static void addToPool(Map<String, List<X509Certificate>> pool, List<X509Certificate> downloaded) {
        for (X509Certificate cert : downloaded) {
            try {
                String ski = CertificateParser.getSubjectKeyIdentifier(cert);
                List<X509Certificate> candidates = pool.computeIfAbsent(ski, k -> new ArrayList<>());
                if (!candidates.contains(cert)) {
                    candidates.add(cert);
                }
            } catch (RuntimeException e) {
                log.debug("Certificado baixado sem SKI, ignorando: {}", e.getMessage());
            }
        }
    }

    /**
     * Baixa os certificados de uma URL CA Issuers. Suporta DER, PEM e PKCS#7 (.p7b).
     * URL bloqueada, falha de rede ou conteúdo não parseável resultam em lista vazia, para que a
     * próxima URL seja tentada.
     */
    private List<X509Certificate> download(String url) {
        try {
            transport.policy().validateUrl(url);
        } catch (DownloadPolicyException e) {
            log.warn("URL de CA Issuers bloqueada pela política de download: {}", e.getMessage());
            return List.of();
        }

        try {
            byte[] data = retryPolicy.executeWithRetry(
                    "AIA CA Issuers " + url,
                    chainConfig.getMaxRetries(),
                    chainConfig.getRetryIntervalSeconds() * 1000L,
                    () -> downloadBytes(url));

            List<X509Certificate> certs = CertificateParser.parseAll(data);
            log.debug("Baixados {} certificados de {}", certs.size(), url);
            return certs;
        } catch (DownloadPolicyException e) {
            log.warn("Resposta AIA bloqueada pela política de download: {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Download de CA Issuers interrompido para {}", url);
        } catch (Exception e) {
            log.warn("Falha ao baixar certificados de {}: {}", url, e.getMessage());
        }
        return List.of();
    }

    private byte[] downloadBytes(String url) throws IOException, InterruptedException {
        return transport.get(url, transport.policy().getMaxAiaResponseBytes(),
                Duration.ofSeconds(chainConfig.getDownloadTimeoutSeconds()));
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
