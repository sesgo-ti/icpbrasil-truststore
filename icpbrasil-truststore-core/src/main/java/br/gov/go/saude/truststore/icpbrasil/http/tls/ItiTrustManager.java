package br.gov.go.saude.truststore.icpbrasil.http.tls;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.IncompleteChainException;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * TrustManager do download do acervo: âncoras fixas (raízes ISRG) e intermediárias resolvidas via
 * AIA, porque o servidor do ITI envia só a própria folha.
 *
 * <p>Intermediárias baixadas entram num pool sem confiança: só valem se o validador PKIX fechar a
 * cadeia até uma âncora. A decisão é sempre da JSSE, delegada a um {@link X509ExtendedTrustManager}
 * PKIX com o mesmo {@link SSLEngine}/{@link Socket}, o que preserva a verificação de hostname. O
 * {@link Clock} define a data de validação. Thread-safe; o pool é compartilhado entre conexões.</p>
 */
@Slf4j
public final class ItiTrustManager extends X509ExtendedTrustManager {

    // O pool é só cache sem confiança: cheio, é esvaziado em vez de recusar novos certificados. Assim,
    // um MITM que o encha de intermediárias inúteis custa uma busca AIA extra, não um bloqueio duradouro.
    private static final int MAX_POOL = 64;
    private static final int MAX_LOG_URL = 200;
    private static final int MAX_LOG_MOTIVO = 500;
    private static final Pattern CONTROLE = Pattern.compile("[\\p{Cc}\\u2028\\u2029]");

    private final List<X509Certificate> anchors;
    private final Set<TrustAnchor> trustAnchors;
    private final CertificateChainResolver resolver;
    private final Clock clock;
    private final Set<X509Certificate> pool = ConcurrentHashMap.newKeySet();

    /**
     * @param anchors únicas âncoras de confiança; certificados idênticos entram uma vez
     * @param resolver busca AIA das intermediárias; a política de URLs dele limita de onde elas vêm
     * @param clock data de validação da cadeia
     * @throws IllegalArgumentException se {@code anchors} for vazio
     */
    public ItiTrustManager(Collection<X509Certificate> anchors, CertificateChainResolver resolver, Clock clock) {
        this.anchors = List.copyOf(new LinkedHashSet<>(anchors));
        if (this.anchors.isEmpty()) {
            throw new IllegalArgumentException("ItiTrustManager exige ao menos uma âncora");
        }
        this.trustAnchors = this.anchors.stream().map(a -> new TrustAnchor(a, null))
                .collect(Collectors.toUnmodifiableSet());
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Configuração de produção: raízes ISRG embutidas e busca AIA restrita a {@code i.lencr.org},
     * sem retentativa dentro do handshake (a sincronização já repete o download inteiro).
     */
    public static ItiTrustManager producao(Clock clock) {
        TrustStoreConfig.ChainConfig semRetentativa = new TrustStoreConfig.ChainConfig();
        semRetentativa.setMaxRetries(0);
        HttpClient httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(semRetentativa.getDownloadTimeoutSeconds()))
                .build();
        CertificateChainResolver resolver = new CertificateChainResolver(new RetryPolicy(new TrustStoreConfig()),
                semRetentativa, httpClient, DownloadPolicy.aiaLetsEncrypt());
        return new ItiTrustManager(ItiTlsAnchors.load(), resolver, clock);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        verificar(chain, delegate -> delegate.checkServerTrusted(chain, authType, engine));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        verificar(chain, delegate -> delegate.checkServerTrusted(chain, authType, socket));
    }

    /** Sem {@link SSLEngine}/{@link Socket} a JSSE não verifica hostname; o uso no TLS passa pelas outras variantes. */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        verificar(chain, delegate -> delegate.checkServerTrusted(chain, authType));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        recusarCliente();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        recusarCliente();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        recusarCliente();
    }

    /** Somente as âncoras; intermediárias do pool nunca são emissores aceitos por si. */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return anchors.toArray(X509Certificate[]::new);
    }

    private static void recusarCliente() throws CertificateException {
        throw new CertificateException("Canal só de cliente: certificados de cliente não são aceitos");
    }

    @FunctionalInterface
    private interface Verificacao {
        void executar(X509ExtendedTrustManager delegate) throws CertificateException;
    }

    private void verificar(X509Certificate[] chain, Verificacao verificacao) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Cadeia do servidor vazia");
        }
        try {
            verificacao.executar(delegate());
        } catch (CertificateException primeira) {
            // Revalida mesmo sem certificado novo: outra conexão pode ter completado o pool em paralelo.
            if (!buscarIntermediarias(chain[0])) {
                registrarRecusa(chain[0], primeira);
                throw primeira;
            }
            try {
                verificacao.executar(delegate());
            } catch (CertificateException segunda) {
                segunda.addSuppressed(primeira);
                registrarRecusa(chain[0], segunda);
                throw segunda;
            }
        }
    }

    // URLs e mensagem podem vir do certificado de um MITM: sem isso, CR/LF forjariam linhas no log.
    private static void registrarRecusa(X509Certificate leaf, CertificateException motivo) {
        List<String> urls = CertificateParser.getCaIssuersUrls(leaf).stream()
                .map(url -> sanitizarParaLog(url, MAX_LOG_URL))
                .toList();
        log.warn("TLS do ITI recusado; CA Issuers da folha {}: {}",
                urls, sanitizarParaLog(motivo.getMessage(), MAX_LOG_MOTIVO));
    }

    /** Troca controles C0/C1 (inclusive CR/LF e NEL) e separadores de linha Unicode por {@code ?} e trunca. */
    static String sanitizarParaLog(String valor, int tamanhoMaximo) {
        if (valor == null) {
            return "null";
        }
        String limpo = CONTROLE.matcher(valor).replaceAll("?");
        return limpo.length() <= tamanhoMaximo ? limpo : limpo.substring(0, tamanhoMaximo) + "...";
    }

    /** @return {@code false} se a busca AIA falhou ou não trouxe nenhuma intermediária */
    private boolean buscarIntermediarias(X509Certificate leaf) {
        List<X509Certificate> cadeia;
        try {
            cadeia = resolver.resolveChain(leaf);
        } catch (IncompleteChainException e) {
            cadeia = e.getPartialChain();
        } catch (RuntimeException e) {
            // Falha inesperada vira recusa comum: o handshake falha com CertificateException e a recusa é registrada.
            return false;
        }
        if (cadeia.size() <= 1) {
            return false;
        }
        adicionarAoPool(cadeia.subList(1, cadeia.size()));
        return true;
    }

    /**
     * Descarta os vencidos; se os novos não couberem, esvazia o pool antes de inseri-los, para que a
     * cadeia recém-buscada entre inteira. Acima do teto, ficam os mais próximos da folha.
     */
    private synchronized void adicionarAoPool(List<X509Certificate> intermediarias) {
        Instant agora = clock.instant();
        pool.removeIf(c -> c.getNotAfter().toInstant().isBefore(agora));
        List<X509Certificate> novas = intermediarias.stream().filter(c -> !pool.contains(c)).toList();
        if (pool.size() + novas.size() > MAX_POOL) {
            log.warn("Pool de intermediárias do TLS do ITI cheio ({}); esvaziado", MAX_POOL);
            pool.clear();
        }
        pool.addAll(novas.subList(0, Math.min(novas.size(), MAX_POOL)));
    }

    int tamanhoDoPool() {
        return pool.size();
    }

    private X509ExtendedTrustManager delegate() throws CertificateException {
        try {
            Instant agora = clock.instant();
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, new X509CertSelector());
            params.setRevocationEnabled(false);
            params.setDate(Date.from(agora));
            List<X509Certificate> vigentes = pool.stream()
                    .filter(c -> c.getNotAfter().toInstant().isAfter(agora))
                    .toList();
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(vigentes)));
            TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
            factory.init(new CertPathTrustManagerParameters(params));
            return (X509ExtendedTrustManager) factory.getTrustManagers()[0];
        } catch (GeneralSecurityException e) {
            throw new CertificateException("Falha ao montar a validação PKIX do TLS do ITI", e);
        }
    }
}
