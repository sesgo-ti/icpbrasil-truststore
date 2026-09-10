package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Pipeline de carga do acervo ICP-Brasil: repositório local → sincronização com o ITI →
 * publicação no {@link Cache}.
 *
 * <p>Invariante: nada é persistido nem publicado antes de o ZIP ter o hash validado, todos os
 * certificados parseados e o índice montado. A validade publicada ({@code expiresAt}) deriva
 * sempre do instante em que a geração foi confirmada junto ao ITI — nunca da hora em que o
 * arquivo foi lido ou validado — somado a {@code cache-ttl-max-hours}.</p>
 */
@Slf4j
public class TrustStoreService {

    /**
     * Tolerância para a última confirmação persistida estar à frente do relógio local (relógios
     * de hosts distintos compartilhando o repositório). Além disso a confirmação é rejeitada,
     * pois estenderia a validade do acervo para além do TTL configurado.
     */
    private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(15);

    private final TrustStoreRepository trustStoreRepository;
    private final IcpBrasilCertificateProvider icpBrasilCertificateProvider;
    private final TrustStoreConfig trustStoreConfig;
    private final Cache cache;
    private final Clock clock;

    public TrustStoreService(TrustStoreRepository trustStoreRepository,
                             IcpBrasilCertificateProvider icpBrasilCertificateProvider,
                             TrustStoreConfig trustStoreConfig,
                             Cache cache) {
        this(trustStoreRepository, icpBrasilCertificateProvider, trustStoreConfig, cache, Clock.systemUTC());
    }

    public TrustStoreService(TrustStoreRepository trustStoreRepository,
                             IcpBrasilCertificateProvider icpBrasilCertificateProvider,
                             TrustStoreConfig trustStoreConfig,
                             Cache cache,
                             Clock clock) {
        this.trustStoreRepository = trustStoreRepository;
        this.icpBrasilCertificateProvider = icpBrasilCertificateProvider;
        this.trustStoreConfig = trustStoreConfig;
        this.cache = cache;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Indica se o cache gerenciado por este serviço está válido.
     * Fachada pública de leitura — a escrita da validade é interna ao pipeline.
     */
    public boolean isCacheValid() {
        return cache.isCacheValid();
    }

    /**
     * Atualiza o acervo servido. Nunca lança: falhas são registradas e o snapshot anterior,
     * quando existe, continua sendo servido até o seu prazo original.
     *
     * <ol>
     *   <li>Sem snapshot vigente, tenta publicar o acervo persistido no repositório local,
     *       com a validade derivada da confirmação persistida (carga repetível: uma leitura que
     *       falhe hoje pode ter sucesso no próximo ciclo).</li>
     *   <li>Baixa o hash publicado pelo ITI. Se repositório local e snapshot atual já têm essa
     *       geração, apenas renova a confirmação; caso contrário baixa o ZIP, valida, parseia,
     *       publica e persiste.</li>
     * </ol>
     *
     * <p>Persistência vem depois da publicação e nunca a desfaz: o repositório serve ao próximo
     * cold start, não à validade do que já foi validado nesta execução.</p>
     *
     * <p>Sincronizado porque bootstrap e agendador podem coincidir; leituras do cache não são
     * bloqueadas.</p>
     */
    public synchronized void refresh() {
        Instant now = clock.instant();
        if (!cache.isCacheValid()) {
            carregarAcervoLocal(now);
        }
        sincronizarComIti(now);
        if (!cache.isCacheValid()) {
            log.error("Acervo ICP-Brasil indisponível: nenhum snapshot válido após a sincronização");
        }
    }

    private void carregarAcervoLocal(Instant now) {
        try {
            Optional<byte[]> zipOpt = trustStoreRepository.recuperarZip().filter(zip -> zip.length > 0);
            Optional<String> hashOpt = trustStoreRepository.recuperarHash().filter(hash -> !hash.isBlank());
            Optional<Instant> confirmacaoOpt = trustStoreRepository.recuperarUltimaConfirmacao();
            if (zipOpt.isEmpty() || hashOpt.isEmpty() || confirmacaoOpt.isEmpty()) {
                log.info("Repositório local sem acervo completo; aguardando sincronização com o ITI");
                return;
            }

            Instant confirmedAt = confirmacaoOpt.get();
            if (confirmedAt.isAfter(now.plus(MAX_CLOCK_SKEW))) {
                log.warn("Última confirmação persistida ({}) está no futuro; acervo local rejeitado", confirmedAt);
                return;
            }
            Instant expiresAt = expiracao(confirmedAt);
            if (!expiresAt.isAfter(now)) {
                log.warn("Acervo local expirado desde {}; aguardando sincronização com o ITI", expiresAt);
                return;
            }

            String hash = normalizarHash(hashOpt.get());
            byte[] zipData = zipOpt.get();
            icpBrasilCertificateProvider.validateZipIntegrity(zipData, hash);
            Map<String, X509Certificate> index = Cache.indexBySki(
                    icpBrasilCertificateProvider.parseCertificates(zipData));
            cache.publish(index, hash, confirmedAt, expiresAt);
            log.info("Acervo do repositório local publicado (confirmado em {})", confirmedAt);
        } catch (RuntimeException e) {
            log.warn("Falha ao carregar acervo do repositório local: {}", e.getMessage());
        }
    }

    private void sincronizarComIti(Instant now) {
        try {
            String hashRemoto = icpBrasilCertificateProvider.baixarHashIcpBrasil();
            Instant expiresAt = expiracao(now);

            // Reconfirmar só pelo hash exige que repositório E snapshot já tenham essa geração:
            // o repositório, para que a confirmação persistida nunca prolongue uma geração que o
            // ITI não anuncia mais (ex.: publicação em memória cuja persistência falhou); o
            // snapshot, de forma atômica, para não republicar um índice invalidado nesse meio-tempo.
            if (repositorioTemGeracao(hashRemoto) && cache.renew(hashRemoto, now, expiresAt)) {
                log.info("O repositório local está sincronizado com a fonte ICP-Brasil");
                persistir("última confirmação", () -> trustStoreRepository.armazenarUltimaConfirmacao(now));
                return;
            }

            log.info("Geração {} anunciada pelo ITI não corresponde ao snapshot atual ou ao repositório local; "
                    + "baixando o bundle", hashRemoto);
            byte[] zipData = icpBrasilCertificateProvider.baixarZipIcpBrasil();
            icpBrasilCertificateProvider.validateZipIntegrity(zipData, hashRemoto);
            List<X509Certificate> certificates = icpBrasilCertificateProvider.parseCertificates(zipData);
            Map<String, X509Certificate> index = Cache.indexBySki(certificates);

            // Publicar antes de persistir: a validação já precedeu ambos, e uma geração que remove
            // uma AC deve valer imediatamente mesmo com o repositório indisponível.
            cache.publish(index, hashRemoto, now, expiresAt);
            persistir("acervo", () -> {
                trustStoreRepository.armazenarZip(zipData);
                trustStoreRepository.armazenarHash(hashRemoto);
                trustStoreRepository.armazenarUltimaConfirmacao(now);
            });
        } catch (RuntimeException e) {
            log.warn("Falha na sincronização com o ITI; snapshot atual mantido até o prazo original: {}",
                    e.getMessage());
        }
    }

    /**
     * Falha de leitura conta como geração ausente: o caminho completo regrava o repositório em
     * vez de confirmar um conteúdo que não pôde ser conferido.
     */
    private boolean repositorioTemGeracao(String hash) {
        try {
            return trustStoreRepository.recuperarHash()
                    .map(TrustStoreService::normalizarHash)
                    .filter(hash::equals)
                    .isPresent();
        } catch (RuntimeException e) {
            log.warn("Falha ao ler o hash do repositório local: {}", e.getMessage());
            return false;
        }
    }

    /**
     * O snapshot já está publicado; se a escrita falhar, apenas o próximo cold start deixa de
     * contar com o repositório, o que é conservador.
     */
    private void persistir(String descricao, Runnable escrita) {
        try {
            escrita.run();
        } catch (RuntimeException e) {
            log.warn("Falha ao persistir {} no repositório local; acervo válido apenas em memória: {}",
                    descricao, e.getMessage());
        }
    }

    private Instant expiracao(Instant confirmedAt) {
        return confirmedAt.plusMillis(trustStoreConfig.getCacheTtlMaxMillis());
    }

    private static String normalizarHash(String hash) {
        return hash.trim().toLowerCase(Locale.ROOT);
    }

    public boolean isTrustedRoot(X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            return cache.getRootCertificates().values().stream()
                    .anyMatch(trusted -> {
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
