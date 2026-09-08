package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider.ParsedSnapshot;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Acervo publicado atomicamente com identidade e validade. Leituras expiram sem depender de refresh.
 * A escrita pertence ao pipeline no mesmo pacote; consumidores recebem apenas leituras.
 * A validade e verificada no instante de cada chamada, nao revoga copias ja entregues.
 */
public class Cache {
    private final Clock clock;
    private volatile Snapshot snapshot;
    private long invalidationVersion;

    /** Usa o relogio UTC do sistema. */
    public Cache() {
        this(Clock.systemUTC());
    }

    /** O relogio tambem governa as confirmacoes produzidas pelo servico deste cache. */
    public Cache(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    Instant now() {
        return clock.instant();
    }

    synchronized long version() {
        return invalidationVersion;
    }

    // Invalidar durante download/parsing impede que aquele refresh ressuscite o acervo.
    synchronized void invalidate() {
        invalidationVersion++;
        snapshot = null;
    }

    // A carga local pode ser repetida, mas nunca substituir uma publicacao ou desfazer invalidacao.
    synchronized void publishInitial(ParsedSnapshot parsed, Instant confirmedAt, long ttlMillis) {
        if (snapshot == null) {
            publish(parsed, confirmedAt, ttlMillis, 0, () -> {});
        }
    }

    synchronized boolean publish(ParsedSnapshot parsed, Instant confirmedAt, long ttlMillis,
                                 long expectedVersion, Runnable persist) {
        Instant expiresAt = confirmedAt.plusMillis(ttlMillis);
        if (ttlMillis <= 0 || expectedVersion != invalidationVersion
                || !usable(confirmedAt, expiresAt, now())) {
            return false;
        }
        Snapshot candidate = new Snapshot(parsed.index(), parsed.hash(), confirmedAt, expiresAt);
        // A invalidacao lineariza antes ou depois de persistir/publicar, nunca entre ambos.
        persist.run();
        snapshot = candidate;
        return true;
    }

    private static boolean usable(Instant confirmedAt, Instant expiresAt, Instant now) {
        return !now.isBefore(confirmedAt) && now.isBefore(expiresAt);
    }

    private Map<String, X509Certificate> currentIndex() {
        Snapshot current = snapshot;
        return current != null && usable(current.confirmedAt(), current.expiresAt(), now())
                ? current.index() : Map.of();
    }

    /** Retorna null se o SKI nao existe ou o acervo esta indisponivel/expirado. */
    public X509Certificate getCertificateBySki(String ski) {
        return lookupCertificate(ski).certificate();
    }

    /**
     * Consulta um unico snapshot e instante, distinguindo acervo indisponivel de SKI ausente.
     * A validade vale para esta chamada; nao revoga o certificado ja entregue.
     */
    public CertificateLookup lookupCertificate(String ski) {
        Snapshot current = snapshot;
        boolean available = current != null && usable(current.confirmedAt(), current.expiresAt(), now());
        return new CertificateLookup(available, available ? current.index().get(ski) : null);
    }

    /** Certificado null significa SKI ausente se available, ou acervo indisponivel caso contrario. */
    public record CertificateLookup(boolean available, X509Certificate certificate) {}

    /** Retorna copia defensiva do indice valido, ou mapa vazio se indisponivel/expirado. */
    public Map<String, X509Certificate> getAllCertificates() {
        return new HashMap<>(currentIndex());
    }

    /** Retorna apenas certificados auto-assinados do snapshot valido capturado nesta chamada. */
    public Map<String, X509Certificate> getRootCertificates() {
        Map<String, X509Certificate> roots = new HashMap<>();
        currentIndex().forEach((ski, certificate) -> {
            if (CertificateParser.isSelfSigned(certificate)) {
                roots.put(ski, certificate);
            }
        });
        return roots;
    }

    /** A janela e [confirmedAt, expiresAt); relogio anterior a confirmacao falha fechado. */
    public boolean isCacheValid() {
        return getState().map(State::valid).orElse(false);
    }

    /** Metadados atomicos para observabilidade sem I/O; preservados mesmo apos expiracao. */
    public Optional<State> getState() {
        Snapshot current = snapshot;
        Instant observedAt = now();
        return current == null ? Optional.empty() : Optional.of(new State(current.hash(),
                current.confirmedAt(), current.expiresAt(), current.index().size(),
                usable(current.confirmedAt(), current.expiresAt(), observedAt), observedAt));
    }

    /** Estado observado em uma chamada; nao e uma autorizacao para leituras futuras. */
    public record State(String hash, Instant confirmedAt, Instant expiresAt, int certificateCount,
                        boolean valid, Instant observedAt) {}

    private record Snapshot(Map<String, X509Certificate> index, String hash,
                            Instant confirmedAt, Instant expiresAt) {}
}
