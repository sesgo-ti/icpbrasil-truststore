package br.gov.go.saude.truststore.icpbrasil.lifecycle;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Saúde do acervo servido, derivada exclusivamente do snapshot publicado no {@link Cache}
 * ({@link Cache#getState()}): sem I/O, para que a sonda de readiness não dependa do storage
 * nem observe um estado diferente do que as leituras do acervo observam.
 *
 * <ul>
 *   <li>{@code UNAVAILABLE} (DOWN): nenhum snapshot publicado ou cache invalidado.</li>
 *   <li>{@code EXPIRED} (DOWN): snapshot vencido pelo relógio; leituras já retornam vazio.</li>
 *   <li>{@code CRITICAL} (UP): vigente, mas confirmado há mais que {@code cache-ttl-critical-hours}.</li>
 *   <li>{@code VALID} (UP): vigente e confirmado dentro do limiar crítico.</li>
 * </ul>
 *
 * <p>Os detalhes limitam-se a {@code status}, {@code confirmedAt}, {@code expiresAt} e, só quando
 * há descarte, {@code raizesNaoFixadas} (lista de {@code subject} e {@code fingerprintSha256} das
 * raízes fora da lista fixada, dados públicos do certificado; o status segue UP, pois o acervo
 * publicado continua íntegro): nenhuma mensagem de exceção ou caminho interno é exposto pelo
 * endpoint.</p>
 */
public class TrustStoreCacheHealthIndicator implements HealthIndicator {

    private final TrustStoreConfig config;
    private final Cache cache;

    public TrustStoreCacheHealthIndicator(TrustStoreConfig config, Cache cache) {
        this.config = config;
        this.cache = cache;
    }

    @Override
    public Health health() {
        Optional<Cache.State> stateOpt = cache.getState();
        if (stateOpt.isEmpty()) {
            return Health.down().withDetail("status", "UNAVAILABLE").build();
        }
        Cache.State state = stateOpt.get();
        Health.Builder builder;
        String status;
        if (!state.valid()) {
            builder = Health.down();
            status = "EXPIRED";
        } else {
            // A vigência já foi decidida pelo relógio do Cache; a idade da confirmação usa o relógio
            // do sistema apenas para classificar VALID/CRITICAL, sem efeito sobre o que é servido.
            Duration idade = Duration.between(state.confirmedAt(), Instant.now());
            builder = Health.up();
            status = idade.toMillis() <= config.getCacheTtlCriticalMillis() ? "VALID" : "CRITICAL";
        }
        builder.withDetail("status", status)
                .withDetail("confirmedAt", state.confirmedAt().toString())
                .withDetail("expiresAt", state.expiresAt().toString());
        if (!state.raizesNaoFixadas().isEmpty()) {
            builder.withDetail("raizesNaoFixadas", state.raizesNaoFixadas().stream()
                    .map(raiz -> Map.of("subject", raiz.subject(), "fingerprintSha256", raiz.fingerprintSha256()))
                    .toList());
        }
        return builder.build();
    }
}
