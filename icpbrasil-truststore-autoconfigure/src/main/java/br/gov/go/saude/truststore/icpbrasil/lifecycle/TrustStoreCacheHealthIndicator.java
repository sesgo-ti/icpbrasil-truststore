package br.gov.go.saude.truststore.icpbrasil.lifecycle;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

import java.time.Duration;

/** Saude temporal do snapshot servido, sem I/O de storage ou rede em probes. */
public class TrustStoreCacheHealthIndicator implements HealthIndicator {

    private final TrustStoreConfig config;
    private final Cache cache;

    /** O limiar critico apenas alerta; a disponibilidade e decidida pelo proprio snapshot. */
    public TrustStoreCacheHealthIndicator(TrustStoreConfig config, Cache cache) {
        this.config = config;
        this.cache = cache;
    }

    @Override
    public Health health() {
        return cache.getState().map(state -> {
            String status = "EXPIRED";
            if (state.valid()) {
                status = Duration.between(state.confirmedAt(), state.observedAt())
                        .compareTo(Duration.ofMillis(config.getCacheTtlCriticalMillis())) > 0
                        ? "CRITICAL" : "VALID";
            }
            return (state.valid() ? Health.up() : Health.down())
                    .withDetail("status", status)
                    .withDetail("ultimaConfirmacao", state.confirmedAt().toString())
                    .build();
        }).orElseGet(() -> Health.down().withDetail("status", "UNAVAILABLE").build());
    }
}
