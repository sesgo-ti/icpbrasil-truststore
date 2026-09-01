package br.gov.go.saude.truststore.icpbrasil.lifecycle;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

import java.time.Instant;
import java.util.Optional;

@Slf4j
public class TrustStoreCacheHealthIndicator implements HealthIndicator {

    private final TrustStoreRepository repository;
    private final TrustStoreConfig config;

    public TrustStoreCacheHealthIndicator(TrustStoreRepository repository, TrustStoreConfig config) {
        this.repository = repository;
        this.config = config;
    }

    @Override
    public Health health() {
        if (!Cache.isCacheValid()) {
            return Health.down()
                .withDetail("status", "EXPIRED")
                .withDetail("message", "Cache expirado — certificados não disponíveis")
                .build();
        }
        try {
            Optional<Instant> ultimaConfirmacaoOpt = repository.recuperarUltimaConfirmacao();
            if (ultimaConfirmacaoOpt.isEmpty()) {
                return Health.down()
                    .withDetail("status", "EXPIRED")
                    .withDetail("message", "Última confirmação indisponível")
                    .build();
            }
            Instant ultimaConfirmacao = ultimaConfirmacaoOpt.get();
            long idadeMillis = Instant.now().toEpochMilli() - ultimaConfirmacao.toEpochMilli();
            if (idadeMillis <= config.getCacheTtlCriticalMillis()) {
                return Health.up()
                    .withDetail("status", "VALID")
                    .withDetail("ultimaConfirmacao", ultimaConfirmacao.toString())
                    .build();
            }
            if (idadeMillis <= config.getCacheTtlMaxMillis()) {
                return Health.up()
                    .withDetail("status", "CRITICAL")
                    .withDetail("message", "Cache sem atualização há mais de "
                        + config.getCacheTtlCriticalHours() + " horas")
                    .withDetail("ultimaConfirmacao", ultimaConfirmacao.toString())
                    .build();
            }
            return Health.down()
                .withDetail("status", "EXPIRED")
                .withDetail("message", "Cache expirado — TTL máximo ultrapassado")
                .withDetail("ultimaConfirmacao", ultimaConfirmacao.toString())
                .build();
        } catch (Exception e) {
            log.error("Erro ao verificar saúde do cache", e);
            return Health.unknown()
                .withDetail("status", "UNKNOWN")
                .withDetail("error", e.getMessage())
                .build();
        }
    }
}
