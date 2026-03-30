package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.repository.TrustStoreRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Slf4j
@Component
@ConditionalOnClass(name = "org.springframework.boot.actuate.health.HealthIndicator")
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
            Instant ultimaConfirmacao = repository.recuperarUltimaConfirmacao();
            if (ultimaConfirmacao == null) {
                return Health.down()
                    .withDetail("status", "EXPIRED")
                    .withDetail("message", "Última confirmação indisponível")
                    .build();
            }
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
