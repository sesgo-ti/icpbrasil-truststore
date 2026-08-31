package br.gov.go.saude.truststore.icpbrasil.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Componente responsável pelo agendamento da atualização do TrustStore.
 * Pode ser desativado via configuração truststore-icpbrasil.scheduling.enabled=false.
 */
@Slf4j
@Component
@EnableScheduling
@ConditionalOnProperty(prefix = "truststore-icpbrasil.scheduling", name = "enabled", havingValue = "true", matchIfMissing = true)
public class TrustStoreScheduler {
    private final TrustStoreService trustStoreService;

    public TrustStoreScheduler(TrustStoreService trustStoreService) {
        this.trustStoreService = trustStoreService;
    }

    /**
     * Executa a verificação automática periódica de sincronização do repositório local.
     * <p>
     * O {@code initialDelayString} é igual ao {@code fixedRateString} para adiar a
     * primeira execução em um intervalo completo — o {@link TrustStoreBootstrap}
     * já realiza a carga inicial no startup, evitando competir com o scheduler.
     */
    @Scheduled(
            fixedRateString = "#{${truststore-icpbrasil.refresh-interval-hours:2} * 60 * 60 * 1000}",
            initialDelayString = "#{${truststore-icpbrasil.refresh-interval-hours:2} * 60 * 60 * 1000}")
    public void scheduleRefresh() {
        log.info("Executando atualização agendada do TrustStore");
        trustStoreService.refresh();
    }
}
