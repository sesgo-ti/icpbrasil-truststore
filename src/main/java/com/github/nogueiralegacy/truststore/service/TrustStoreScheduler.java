package com.github.nogueiralegacy.truststore.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Componente responsável pelo agendamento da atualização do TrustStore.
 * Pode ser desativado via configuração truststore.scheduling.enabled=false.
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
     */
    @Scheduled(fixedRateString = "#{${truststore-icpbrasil.refresh-interval-hours:2} * 60 * 60 * 1000}")
    public void scheduleRefresh() {
        log.info("Executando atualização agendada do TrustStore");
        trustStoreService.refresh();
    }
}
