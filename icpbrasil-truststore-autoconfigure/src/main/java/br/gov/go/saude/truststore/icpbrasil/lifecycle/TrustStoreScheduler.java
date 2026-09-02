package br.gov.go.saude.truststore.icpbrasil.lifecycle;

import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Componente responsável pelo agendamento da atualização do TrustStore.
 * Pode ser desativado via configuração icpbrasil-truststore.scheduling.enabled=false.
 */
@Slf4j
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
            fixedRateString = "#{${icpbrasil-truststore.refresh-interval-hours:2} * 60 * 60 * 1000}",
            initialDelayString = "#{${icpbrasil-truststore.refresh-interval-hours:2} * 60 * 60 * 1000}")
    public void scheduleRefresh() {
        log.info("Executando atualização agendada do TrustStore");
        trustStoreService.refresh();
    }
}
