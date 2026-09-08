package br.gov.go.saude.truststore.icpbrasil.lifecycle;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Agendador da atualização periódica do trust store.
 *
 * <p>Usa um {@link ScheduledExecutorService} próprio (thread daemon dedicada) em vez de
 * {@code @Scheduled}/{@code @EnableScheduling}: uma auto-configuração não deve ativar a
 * infraestrutura global de scheduling do Spring, pois isso ligaria inadvertidamente os
 * {@code @Scheduled} da aplicação consumidora.</p>
 *
 * <p>A primeira execução é adiada em um intervalo completo — o {@link TrustStoreBootstrap}
 * já realiza a carga inicial no startup, evitando trabalho duplicado.</p>
 *
 * <p>Ciclo de vida gerenciado pela auto-configuração via {@code initMethod}/{@code destroyMethod}.</p>
 */
@Slf4j
public class TrustStoreScheduler {

    private final TrustStoreService trustStoreService;
    private final long intervalMillis;
    private ScheduledExecutorService executor;

    public TrustStoreScheduler(TrustStoreService trustStoreService, TrustStoreConfig trustStoreConfig) {
        this.trustStoreService = trustStoreService;
        this.intervalMillis = trustStoreConfig.getRefreshIntervalMillis();
    }

    /**
     * Inicia o agendamento periódico (chamado pelo container como {@code initMethod}).
     */
    public void start() {
        executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "icpbrasil-truststore-scheduler");
            thread.setDaemon(true);
            return thread;
        });
        executor.scheduleAtFixedRate(this::scheduleRefresh, intervalMillis, intervalMillis, TimeUnit.MILLISECONDS);
        log.info("Agendador do trust store iniciado (intervalo: {} ms)", intervalMillis);
    }

    /**
     * Encerra o agendamento (chamado pelo container como {@code destroyMethod}).
     */
    public void stop() {
        if (executor != null) {
            executor.shutdownNow();
            log.info("Agendador do trust store encerrado");
        }
    }

    void scheduleRefresh() {
        try {
            log.info("Executando atualização agendada do TrustStore");
            trustStoreService.refresh();
        } catch (Exception e) {
            // scheduleAtFixedRate cancela execuções futuras se a tarefa lançar exceção;
            // capturamos aqui para garantir que uma falha pontual não mate o agendamento
            log.error("Falha na atualização agendada do trust store", e);
        }
    }
}
