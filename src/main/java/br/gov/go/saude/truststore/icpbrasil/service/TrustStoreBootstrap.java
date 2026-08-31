package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Garante que o cache ICP-Brasil esteja carregado antes de o Spring Boot
 * declarar o contexto "Started" — eliminando a race condition entre o startup
 * e a primeira execução do scheduler.
 *
 * <p>Implementa {@link ApplicationRunner}, que é executado de forma síncrona
 * imediatamente antes de {@code SpringApplication.run()} retornar. Qualquer
 * exceção propagada daqui aborta o startup.</p>
 *
 * <p>Comportamento controlado por {@code truststore-icpbrasil.bootstrap.*}:</p>
 * <ul>
 *   <li>{@code enabled} (padrão {@code true}): quando {@code false}, desabilita o bootstrap por completo —
 *       o bean não é registrado e o cache só será populado na primeira execução do scheduler.</li>
 *   <li>{@code fail-fast} (padrão {@code true}): se a carga falhar, aborta o startup.</li>
 * </ul>
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(
        prefix = "truststore-icpbrasil.bootstrap",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
public class TrustStoreBootstrap implements ApplicationRunner {

    private final TrustStoreService trustStoreService;
    private final TrustStoreConfig trustStoreConfig;

    public TrustStoreBootstrap(TrustStoreService trustStoreService, TrustStoreConfig trustStoreConfig) {
        this.trustStoreService = trustStoreService;
        this.trustStoreConfig = trustStoreConfig;
    }

    @Override
    public void run(ApplicationArguments args) {
        TrustStoreConfig.BootstrapConfig bootstrap = trustStoreConfig.getBootstrap();

        if (bootstrap != null && !bootstrap.isEnabled()) {
            log.info("Bootstrap síncrono desabilitado — cache será populado apenas pelo scheduler");
            return;
        }

        boolean failFast = bootstrap == null || bootstrap.isFailFast();
        log.info("Iniciando bootstrap síncrono do trust store ICP-Brasil (fail-fast={})", failFast);
        long inicio = System.currentTimeMillis();

        try {
            trustStoreService.refresh();
        } catch (Exception e) {
            String msg = "Falha na carga inicial do trust store ICP-Brasil durante o bootstrap";
            if (failFast) {
                throw new IllegalStateException(msg + " — abortando startup", e);
            }
            log.error("{} — aplicação subirá com cache indisponível (fail-fast=false)", msg, e);
            return;
        }

        if (!Cache.isCacheValid()) {
            String msg = "Bootstrap concluído mas o cache permaneceu inválido (download ou validação falhou)";
            if (failFast) {
                throw new IllegalStateException(msg + " — abortando startup");
            }
            log.error("{} — aplicação subirá com cache indisponível (fail-fast=false)", msg);
            return;
        }

        long duracao = System.currentTimeMillis() - inicio;
        log.info("Bootstrap síncrono concluído com sucesso em {} ms", duracao);
    }
}
