package br.gov.go.saude.truststore.icpbrasil.lifecycle;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

/**
 * Tenta carregar o cache antes do ApplicationReadyEvent e do retorno de SpringApplication.run().
 * O servidor HTTP e outros beans podem operar antes deste runner: consumidores devem
 * respeitar readiness e tratar acervo indisponivel, inclusive em inicializadores de beans.
 *
 * <p>Implementa {@link ApplicationRunner}, que é executado de forma síncrona
 * durante o startup, sem barreira global de requisicoes. Qualquer exceção propagada
 * daqui aborta o startup, mas nao desfaz requisicoes ja atendidas.</p>
 *
 * <p>Comportamento controlado por {@code icpbrasil-truststore.bootstrap.*}:</p>
 * <ul>
 *   <li>{@code enabled} (padrão {@code true}): quando {@code false}, desabilita o bootstrap por completo —
 *       o bean não é registrado; a carga depende do scheduler ou de refresh explicito.</li>
 *   <li>{@code fail-fast} (padrão {@code true}): se o cache continuar invalido, aborta o startup.</li>
 * </ul>
 */
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
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
            log.info("Bootstrap síncrono desabilitado; carga depende de refresh agendado ou explicito");
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

        if (!trustStoreService.isCacheValid()) {
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
