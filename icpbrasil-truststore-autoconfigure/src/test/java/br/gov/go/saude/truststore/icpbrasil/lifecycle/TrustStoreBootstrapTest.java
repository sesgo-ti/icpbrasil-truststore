package br.gov.go.saude.truststore.icpbrasil.lifecycle;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TrustStoreBootstrapTest {

    private TrustStoreService service;
    private TrustStoreConfig config;
    private TrustStoreConfig.BootstrapConfig bootstrap;
    private TrustStoreBootstrap bootstrapRunner;

    @BeforeEach
    void setUp() {
        service = mock(TrustStoreService.class);
        config = new TrustStoreConfig();
        bootstrap = new TrustStoreConfig.BootstrapConfig();
        config.setBootstrap(bootstrap);
        bootstrapRunner = new TrustStoreBootstrap(service, config);
        // Validade do cache é lida via TrustStoreService (mock) — sem estado estático a limpar
        when(service.isCacheValid()).thenReturn(false);
    }

    @SneakyThrows
    @Test
    void testRun_BootstrapDesabilitado_NaoChamaService() {
        bootstrap.setEnabled(false);

        bootstrapRunner.run(new DefaultApplicationArguments());

        verify(service, never()).refresh();
    }

    @SneakyThrows
    @Test
    void testRun_CargaBemSucedida_NaoLancaExcecao() {
        doNothing().when(service).refresh();
        when(service.isCacheValid()).thenReturn(true);

        assertDoesNotThrow(() -> bootstrapRunner.run(new DefaultApplicationArguments()));
        verify(service).refresh();
    }

    @SneakyThrows
    @Test
    void testRun_CacheInvalidoAposRefreshComFailFast_LancaIllegalStateException() {
        bootstrap.setFailFast(true);
        doNothing().when(service).refresh();

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> bootstrapRunner.run(new DefaultApplicationArguments()));
        assertTrue(ex.getMessage().toLowerCase().contains("bootstrap"));
    }

    @SneakyThrows
    @Test
    void testRun_CacheInvalidoAposRefreshSemFailFast_LogaErroESegue() {
        bootstrap.setFailFast(false);
        doNothing().when(service).refresh();

        assertDoesNotThrow(() -> bootstrapRunner.run(new DefaultApplicationArguments()));
        verify(service).refresh();
    }

    @SneakyThrows
    @Test
    void testRun_ServiceLancandoExcecaoComFailFast_PropagaIllegalStateException() {
        bootstrap.setFailFast(true);
        doThrow(new RuntimeException("rede indisponível")).when(service).refresh();

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> bootstrapRunner.run(new DefaultApplicationArguments()));
        assertNotNull(ex.getCause());
    }

    @SneakyThrows
    @Test
    void testRun_ServiceLancandoExcecaoSemFailFast_NaoPropaga() {
        bootstrap.setFailFast(false);
        doThrow(new RuntimeException("rede indisponível")).when(service).refresh();

        assertDoesNotThrow(() -> bootstrapRunner.run(new DefaultApplicationArguments()));
    }
}
