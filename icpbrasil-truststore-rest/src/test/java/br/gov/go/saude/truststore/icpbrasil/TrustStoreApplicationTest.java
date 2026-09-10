package br.gov.go.saude.truststore.icpbrasil;

import br.gov.go.saude.truststore.icpbrasil.config.IcpBrasilEndpoints;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreCacheHealthIndicator;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * O standalone faz component scan no mesmo pacote da auto-configuração: este teste garante
 * que as configurações importadas por ela não são registradas em duplicidade pelo scan.
 * Bootstrap e agendamento ficam desligados para não acessar a rede.
 */
@SpringBootTest(properties = {
        "icpbrasil-truststore.bootstrap.enabled=false",
        "icpbrasil-truststore.scheduling.enabled=false",
        "icpbrasil-truststore.filesystem.base-dir=target/test-truststore-rest",
})
class TrustStoreApplicationTest {

    @Autowired
    ApplicationContext context;

    @Test
    void testContexto_ComponentScanEAutoConfiguracao_NaoDuplicamBeans() {
        assertEquals(1, context.getBeanNamesForType(TrustStoreService.class).length);
        assertEquals(1, context.getBeanNamesForType(TrustStoreRepository.class).length);
        assertInstanceOf(FilesystemTrustStoreRepository.class, context.getBean(TrustStoreRepository.class));
        assertEquals(1, context.getBeanNamesForType(TrustStoreCacheHealthIndicator.class).length);
        assertNotNull(context.getBean("trustStoreCacheHealthIndicator"));
    }

    /** O application.yaml do serviço não repete as URLs do ITI: elas vêm dos defaults da biblioteca. */
    @Test
    void testConfig_UrlsDoIti_VemDosDefaultsDaBiblioteca() {
        TrustStoreConfig config = context.getBean(TrustStoreConfig.class);

        assertEquals(IcpBrasilEndpoints.BUNDLE_ZIP_URL, config.getCertificateUrl());
        assertEquals(IcpBrasilEndpoints.BUNDLE_HASH_URL, config.getHashUrl());
    }
}
