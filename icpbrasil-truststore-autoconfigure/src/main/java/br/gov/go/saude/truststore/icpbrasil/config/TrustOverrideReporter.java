package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.http.TrustStoreManager;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Avisa quando a aplicação substitui um bean que decide em quem a biblioteca confia: configuração
 * nunca altera a confiança, mas código do consumidor pode, e isso deve ficar visível no log.
 *
 * <p>A detecção é feita nas definições de bean, sem instanciá-los: um bean cuja fábrica não seja
 * {@link TrustStoreAutoConfiguration} foi registrado pela aplicação.</p>
 */
@Slf4j
class TrustOverrideReporter implements SmartInitializingSingleton {

    // Downloader e CertificateHttpTransport carregam a confiança do canal (SSLContext e política de destino).
    static final List<Class<?>> TIPOS_DE_CONFIANCA = List.of(
            TrustStoreManager.class, TrustMaterialSource.class,
            Downloader.class, CertificateHttpTransport.class);

    private final ConfigurableListableBeanFactory beanFactory;

    TrustOverrideReporter(ConfigurableListableBeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    @Override
    public void afterSingletonsInstantiated() {
        substituidos().forEach(tipo -> log.warn(
                "{} substituído pela aplicação: a confiança em uso não é a padrão da biblioteca", tipo));
    }

    /** Nomes simples dos tipos de confiança com ao menos um bean não registrado pela auto-configuração. */
    List<String> substituidos() {
        List<String> tipos = new ArrayList<>();
        for (Class<?> tipo : TIPOS_DE_CONFIANCA) {
            for (String nome : beanFactory.getBeanNamesForType(tipo, true, false)) {
                // Singleton registrado manualmente não tem definição: só pode ter vindo da aplicação.
                if (!beanFactory.containsBeanDefinition(nome)) {
                    tipos.add(tipo.getSimpleName());
                    continue;
                }
                String fabrica = beanFactory.getBeanDefinition(nome).getFactoryBeanName();
                if (!TrustStoreAutoConfiguration.class.getName().equals(fabrica)) {
                    tipos.add(tipo.getSimpleName());
                }
            }
        }
        return tipos;
    }
}
