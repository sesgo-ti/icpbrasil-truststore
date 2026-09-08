package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import lombok.SneakyThrows;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import static org.junit.jupiter.api.Assertions.*;

/** Executa o contrato em um classloader sem acesso aos JARs opcionais. */
public class IsolatedContextScenario {

    /** Verifica descoberta via AutoConfiguration.imports e binding do YAML minimo. */
    @SneakyThrows
    public static void run(String baseDir) {
        var yaml = new YamlPropertySourceLoader().load("minimo", new ClassPathResource("minimal.yaml"));
        var runner = new ApplicationContextRunner().withUserConfiguration(Consumer.class)
                .withInitializer(context -> yaml.forEach(context.getEnvironment().getPropertySources()::addLast))
                .withPropertyValues("icpbrasil-truststore.bootstrap.enabled=false",
                        "icpbrasil-truststore.scheduling.enabled=false",
                        "icpbrasil-truststore.filesystem.base-dir=" + baseDir);
        runner.run(context -> {
            assertNull(context.getStartupFailure());
            assertNotNull(context.getBean(TrustStoreService.class));
            assertInstanceOf(FilesystemTrustStoreRepository.class, context.getBean(TrustStoreRepository.class));
            assertEquals(60, context.getBean(TrustStoreConfig.class).getNetwork().getDownloadTimeoutSeconds());
            assertFalse(context.containsBean("s3Client"));
            assertFalse(context.containsBean("trustStoreCacheHealthIndicator"));
            assertFalse(context.containsBean("trustStoreBootstrap"));
            assertFalse(context.containsBean("trustStoreScheduler"));
        });
        runner.withPropertyValues("icpbrasil-truststore.storage.type=s3").run(context -> {
            Throwable failure = context.getStartupFailure();
            assertNotNull(failure);
            while (failure.getCause() != null) {
                failure = failure.getCause();
            }
            assertInstanceOf(IllegalStateException.class, failure);
            assertTrue(failure.getMessage().contains("software.amazon.awssdk:s3"));
        });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    static class Consumer {
    }
}
