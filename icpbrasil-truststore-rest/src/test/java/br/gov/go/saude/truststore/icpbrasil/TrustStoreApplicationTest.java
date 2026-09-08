package br.gov.go.saude.truststore.icpbrasil;

import br.gov.go.saude.truststore.icpbrasil.config.S3Properties;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreCacheHealthIndicator;
import br.gov.go.saude.truststore.icpbrasil.repository.S3Repository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.util.ReflectionTestUtils;
import software.amazon.awssdk.services.s3.S3Client;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustStoreApplicationTest {

    @Test
    @SneakyThrows
    void testDefaultsCore_CoincidemComYamlStandalone() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        new YamlPropertySourceLoader().load("standalone", new ClassPathResource("application.yaml"))
                .forEach(environment.getPropertySources()::addLast);
        TrustStoreConfig bound = Binder.get(environment)
                .bind("icpbrasil-truststore", Bindable.of(TrustStoreConfig.class)).get();
        assertEquals(new TrustStoreConfig(), bound);
    }

    @Test
    void testStandalone_ScanEAutoConfiguracaoS3_NaoDuplicamBeans() {
        new ApplicationContextRunner().withUserConfiguration(TrustStoreApplication.class)
                .withPropertyValues("icpbrasil-truststore.bootstrap.enabled=false",
                        "icpbrasil-truststore.scheduling.enabled=false",
                        "icpbrasil-truststore.storage.type=s3",
                        "icpbrasil-truststore.s3.endpoint=https://s3.example.invalid",
                        "icpbrasil-truststore.s3.region=us-east-1",
                        "icpbrasil-truststore.s3.access-key=fictitious-access-key",
                        "icpbrasil-truststore.s3.secret-key=fictitious-secret-key",
                        "icpbrasil-truststore.s3.bucket=test-bucket")
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertEquals(1, context.getBeansOfType(TrustStoreAutoConfiguration.class).size());
                    assertEquals(1, context.getBeansOfType(S3Client.class).size());
                    assertEquals(1, context.getBeansOfType(S3Properties.class).size());
                    assertEquals(1, context.getBeansOfType(TrustStoreRepository.class).size());
                    assertEquals(1, context.getBeansOfType(TrustStoreCacheHealthIndicator.class).size());
                    assertInstanceOf(S3Repository.class, context.getBean(TrustStoreRepository.class));
                });
    }

    @Test
    void testStandalone_ClienteCustomizado_ScanNaoAntecipaFactory() {
        S3Client client = mock(S3Client.class);
        new ApplicationContextRunner().withUserConfiguration(TrustStoreApplication.class)
                .withBean(S3Client.class, () -> client)
                .withPropertyValues("icpbrasil-truststore.bootstrap.enabled=false",
                        "icpbrasil-truststore.scheduling.enabled=false",
                        "icpbrasil-truststore.storage.type=s3",
                        "icpbrasil-truststore.s3.endpoint=https://s3.example.invalid",
                        "icpbrasil-truststore.s3.region=us-east-1",
                        "icpbrasil-truststore.s3.access-key=fictitious-access-key",
                        "icpbrasil-truststore.s3.secret-key=fictitious-secret-key",
                        "icpbrasil-truststore.s3.bucket=test-bucket",
                        "icpbrasil-truststore.s3.ca-cert-path=file:/inexistente.pem")
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertEquals(1, context.getBeansOfType(S3Client.class).size());
                    assertSame(client, context.getBean(S3Client.class));
                    assertSame(client, ReflectionTestUtils.getField(context.getBean(TrustStoreRepository.class),
                            "s3Client"));
                    verifyNoInteractions(client);
                });
    }
}
