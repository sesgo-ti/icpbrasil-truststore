package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreCacheHealthIndicator;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.S3Repository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.service.provider.CertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.TrustedCertsProvider;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.util.ReflectionTestUtils;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

class TrustStoreAutoConfigurationTest {

    private static final String[] PROPS_S3 = {
            "icpbrasil-truststore.storage.type=s3",
            "icpbrasil-truststore.s3.endpoint=https://s3.example.invalid",
            "icpbrasil-truststore.s3.region=us-east-1",
            "icpbrasil-truststore.s3.access-key=fictitious-access-key",
            "icpbrasil-truststore.s3.secret-key=fictitious-secret-key",
            "icpbrasil-truststore.s3.bucket=test-bucket"
    };

    @TempDir
    Path tempDir;

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(TrustStoreAutoConfiguration.class))
                .withPropertyValues("icpbrasil-truststore.bootstrap.enabled=false",
                        "icpbrasil-truststore.scheduling.enabled=false",
                        "icpbrasil-truststore.filesystem.base-dir=" + tempDir);
    }

    @Test
    void testContexto_ComDefaultsFilesystem_SobeComBeansPrincipais() {
        runner().run(context -> {
            assertNull(context.getStartupFailure());
            assertNotNull(context.getBean(TrustStoreConfig.class));
            assertNotNull(context.getBean(TrustStoreService.class));
            assertInstanceOf(FilesystemTrustStoreRepository.class, context.getBean(TrustStoreRepository.class));
            assertEquals(1, context.getBeansOfType(TrustStoreCacheHealthIndicator.class).size());
            assertFalse(context.containsBean("trustStoreBootstrap"));
            assertFalse(context.containsBean("trustStoreScheduler"));
            assertTrue(context.getBeansOfType(S3Client.class).isEmpty());
            assertTrue(context.getBeansOfType(S3Properties.class).isEmpty());
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"software.amazon.awssdk", "org.springframework.boot.actuate", "ambos"})
    void testContexto_ClasspathFiltrado_SobeSemOpcionais(String pacote) {
        String[] pacotes = pacote.equals("ambos")
                ? new String[]{"software.amazon.awssdk", "org.springframework.boot.actuate"}
                : new String[]{pacote};
        runner().withClassLoader(new FilteredClassLoader(pacotes)).run(context -> {
            assertNull(context.getStartupFailure());
            assertNotNull(context.getBean(TrustStoreService.class));
            assertInstanceOf(FilesystemTrustStoreRepository.class, context.getBean(TrustStoreRepository.class));
            assertEquals(pacote.equals("software.amazon.awssdk"),
                    context.containsBean("trustStoreCacheHealthIndicator"));
            assertFalse(context.containsBean("s3Client"));
        });
    }

    @Test
    @SneakyThrows
    void testContexto_ClassLoaderIsoladoSemAwsActuator_DescobreAutoConfiguracaoComYamlMinimo() {
        // FilteredClassLoader filtra condições, mas classes delegadas ao parent ainda
        // podem resolver tipos opcionais. Aqui nem Spring nem a biblioteca usam esse parent.
        URL[] urls = Arrays.stream(System.getProperty("surefire.test.class.path").split(File.pathSeparator))
                .filter(path -> !path.contains("/software/amazon/awssdk/"))
                .filter(path -> !path.contains("/spring-boot-actuator"))
                .map(Path::of).map(TrustStoreAutoConfigurationTest::url).toArray(URL[]::new);
        try (URLClassLoader loader = new URLClassLoader(urls, ClassLoader.getPlatformClassLoader())) {
            assertThrows(ClassNotFoundException.class,
                    () -> loader.loadClass("software.amazon.awssdk.services.s3.S3Client"));
            assertThrows(ClassNotFoundException.class,
                    () -> loader.loadClass("org.springframework.boot.actuate.health.HealthIndicator"));
            ClassLoader previous = Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(loader);
                loader.loadClass("br.gov.go.saude.truststore.icpbrasil.config.IsolatedContextScenario")
                        .getMethod("run", String.class).invoke(null, tempDir.toString());
            } finally {
                Thread.currentThread().setContextClassLoader(previous);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "certificate-url=", "certificate-url=http://example.invalid/x.zip", "hash-url=",
            "hash-url=http://example.invalid/hash.txt", "trusted-certs.dir=", "filesystem.base-dir=",
            "storage.truststore-archive-path=", "storage.hash-file-path=", "storage.confirmation-file-path=",
            "network.download-timeout-seconds=29", "network.download-timeout-seconds=301",
            "network.max-retries=0", "network.max-retries=11",
            "network.retry-interval-seconds=9", "network.retry-interval-seconds=301",
            "cache-ttl-critical-hours=23", "cache-ttl-critical-hours=169",
            "cache-ttl-max-hours=71", "cache-ttl-max-hours=721", "cache-ttl-max-hours=72",
            "refresh-interval-hours=0", "refresh-interval-hours=73",
            "chain.download-timeout-seconds=0", "revocation.ocsp-timeout-seconds=0",
            "download-policy.max-aia-response-bytes=0", "bundle.max-entries=0"
    })
    void testContexto_ValorExplicitamenteInvalido_FalhaComPropriedade(String propriedade) {
        runner().withPropertyValues("icpbrasil-truststore." + propriedade).run(context -> {
            assertNotNull(context.getStartupFailure());
            String chave = propriedade.substring(0, propriedade.indexOf('='));
            if (chave.startsWith("bundle.")) {
                chave = "bundle";
            }
            assertTrue(mensagens(context.getStartupFailure()).contains(chave));
        });
    }

    @Test
    void testContexto_StorageS3SemSdk_FalhaComDiagnostico() {
        runner().withClassLoader(new FilteredClassLoader("software.amazon.awssdk"))
                .withPropertyValues("icpbrasil-truststore.storage.type=s3").run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagens(context.getStartupFailure()).contains("software.amazon.awssdk:s3"));
                    assertFalse(mensagens(context.getStartupFailure()).contains("NoClassDefFoundError"));
                });
    }

    @Test
    void testContexto_StorageS3SemApache_FalhaComDiagnostico() {
        runner().withClassLoader(new FilteredClassLoader("software.amazon.awssdk.http.apache"))
                .withPropertyValues(PROPS_S3).run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagens(context.getStartupFailure()).contains("software.amazon.awssdk:apache-client"));
                });
    }

    @Test
    void testContexto_StorageS3SemPropriedades_FalhaNoBinding() {
        runner().withPropertyValues("icpbrasil-truststore.storage.type=s3").run(context -> {
            assertNotNull(context.getStartupFailure());
            assertTrue(mensagens(context.getStartupFailure()).contains("S3 bucket must be provided"));
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"endpoint", "region", "access-key", "secret-key", "bucket"})
    void testContexto_PropriedadeS3Vazia_ContinuaObrigatoria(String propriedade) {
        runner().withPropertyValues(PROPS_S3)
                .withPropertyValues("icpbrasil-truststore.s3." + propriedade + "=")
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagens(context.getStartupFailure()).contains("must be provided"));
                });
    }

    @Test
    void testContexto_StorageS3_CriaClienteEConectaRepositorioSemRede() {
        runner().withPropertyValues(PROPS_S3).run(context -> {
            assertNull(context.getStartupFailure());
            assertEquals(1, context.getBeansOfType(S3Client.class).size());
            S3Client client = context.getBean(S3Client.class);
            assertEquals(Region.US_EAST_1, client.serviceClientConfiguration().region());
            assertEquals("https://s3.example.invalid",
                    client.serviceClientConfiguration().endpointOverride().orElseThrow().toString());
            TrustStoreRepository repository = context.getBean(TrustStoreRepository.class);
            assertInstanceOf(S3Repository.class, repository);
            assertSame(client, ReflectionTestUtils.getField(repository, "s3Client"));
            assertSame(repository, ReflectionTestUtils.getField(context.getBean(TrustStoreService.class),
                    "repository"));
            assertFalse(context.containsBean("filesystemTrustStoreRepository"));
        });
    }

    @Test
    void testContexto_ClienteS3CustomizadoSemApache_RespeitaBeanEUsaBucketConfigurado() {
        S3Client client = mock(S3Client.class);
        runner().withClassLoader(new FilteredClassLoader("software.amazon.awssdk.http.apache"))
                .withBean(S3Client.class, () -> client).withPropertyValues(PROPS_S3)
                .withPropertyValues("icpbrasil-truststore.s3.ca-cert-path=file:/inexistente.pem")
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertEquals(1, context.getBeansOfType(S3Client.class).size());
                    assertSame(client, context.getBean(S3Client.class));
                    verifyNoInteractions(client);
                    context.getBean(TrustStoreRepository.class).armazenarHash("hash-ficticio");
                    verify(client).putObject(argThat((PutObjectRequest request) ->
                            request.bucket().equals("test-bucket") && request.key().equals("hash.txt")),
                            any(RequestBody.class));
                });
    }

    @Test
    void testContexto_ConsumidorSobrescreveProvider_NaoDuplicaBean() {
        runner().withUserConfiguration(ProviderCustomizado.class).run(context -> {
            assertNull(context.getStartupFailure());
            assertSame(context.getBean(ProviderCustomizado.class).provider, context.getBean("trustedCertsProvider"));
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class ProviderCustomizado {
        CertificateProvider provider = new TrustedCertsProvider(
                List.of(lerRecurso("registries/certificates/isrgrootx1.json")));

        @Bean
        CertificateProvider trustedCertsProvider() {
            return provider;
        }

        @SneakyThrows
        private static byte[] lerRecurso(String nome) {
            try (var is = ProviderCustomizado.class.getClassLoader().getResourceAsStream(nome)) {
                assertNotNull(is);
                return is.readAllBytes();
            }
        }
    }

    @SneakyThrows
    private static URL url(Path path) {
        return path.toUri().toURL();
    }

    private static String mensagens(Throwable falha) {
        StringBuilder mensagens = new StringBuilder();
        for (Throwable atual = falha; atual != null; atual = atual.getCause()) {
            mensagens.append(atual.getMessage()).append(" | ");
        }
        return mensagens.toString();
    }
}
