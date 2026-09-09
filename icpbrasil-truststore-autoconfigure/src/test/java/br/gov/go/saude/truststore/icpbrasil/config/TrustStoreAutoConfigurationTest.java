package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.lifecycle.TrustStoreCacheHealthIndicator;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.S3Repository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.service.provider.CertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.service.provider.TrustedCertsProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.s3.S3Client;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Testes de contrato da auto-configuração: contexto sobe com configuração mínima
 * válida e falha rápido (fail-fast) com mensagem apontando a propriedade exata
 * quando uma configuração obrigatória está ausente ou inválida.
 */
class TrustStoreAutoConfigurationTest {

    /**
     * Configuração mínima documentada no README para o modo biblioteca, mais o desligamento
     * de bootstrap/scheduler para o teste não acessar a rede. Tudo o mais vem dos defaults.
     */
    private static String[] propsMinimasDoReadme(Path baseDir) {
        return new String[] {
                "icpbrasil-truststore.storage.type=filesystem",
                "icpbrasil-truststore.filesystem.base-dir=" + baseDir,
                "icpbrasil-truststore.bootstrap.enabled=false",
                "icpbrasil-truststore.scheduling.enabled=false",
        };
    }

    /** Conjunto explícito de propriedades (storage filesystem), independente dos defaults. */
    private static final String[] PROPS_MINIMAS = {
            "icpbrasil-truststore.certificate-url=https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip",
            "icpbrasil-truststore.hash-url=https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt",
            "icpbrasil-truststore.network.download-timeout-seconds=30",
            "icpbrasil-truststore.network.max-retries=3",
            "icpbrasil-truststore.network.retry-interval-seconds=10",
            "icpbrasil-truststore.cache-ttl-critical-hours=72",
            "icpbrasil-truststore.cache-ttl-max-hours=168",
            "icpbrasil-truststore.refresh-interval-hours=1",
            "icpbrasil-truststore.storage.type=filesystem",
            "icpbrasil-truststore.storage.truststore-archive-path=ACcompactado.zip",
            "icpbrasil-truststore.storage.hash-file-path=hash.txt",
            "icpbrasil-truststore.storage.confirmation-file-path=confirmacao.txt",
            "icpbrasil-truststore.filesystem.base-dir=target/test-truststore",
            "icpbrasil-truststore.trusted-certs.dir=classpath:registries/certificates",
            "icpbrasil-truststore.bootstrap.enabled=false",
            "icpbrasil-truststore.scheduling.enabled=false",
    };

    private static final String[] PROPS_S3 = {
            "icpbrasil-truststore.storage.type=s3",
            "icpbrasil-truststore.s3.endpoint=https://s3.exemplo.invalid",
            "icpbrasil-truststore.s3.region=us-east-1",
            "icpbrasil-truststore.s3.access-key=teste-access-key",
            "icpbrasil-truststore.s3.secret-key=teste-secret-key",
            "icpbrasil-truststore.s3.bucket=bucket-teste",
    };

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            // ConfigurationProperties/ValidationAutoConfiguration fornecem a infraestrutura
            // de binding e Bean Validation que numa aplicação Boot real está sempre presente
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    ValidationAutoConfiguration.class,
                    TrustStoreAutoConfiguration.class));

    @Test
    void testContexto_ComConfigMinimaFilesystem_SobeComBeansPrincipais() {
        runner.withPropertyValues(PROPS_MINIMAS).run(context -> {
            assertNull(context.getStartupFailure());
            assertNotNull(context.getBean(TrustStoreConfig.class));
            assertNotNull(context.getBean(TrustStoreService.class));
            assertInstanceOf(FilesystemTrustStoreRepository.class, context.getBean(TrustStoreRepository.class));
            assertEquals(1, context.getBeansOfType(CertificateHttpTransport.class).size(),
                    "AIA, OCSP e CRL compartilham um único transporte HTTP");
        });
    }

    @Test
    void testContexto_ConfigMinimaDoReadmeSemAwsNemActuator_SobeComDefaults(@TempDir Path baseDir) {
        runner.withClassLoader(new FilteredClassLoader(S3Client.class, HealthIndicator.class))
                .withPropertyValues(propsMinimasDoReadme(baseDir))
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    TrustStoreConfig config = context.getBean(TrustStoreConfig.class);
                    assertTrue(config.getCertificateUrl().startsWith("https://acraiz.icpbrasil.gov.br/"));
                    assertEquals(2, config.getRefreshIntervalHours());
                    assertEquals(72, config.getCacheTtlCriticalHours());
                    assertEquals(168, config.getCacheTtlMaxHours());
                    assertEquals("classpath:registries/certificates", config.getTrustedCerts().getDir());
                    assertNotNull(context.getBean(TrustStoreService.class));
                    assertInstanceOf(FilesystemTrustStoreRepository.class, context.getBean(TrustStoreRepository.class));
                    assertFalse(context.containsBean("trustStoreCacheHealthIndicator"));
                    assertFalse(context.containsBean("s3Repository"));
                    assertFalse(context.containsBean("s3Client"));
                });
    }

    @Test
    void testContexto_StorageS3SemAwsSdk_FalhaCitandoDependencias(@TempDir Path baseDir) {
        runner.withClassLoader(new FilteredClassLoader(S3Client.class))
                .withPropertyValues(substituir(propsMinimasDoReadme(baseDir), "icpbrasil-truststore.storage.type=s3"))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagemRaiz(context.getStartupFailure()).contains("software.amazon.awssdk:s3"));
                });
    }

    @Test
    void testContexto_StorageS3ComS3ClientDoConsumidor_UsaBeanFornecido(@TempDir Path baseDir) {
        runner.withUserConfiguration(S3ClientCustomizado.class)
                .withPropertyValues(concatenar(propsMinimasDoReadme(baseDir), PROPS_S3))
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertInstanceOf(S3Repository.class, context.getBean(TrustStoreRepository.class));
                    assertEquals(1, context.getBeanNamesForType(S3Client.class).length);
                    assertSame(context.getBean(S3ClientCustomizado.class).client, context.getBean(S3Client.class));
                });
    }

    @Test
    void testContexto_StorageS3SemBeanDoConsumidor_CriaS3ClientPadrao(@TempDir Path baseDir) {
        runner.withPropertyValues(concatenar(propsMinimasDoReadme(baseDir), PROPS_S3))
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertTrue(context.containsBean("s3Client"));
                    assertInstanceOf(S3Repository.class, context.getBean(TrustStoreRepository.class));
                });
    }

    @Test
    void testContexto_ComActuatorNoClasspath_RegistraHealthIndicator(@TempDir Path baseDir) {
        runner.withPropertyValues(propsMinimasDoReadme(baseDir)).run(context -> {
            assertNull(context.getStartupFailure());
            assertNotNull(context.getBean(TrustStoreCacheHealthIndicator.class));
        });
    }

    /**
     * Guarda estrutural do isolamento: a classe principal não pode referenciar tipos das
     * dependências opcionais em assinaturas, senão a introspecção dos métodos {@code @Bean}
     * falha quando elas estão ausentes — algo que o FilteredClassLoader não reproduz, pois
     * a própria classe já está carregada pelo class loader da aplicação.
     */
    @Test
    void testAutoConfiguration_NaoReferenciaTiposOpcionaisEmAssinaturas() {
        for (Method metodo : TrustStoreAutoConfiguration.class.getDeclaredMethods()) {
            assertTipoNaoOpcional(metodo.getReturnType(), metodo);
            for (Class<?> parametro : metodo.getParameterTypes()) {
                assertTipoNaoOpcional(parametro, metodo);
            }
        }
    }

    private static void assertTipoNaoOpcional(Class<?> tipo, Method metodo) {
        String nome = tipo.getName();
        assertFalse(nome.startsWith("software.amazon.") || nome.startsWith("org.springframework.boot.actuate."),
                "Tipo opcional " + nome + " exposto na assinatura de " + metodo.getName());
    }

    @Test
    void testContexto_CertificateUrlVazia_FalhaComMensagemDaPropriedade() {
        runner.withPropertyValues(substituir(PROPS_MINIMAS, "icpbrasil-truststore.certificate-url="))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    String causa = mensagemRaiz(context.getStartupFailure());
                    assertTrue(causa.contains("icpbrasil-truststore.certificate-url"),
                            "Mensagem deve apontar a propriedade inválida. Recebido: " + causa);
                });
    }

    @Test
    void testContexto_ComCertificateUrlHttp_FalhaExigindoHttps() {
        runner.withPropertyValues(substituir(PROPS_MINIMAS,
                        "icpbrasil-truststore.certificate-url=http://acraiz.icpbrasil.gov.br/x.zip"))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagemRaiz(context.getStartupFailure()).contains("HTTPS"));
                });
    }

    @Test
    void testContexto_TrustedCertsDirVazio_FalhaComMensagemDaPropriedade() {
        runner.withPropertyValues(substituir(PROPS_MINIMAS, "icpbrasil-truststore.trusted-certs.dir="))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagemRaiz(context.getStartupFailure())
                            .contains("icpbrasil-truststore.trusted-certs.dir"));
                });
    }

    @Test
    void testContexto_SemFilesystemBaseDir_FalhaComMensagemDaPropriedade() {
        runner.withPropertyValues(remover(PROPS_MINIMAS, "icpbrasil-truststore.filesystem.base-dir"))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagemRaiz(context.getStartupFailure())
                            .contains("icpbrasil-truststore.filesystem.base-dir"));
                });
    }

    @Test
    void testContexto_StorageS3SemPropriedadesS3_FalhaNoBinding() {
        runner.withPropertyValues(substituir(PROPS_MINIMAS, "icpbrasil-truststore.storage.type=s3"))
                .run(context -> assertNotNull(context.getStartupFailure(),
                        "storage.type=s3 sem icpbrasil-truststore.s3.* deve impedir o startup"));
    }

    @Test
    void testContexto_ConsumidorSobrescreveProvider_NaoDuplicaBean() {
        runner.withUserConfiguration(ProviderCustomizado.class)
                .withPropertyValues(PROPS_MINIMAS)
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertSame(context.getBean(ProviderCustomizado.class).provider,
                            context.getBean("trustedCertsProvider"));
                });
    }

    @Test
    void testContexto_BootstrapDesabilitado_NaoRegistraBeanDeBootstrap() {
        runner.withPropertyValues(PROPS_MINIMAS).run(context ->
                assertFalse(context.containsBean("trustStoreBootstrap")));
    }

    @Configuration
    static class ProviderCustomizado {
        // Provider real com um certificado do classpath: o TrustStoreManager
        // rejeita providers sem certificados, então um stub vazio não serve.
        CertificateProvider provider = new TrustedCertsProvider(
                List.of(lerRecurso("registries/certificates/isrgrootx1.json")));

        @Bean
        CertificateProvider trustedCertsProvider() {
            return provider;
        }

        private static byte[] lerRecurso(String nome) {
            try (InputStream is = ProviderCustomizado.class.getClassLoader().getResourceAsStream(nome)) {
                if (is == null) {
                    throw new IllegalStateException("Recurso de teste não encontrado: " + nome);
                }
                return is.readAllBytes();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    @Configuration
    static class S3ClientCustomizado {
        S3Client client = mock(S3Client.class);

        @Bean
        S3Client s3ClientDoConsumidor() {
            return client;
        }
    }

    private static String[] remover(String[] props, String chave) {
        return Arrays.stream(props)
                .filter(p -> !p.startsWith(chave + "="))
                .toArray(String[]::new);
    }

    private static String[] substituir(String[] props, String novaEntrada) {
        String chave = novaEntrada.substring(0, novaEntrada.indexOf('='));
        String[] sem = remover(props, chave);
        String[] resultado = Arrays.copyOf(sem, sem.length + 1);
        resultado[sem.length] = novaEntrada;
        return resultado;
    }

    /** Concatena entradas; as de {@code extras} substituem chaves repetidas de {@code base}. */
    private static String[] concatenar(String[] base, String[] extras) {
        String[] resultado = base;
        for (String extra : extras) {
            resultado = substituir(resultado, extra);
        }
        return resultado;
    }

    /** Percorre a cadeia de causas e retorna a mensagem mais específica. */
    private static String mensagemRaiz(Throwable t) {
        Throwable atual = t;
        StringBuilder mensagens = new StringBuilder();
        while (atual != null) {
            if (atual.getMessage() != null) {
                mensagens.append(atual.getMessage()).append(" | ");
            }
            atual = atual.getCause();
        }
        return mensagens.toString();
    }
}
