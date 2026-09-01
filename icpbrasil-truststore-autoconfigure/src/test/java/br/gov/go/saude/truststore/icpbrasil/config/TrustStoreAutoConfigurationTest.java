package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.truststore.icpbrasil.service.provider.CertificateProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes de contrato da auto-configuração: contexto sobe com configuração mínima
 * válida e falha rápido (fail-fast) com mensagem apontando a propriedade exata
 * quando uma configuração obrigatória está ausente ou inválida.
 */
class TrustStoreAutoConfigurationTest {

    /** Conjunto mínimo de propriedades para um contexto válido (storage filesystem). */
    private static final String[] PROPS_MINIMAS = {
            "truststore-icpbrasil.certificate-url=https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip",
            "truststore-icpbrasil.hash-url=https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt",
            "truststore-icpbrasil.network.download-timeout-seconds=30",
            "truststore-icpbrasil.network.max-retries=3",
            "truststore-icpbrasil.network.retry-interval-seconds=10",
            "truststore-icpbrasil.cache-ttl-critical-hours=72",
            "truststore-icpbrasil.cache-ttl-max-hours=168",
            "truststore-icpbrasil.refresh-interval-hours=1",
            "truststore-icpbrasil.storage.type=filesystem",
            "truststore-icpbrasil.storage.truststore-archive-path=ACcompactado.zip",
            "truststore-icpbrasil.storage.hash-file-path=hash.txt",
            "truststore-icpbrasil.storage.confirmation-file-path=confirmacao.txt",
            "truststore-icpbrasil.filesystem.base-dir=target/test-truststore",
            "truststore-icpbrasil.trusted-certs.dir=classpath:registries/certificates",
            "truststore-icpbrasil.bootstrap.enabled=false",
            "truststore-icpbrasil.scheduling.enabled=false",
    };

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            // ConfigurationProperties/ValidationAutoConfiguration fornecem a infraestrutura
            // de binding e Bean Validation que numa aplicação Boot real está sempre presente
            .withConfiguration(AutoConfigurations.of(
                    org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration.class,
                    org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration.class,
                    TrustStoreAutoConfiguration.class));

    @Test
    void testContexto_ComConfigMinimaFilesystem_SobeComBeansPrincipais() {
        runner.withPropertyValues(PROPS_MINIMAS).run(context -> {
            assertNull(context.getStartupFailure());
            assertNotNull(context.getBean(TrustStoreConfig.class));
            assertNotNull(context.getBean(TrustStoreService.class));
            assertInstanceOf(FilesystemTrustStoreRepository.class, context.getBean(TrustStoreRepository.class));
        });
    }

    @Test
    void testContexto_SemCertificateUrl_FalhaComMensagemDaPropriedade() {
        runner.withPropertyValues(remover(PROPS_MINIMAS, "truststore-icpbrasil.certificate-url"))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    String causa = mensagemRaiz(context.getStartupFailure());
                    assertTrue(causa.contains("truststore-icpbrasil.certificate-url"),
                            "Mensagem deve apontar a propriedade ausente. Recebido: " + causa);
                });
    }

    @Test
    void testContexto_ComCertificateUrlHttp_FalhaExigindoHttps() {
        runner.withPropertyValues(substituir(PROPS_MINIMAS,
                        "truststore-icpbrasil.certificate-url=http://acraiz.icpbrasil.gov.br/x.zip"))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagemRaiz(context.getStartupFailure()).contains("HTTPS"));
                });
    }

    @Test
    void testContexto_SemTrustedCertsDir_FalhaComMensagemDaPropriedade() {
        runner.withPropertyValues(remover(PROPS_MINIMAS, "truststore-icpbrasil.trusted-certs.dir"))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagemRaiz(context.getStartupFailure())
                            .contains("truststore-icpbrasil.trusted-certs.dir"));
                });
    }

    @Test
    void testContexto_SemFilesystemBaseDir_FalhaComMensagemDaPropriedade() {
        runner.withPropertyValues(remover(PROPS_MINIMAS, "truststore-icpbrasil.filesystem.base-dir"))
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(mensagemRaiz(context.getStartupFailure())
                            .contains("truststore-icpbrasil.filesystem.base-dir"));
                });
    }

    @Test
    void testContexto_StorageS3SemPropriedadesS3_FalhaNoBinding() {
        runner.withPropertyValues(substituir(PROPS_MINIMAS, "truststore-icpbrasil.storage.type=s3"))
                .run(context -> assertNotNull(context.getStartupFailure(),
                        "storage.type=s3 sem truststore-icpbrasil.s3.* deve impedir o startup"));
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
        CertificateProvider provider = new br.gov.go.saude.truststore.icpbrasil.service.provider.TrustedCertsProvider(
                List.of(lerRecurso("registries/certificates/isrgrootx1.json")));

        @Bean
        CertificateProvider trustedCertsProvider() {
            return provider;
        }

        private static byte[] lerRecurso(String nome) {
            try (var is = ProviderCustomizado.class.getClassLoader().getResourceAsStream(nome)) {
                if (is == null) {
                    throw new IllegalStateException("Recurso de teste não encontrado: " + nome);
                }
                return is.readAllBytes();
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        }
    }

    private static String[] remover(String[] props, String chave) {
        return java.util.Arrays.stream(props)
                .filter(p -> !p.startsWith(chave + "="))
                .toArray(String[]::new);
    }

    private static String[] substituir(String[] props, String novaEntrada) {
        String chave = novaEntrada.substring(0, novaEntrada.indexOf('='));
        String[] sem = remover(props, chave);
        String[] resultado = java.util.Arrays.copyOf(sem, sem.length + 1);
        resultado[sem.length] = novaEntrada;
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
