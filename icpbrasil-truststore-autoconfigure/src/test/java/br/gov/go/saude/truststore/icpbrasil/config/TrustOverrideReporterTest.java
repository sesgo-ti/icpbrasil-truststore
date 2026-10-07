package br.gov.go.saude.truststore.icpbrasil.config;

import br.gov.go.saude.truststore.icpbrasil.http.CertificateHttpTransport;
import br.gov.go.saude.truststore.icpbrasil.http.DownloadPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(OutputCaptureExtension.class)
class TrustOverrideReporterTest {

    private static final String AVISO = "substituído pela aplicação";

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
            "icpbrasil-truststore.bootstrap.enabled=false",
            "icpbrasil-truststore.scheduling.enabled=false",
    };

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    ValidationAutoConfiguration.class,
                    TrustStoreAutoConfiguration.class))
            .withPropertyValues(PROPS_MINIMAS);

    @Test
    void testInicializacao_BeansPadrao_NaoAvisa(CapturedOutput output) {
        runner.run(context -> {
            assertEquals(List.of(), context.getBean(TrustOverrideReporter.class).substituidos());
            assertTrue(!output.getOut().contains(AVISO), output.getOut());
        });
    }

    @Test
    void testInicializacao_SingletonRegistradoManualmente_TratadoComoSubstituido() {
        runner.withInitializer(context -> context.getBeanFactory()
                        .registerSingleton("trustMaterialSourceManual", (TrustMaterialSource) Optional::empty))
                .run(context -> assertEquals(List.of("TrustMaterialSource"),
                        context.getBean(TrustOverrideReporter.class).substituidos()));
    }

    @Test
    void testInicializacao_TrustMaterialSourceDoConsumidor_AvisaEmWarn(CapturedOutput output) {
        runner.withBean(TrustMaterialSource.class, () -> Optional::empty)
                .run(context -> {
                    assertEquals(List.of("TrustMaterialSource"),
                            context.getBean(TrustOverrideReporter.class).substituidos());
                    assertTrue(output.getOut().contains("TrustMaterialSource " + AVISO), output.getOut());
                });
    }

    @Test
    void testInicializacao_DownloaderDoConsumidor_AvisaEmWarn(CapturedOutput output) {
        runner.withBean(Downloader.class, () -> new Downloader(transporteQualquer(), null, new TrustStoreConfig()))
                .run(context -> {
                    assertEquals(List.of("Downloader"),
                            context.getBean(TrustOverrideReporter.class).substituidos());
                    assertTrue(output.getOut().contains("Downloader " + AVISO), output.getOut());
                });
    }

    @Test
    void testInicializacao_CertificateHttpTransportDoConsumidor_AvisaEmWarn(CapturedOutput output) {
        runner.withBean(CertificateHttpTransport.class, TrustOverrideReporterTest::transporteQualquer)
                .run(context -> {
                    assertEquals(List.of("CertificateHttpTransport"),
                            context.getBean(TrustOverrideReporter.class).substituidos());
                    assertTrue(output.getOut().contains("CertificateHttpTransport " + AVISO), output.getOut());
                });
    }

    private static CertificateHttpTransport transporteQualquer() {
        return new CertificateHttpTransport(DownloadPolicy.acervoIti(), Duration.ofSeconds(1));
    }
}
