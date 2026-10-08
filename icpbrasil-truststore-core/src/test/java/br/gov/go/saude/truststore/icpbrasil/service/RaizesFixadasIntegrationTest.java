package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.http.RetryPolicy;
import br.gov.go.saude.truststore.icpbrasil.http.TrustStoreManager;
import br.gov.go.saude.truststore.icpbrasil.http.tls.TlsTrust;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.service.provider.IcpBrasilCertificateProvider;
import br.gov.go.saude.truststore.icpbrasil.support.AlertaIcp;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Confronta o acervo real do ITI, baixado pela pilha de produção, com as raízes fixadas. */
@Tag("integration")
class RaizesFixadasIntegrationTest {

    private static List<X509Certificate> acervo;

    @BeforeAll
    @SneakyThrows
    static void baixarAcervoReal() {
        AlertaIcp.limpar();

        TrustStoreConfig config = config();
        TrustStoreManager trustStoreManager = new TrustStoreManager(TlsTrust.pinnedRoots(Clock.systemUTC()));
        Downloader downloader = new Downloader(
                Downloader.transporteAcervoIti(trustStoreManager.getSslContext(), config),
                new RetryPolicy(config), config);
        // O repositório só serve a getCertificates(); o download e o parse não o usam.
        IcpBrasilCertificateProvider provider = new IcpBrasilCertificateProvider(downloader, null);

        byte[] zip = provider.baixarZipIcpBrasil();
        provider.validateZipIntegrity(zip, provider.baixarHashIcpBrasil());
        acervo = provider.parseCertificates(zip);
    }

    @Test
    void testAcervoReal_TodasAsRaizesFixadas() {
        RaizesFixadas.Resultado resultado = RaizesFixadas.producao().filtrar(acervo);

        AlertaIcp.registrarRaizesDescartadas(resultado.raizesDescartadas(), acervo);
        assertTrue(resultado.raizesDescartadas().isEmpty(), resultado.raizesDescartadas().toString());
    }

    @Test
    void testAcervoReal_TodasAsRaizesFixadasPresentes() {
        Set<String> presentes = acervo.stream()
                .filter(CertificateParser::isSelfSignedRoot)
                .map(CertificateParser::getFingerprintSha256)
                .collect(Collectors.toSet());
        List<String> ausentes = RaizesFixadas.producao().fingerprints().stream()
                .filter(fingerprint -> !presentes.contains(fingerprint))
                .sorted()
                .toList();

        AlertaIcp.registrarRaizesAusentes(ausentes);
        assertTrue(ausentes.isEmpty(), "raízes fixadas ausentes do acervo: " + ausentes);
    }

    @Test
    void testAcervoReal_FiltroMantemTodosOsCertificados() {
        List<X509Certificate> mantidos = RaizesFixadas.producao().filtrar(acervo).certificados();
        Set<X509Certificate> descartados = new HashSet<>(acervo);
        descartados.removeAll(mantidos);

        AlertaIcp.registrarCertificados("Certificados do acervo descartados pelo filtro", List.copyOf(descartados));
        assertEquals(acervo.size(), mantidos.size(), "descartados: " + descartados);
    }

    @Test
    void testAcervoReal_NenhumaAcSobRaizV7() {
        List<X509Certificate> sobV7 = acervo.stream()
                .filter(c -> !CertificateParser.isSelfSignedRoot(c))
                .filter(c -> c.getIssuerX500Principal().getName().contains("Raiz Brasileira v7"))
                .toList();

        AlertaIcp.registrarCertificados("ACs emitidas pela Raiz Brasileira v7", sobV7);
        assertTrue(sobV7.isEmpty(), sobV7.toString());
    }

    private static TrustStoreConfig config() {
        TrustStoreConfig config = new TrustStoreConfig();

        TrustStoreConfig.NetworkConfig network = new TrustStoreConfig.NetworkConfig();
        network.setDownloadTimeoutSeconds(60);
        network.setMaxRetries(3);
        network.setRetryIntervalSeconds(30);
        config.setNetwork(network);

        return config;
    }
}
