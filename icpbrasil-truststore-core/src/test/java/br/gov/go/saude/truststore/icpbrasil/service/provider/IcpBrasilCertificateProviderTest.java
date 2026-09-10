package br.gov.go.saude.truststore.icpbrasil.service.provider;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.FilesystemTrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.RecoveryIcpBrasilResourceException;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestResourceLoader;
import br.gov.go.saude.truststore.icpbrasil.util.HashValidator;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IcpBrasilCertificateProviderTest {

    private static final String ZIP_URL =
            "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip";
    private static final String HASH_URL =
            "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt";

    static KeyPair rootKp;
    static X509Certificate root;
    static X509Certificate intermediate;
    static byte[] bundle;
    static String bundleHash;

    @TempDir
    Path baseDir;

    TrustStoreConfig config;
    FilesystemTrustStoreRepository repository;
    Downloader downloader;
    IcpBrasilCertificateProvider provider;

    @BeforeAll
    static void generateBundle() {
        rootKp = TestBundleFactory.newKeyPair();
        root = TestBundleFactory.caCert("Raiz", rootKp);
        intermediate = TestBundleFactory.intermediateCaCert("Intermediaria",
                TestBundleFactory.newKeyPair(), root, rootKp);
        bundle = TestBundleFactory.bundleOf(root, intermediate);
        bundleHash = HashValidator.computeSha512(bundle);
    }

    @BeforeEach
    void setUp() {
        config = buildConfig(baseDir);
        repository = new FilesystemTrustStoreRepository(config);
        downloader = mock(Downloader.class);
        provider = new IcpBrasilCertificateProvider(config, downloader, repository);
    }

    @Test
    void testParseCertificates_BundleValido_RetornaTodosOsCertificados() {
        List<X509Certificate> certificates = provider.parseCertificates(bundle);

        assertEquals(List.of(root, intermediate), certificates);
    }

    @SneakyThrows
    @Test
    void testParseCertificates_AcervoRealDoIti_AceitoIntegralmente() {
        byte[] acervo = TestResourceLoader.getResource("ACcompactado.zip").readAllBytes();
        X509Certificate esperado = CertificateParser.parse(TestResourceLoader.getResource("AC_SOLUTI_Multipla_v5_G2.crt"));

        List<X509Certificate> certificates = provider.parseCertificates(acervo);

        assertEquals(159, certificates.size());
        assertTrue(certificates.contains(esperado));
    }

    @Test
    void testParseCertificates_EntradasNaoCertificado_Ignoradas() {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("LEIAME.txt", "acervo".getBytes(StandardCharsets.UTF_8));
        entries.put("pasta/", new byte[0]);
        entries.put("pasta/raiz.CER", encoded(root));

        List<X509Certificate> certificates = provider.parseCertificates(TestBundleFactory.zipOf(entries));

        assertEquals(List.of(root), certificates);
    }

    @Test
    void testParseCertificates_ZipSemEntradas_Falha() {
        byte[] vazio = TestBundleFactory.zipOf(Map.of());

        assertThrows(IllegalArgumentException.class, () -> provider.parseCertificates(vazio));
    }

    @Test
    void testParseCertificates_ZipSemCertificados_Falha() {
        byte[] soTexto = TestBundleFactory.zipOf(Map.of("LEIAME.txt", "x".getBytes(StandardCharsets.UTF_8)));

        assertThrows(IllegalArgumentException.class, () -> provider.parseCertificates(soTexto));
    }

    @Test
    void testParseCertificates_ArrayVazio_Falha() {
        assertThrows(IllegalArgumentException.class, () -> provider.parseCertificates(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> provider.parseCertificates(null));
    }

    @Test
    void testParseCertificates_NaoEZip_Falha() {
        byte[] lixo = "isto nao e um zip".getBytes(StandardCharsets.UTF_8);

        assertThrows(IllegalArgumentException.class, () -> provider.parseCertificates(lixo));
    }

    @Test
    void testParseCertificates_EntradaInvalidaEntreValidas_FalhaInteira() {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("ac-0.crt", encoded(root));
        entries.put("ac-1.crt", "nao e certificado".getBytes(StandardCharsets.UTF_8));
        entries.put("ac-2.crt", encoded(intermediate));

        assertThrows(IllegalArgumentException.class,
                () -> provider.parseCertificates(TestBundleFactory.zipOf(entries)));
    }

    @Test
    void testParseCertificates_CertificadoSemSki_Falha() {
        X509Certificate semSki = TestBundleFactory.caCertWithoutSki("Sem SKI", TestBundleFactory.newKeyPair());

        assertThrows(IllegalArgumentException.class,
                () -> provider.parseCertificates(TestBundleFactory.bundleOf(root, semSki)));
    }

    @Test
    void testParseCertificates_CertificadoNaoCa_Falha() {
        X509Certificate leaf = TestCertificateFactory.generateLeafCert(TestBundleFactory.newKeyPair(), rootKp, root);

        assertThrows(IllegalArgumentException.class,
                () -> provider.parseCertificates(TestBundleFactory.bundleOf(root, leaf)));
    }

    @Test
    void testParseCertificates_EntradaExcedeMaxEntryBytes_Falha() {
        byte[] gigante = new byte[IcpBrasilCertificateProvider.MAX_ENTRY_BYTES + 1];
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("ac-0.crt", encoded(root));
        entries.put("gigante.crt", gigante);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> provider.parseCertificates(TestBundleFactory.zipOf(entries)));
        assertTrue(ex.getMessage().contains("gigante.crt"));
    }

    @Test
    void testParseCertificates_EntradaNaoCertificadoExcedeMaxEntryBytes_Falha() {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("ac-0.crt", encoded(root));
        entries.put("dados.bin", new byte[IcpBrasilCertificateProvider.MAX_ENTRY_BYTES + 1]);

        assertThrows(IllegalArgumentException.class,
                () -> provider.parseCertificates(TestBundleFactory.zipOf(entries)));
    }

    @Test
    void testParseCertificates_EntradaNoLimiteExato_Aceita() {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("dados.bin", new byte[IcpBrasilCertificateProvider.MAX_ENTRY_BYTES]);
        entries.put("ac-0.crt", encoded(root));

        assertEquals(List.of(root), provider.parseCertificates(TestBundleFactory.zipOf(entries)));
    }

    @Test
    void testParseCertificates_ExcedeMaxEntries_Falha() {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("ac-0.crt", encoded(root));
        byte[] minimo = {0};
        for (int i = 0; i < IcpBrasilCertificateProvider.MAX_ENTRIES; i++) {
            entries.put("e-" + i + ".txt", minimo);
        }

        assertThrows(IllegalArgumentException.class,
                () -> provider.parseCertificates(TestBundleFactory.zipOf(entries)));
    }

    @Test
    void testParseCertificates_ExcedeMaxTotalBytes_Falha() {
        // Entradas individualmente dentro do limite, mas cuja soma descompactada excede o total;
        // zeros compactam para poucos bytes, então o ZIP em si é pequeno.
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("ac-0.crt", encoded(root));
        byte[] bloco = new byte[IcpBrasilCertificateProvider.MAX_ENTRY_BYTES];
        long blocos = IcpBrasilCertificateProvider.MAX_TOTAL_BYTES / bloco.length + 1;
        for (int i = 0; i < blocos; i++) {
            entries.put("dados-" + i + ".bin", bloco);
        }

        assertThrows(IllegalArgumentException.class,
                () -> provider.parseCertificates(TestBundleFactory.zipOf(entries)));
    }

    @Test
    void testParseCertificates_ZipCompactadoExcedeMaxZipBytes_Falha() {
        byte[] enorme = new byte[IcpBrasilCertificateProvider.MAX_ZIP_BYTES + 1];

        assertThrows(IllegalArgumentException.class, () -> provider.parseCertificates(enorme));
    }

    @Test
    void testValidateZipIntegrity_HashCorreto_NaoLanca() {
        assertDoesNotThrow(() -> provider.validateZipIntegrity(bundle, bundleHash));
        assertDoesNotThrow(() -> provider.validateZipIntegrity(bundle, bundleHash.toUpperCase(Locale.ROOT)));
        assertDoesNotThrow(() -> provider.validateZipIntegrity(bundle, "  " + bundleHash + "\n"));
    }

    @Test
    void testValidateZipIntegrity_HashDivergente_LancaSecurityException() {
        String outro = HashValidator.computeSha512(new byte[]{1, 2, 3});

        assertThrows(SecurityException.class, () -> provider.validateZipIntegrity(bundle, outro));
    }

    @Test
    void testValidateZipIntegrity_HashMalformado_LancaSecurityException() {
        assertThrows(SecurityException.class, () -> provider.validateZipIntegrity(bundle, null));
        assertThrows(SecurityException.class, () -> provider.validateZipIntegrity(bundle, ""));
        assertThrows(SecurityException.class, () -> provider.validateZipIntegrity(bundle, bundleHash.substring(1)));
        assertThrows(SecurityException.class, () -> provider.validateZipIntegrity(bundle, "<html>erro</html>"));
    }

    @SneakyThrows
    @Test
    void testValidateZipIntegrity_AcervoRealComHashPublicado_NaoLanca() {
        byte[] acervo = TestResourceLoader.getResource("ACcompactado.zip").readAllBytes();
        String hashContent = new String(TestResourceLoader.getResource("hashsha512.txt").readAllBytes(),
                StandardCharsets.UTF_8);
        when(downloader.downloadText(HASH_URL)).thenReturn(hashContent);

        assertDoesNotThrow(() -> provider.validateZipIntegrity(acervo, provider.baixarHashIcpBrasil()));
    }

    @SneakyThrows
    @Test
    void testBaixarHashIcpBrasil_FormatoSha512sum_ExtraiHashEmMinusculo() {
        when(downloader.downloadText(HASH_URL)).thenReturn(bundleHash.toUpperCase(Locale.ROOT) + "  ACcompactado.zip\n");

        assertEquals(bundleHash, provider.baixarHashIcpBrasil());
    }

    @SneakyThrows
    @Test
    void testBaixarHashIcpBrasil_ConteudoNaoHex_Lanca() {
        when(downloader.downloadText(HASH_URL)).thenReturn("<html>manutencao</html>");

        assertThrows(RecoveryIcpBrasilResourceException.class, () -> provider.baixarHashIcpBrasil());
    }

    @SneakyThrows
    @Test
    void testBaixarHashIcpBrasil_VazioOuFalhaDeRede_Lanca() {
        when(downloader.downloadText(HASH_URL)).thenReturn("   ");
        assertThrows(RecoveryIcpBrasilResourceException.class, () -> provider.baixarHashIcpBrasil());

        when(downloader.downloadText(HASH_URL)).thenThrow(new IOException("offline"));
        assertThrows(RecoveryIcpBrasilResourceException.class, () -> provider.baixarHashIcpBrasil());
    }

    @SneakyThrows
    @Test
    void testBaixarZipIcpBrasil_RetornaBytesBaixados() {
        when(downloader.downloadBytes(ZIP_URL)).thenReturn(bundle);

        assertArrayEquals(bundle, provider.baixarZipIcpBrasil());
    }

    @SneakyThrows
    @Test
    void testBaixarZipIcpBrasil_VazioOuFalhaDeRede_Lanca() {
        when(downloader.downloadBytes(ZIP_URL)).thenReturn(new byte[0]);
        assertThrows(RecoveryIcpBrasilResourceException.class, () -> provider.baixarZipIcpBrasil());

        when(downloader.downloadBytes(ZIP_URL)).thenThrow(new IOException("offline"));
        assertThrows(RecoveryIcpBrasilResourceException.class, () -> provider.baixarZipIcpBrasil());
    }

    @Test
    void testGetCertificates_RepositorioLocalCompleto_RetornaCertificadosSemRede() {
        repository.armazenarZip(bundle);
        repository.armazenarHash(bundleHash);

        List<X509Certificate> certificates = provider.getCertificates();

        assertEquals(List.of(root, intermediate), certificates);
    }

    @Test
    void testGetCertificates_RepositorioLocalVazio_LancaIllegalStateException() {
        assertThrows(IllegalStateException.class, () -> provider.getCertificates());
    }

    @Test
    void testGetCertificates_HashLocalDivergente_LancaSecurityException() {
        repository.armazenarZip(bundle);
        repository.armazenarHash(HashValidator.computeSha512(new byte[]{9}));

        assertThrows(SecurityException.class, () -> provider.getCertificates());
    }

    @SneakyThrows
    private static byte[] encoded(X509Certificate certificate) {
        return certificate.getEncoded();
    }

    private static TrustStoreConfig buildConfig(Path baseDir) {
        TrustStoreConfig config = new TrustStoreConfig();
        config.setCertificateUrl(ZIP_URL);
        config.setHashUrl(HASH_URL);

        TrustStoreConfig.NetworkConfig network = new TrustStoreConfig.NetworkConfig();
        network.setDownloadTimeoutSeconds(30);
        network.setMaxRetries(3);
        network.setRetryIntervalSeconds(30);
        config.setNetwork(network);

        TrustStoreConfig.StorageConfig storage = new TrustStoreConfig.StorageConfig();
        storage.setType("filesystem");
        storage.setTruststoreArchivePath("ACcompactado.zip");
        storage.setHashFilePath("hash.txt");
        storage.setConfirmationFilePath("ultima_confirmacao.txt");
        config.setStorage(storage);

        TrustStoreConfig.FilesystemConfig filesystem = new TrustStoreConfig.FilesystemConfig();
        filesystem.setBaseDir(baseDir.toString());
        config.setFilesystem(filesystem);

        return config;
    }
}
