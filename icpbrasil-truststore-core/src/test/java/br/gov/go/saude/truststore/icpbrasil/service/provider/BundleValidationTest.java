package br.gov.go.saude.truststore.icpbrasil.service.provider;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static br.gov.go.saude.truststore.icpbrasil.support.TestBundle.*;
import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BundleValidationTest {
    private static KeyPair key;
    private static X509Certificate ca;
    private static byte[] der;
    private TrustStoreConfig config;
    private TrustStoreRepository repository;
    private Downloader downloader;

    @BeforeAll
    @SneakyThrows
    static void setUpCertificates() {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
        ca = generateRootCert(key);
        der = ca.getEncoded();
    }

    @BeforeEach
    void setUp() {
        config = new TrustStoreConfig();
        repository = mock(TrustStoreRepository.class);
        downloader = mock(Downloader.class);
    }

    @Test
    @SneakyThrows
    void testFixtureReal_TodasEntradasSaoCaComSki_CompativelComLimitesPadrao() {
        try (var zip = TestResourceLoader.getResource("ACcompactado.zip")) {
            var parsed = parse(zip.readAllBytes());
            assertFalse(parsed.certificates().isEmpty());
            assertTrue(parsed.certificates().stream().allMatch(cert -> cert.getBasicConstraints() >= 0));
            assertFalse(parsed.index().containsKey(""));
        }
    }

    @Test
    void testParseSnapshot_ImutavelECopiaDefensiva() {
        byte[] bytes = zip(ca);
        var parsed = parse(bytes);
        byte[] original = bytes.clone();
        bytes[0] = 0;
        parsed.zip()[0] = 0;
        assertArrayEquals(original, parsed.zip());
        assertEquals(hash(original), parsed.hash());
        assertThrows(UnsupportedOperationException.class, () -> parsed.index().clear());
        assertThrows(UnsupportedOperationException.class, () -> parsed.certificates().clear());
    }

    @Test
    void testParseSnapshot_ZipVazioSemCertificadosOuBytesInvalidos_Rejeita() {
        for (byte[] bytes : new byte[][]{new byte[0], new byte[]{1, 2}, zip(Map.of()),
                zip(Map.of("readme.txt", new byte[]{1})), zip(Map.of("ca.crt", new byte[0]))}) {
            assertThrows(SecurityException.class, () -> parse(bytes));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testParseSnapshot_EntradaInvalidaAntesOuDepoisDaValida_RejeitaGeracaoInteira(boolean invalidFirst) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(invalidFirst ? "invalid.crt" : "ca.crt", invalidFirst ? new byte[]{1} : der);
        entries.put(invalidFirst ? "ca.crt" : "invalid.crt", invalidFirst ? der : new byte[]{1});
        assertThrows(SecurityException.class, () -> parse(zip(entries)));
    }

    @Test
    @SneakyThrows
    void testParseSnapshot_CaSemSkiOuNaoCa_RejeitaMesmoComOutraCaValida() {
        X500Name name = new X500Name("CN=CA sem SKI");
        var builder = createBuilder(name, name, 7, key);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        for (X509Certificate invalid : new X509Certificate[]{sign(builder, key), generateLeafCert(key, key, ca)}) {
            byte[] bytes = zip(Map.of("ca.crt", der, "invalid.crt", invalid.getEncoded()));
            assertThrows(SecurityException.class, () -> parse(bytes));
        }
    }

    @Test
    @SneakyThrows
    void testParseSnapshot_CaIntermediariaSemRaiz_AceitaListaDeCas() {
        var builder = createBuilder(new X500Name("CN=Issuer"), new X500Name("CN=Intermediate"), 9, key);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        addSki(builder, key);
        assertEquals(1, parse(zip(sign(builder, key))).index().size());
    }

    @Test
    void testParseSnapshot_HashErradoMalformadoOuNulo_Rejeita() {
        byte[] bytes = zip(ca);
        for (String invalid : new String[]{null, "", "a", "0".repeat(128)}) {
            assertThrows(SecurityException.class, () -> provider().parseSnapshot(bytes, invalid));
        }
        assertEquals(hash(bytes), provider().parseSnapshot(bytes, hash(bytes).toUpperCase()).hash());
    }

    @Test
    void testGetCertificates_StorageHashOuParsingInvalido_NaoRetornaListaParcial() {
        byte[] invalid = zip(Map.of("ca.crt", der, "invalid.crt", new byte[]{1}));
        when(repository.recuperarZip()).thenReturn(Optional.of(invalid));
        when(repository.recuperarHash()).thenReturn(Optional.of(hash(invalid)));
        assertThrows(SecurityException.class, () -> provider().getCertificates());
        when(repository.recuperarZip()).thenReturn(Optional.of(zip(ca)));
        assertThrows(SecurityException.class, () -> provider().getCertificates());
        verifyNoInteractions(downloader);
    }

    @Test
    void testParseSnapshot_LimiteCompressed_AceitaExatoRejeitaExcedente() {
        byte[] bytes = zip(ca);
        config.getBundle().setMaxCompressedBytes(bytes.length);
        assertEquals(1, parse(bytes).index().size());
        config.getBundle().setMaxCompressedBytes(bytes.length - 1);
        assertThrows(SecurityException.class, () -> parse(bytes));
    }

    @ParameterizedTest
    @ValueSource(strings = {"bomb.crt", "ignored.txt", "directory/"})
    void testParseSnapshot_ZipBombEntradaInclusiveIgnoradaOuDiretorio_Rejeita(String name) {
        config.getBundle().setMaxEntryBytes(1024);
        byte[] bytes = zip(Map.of("ca.crt", der, name, new byte[100_000]));
        assertTrue(bytes.length < 2048);
        assertThrows(SecurityException.class, () -> parse(bytes));
    }

    @Test
    void testParseSnapshot_LimiteTotalIncluiEntradasIgnoradas_AceitaExato() {
        byte[] bytes = zip(Map.of("ca.crt", der, "ignored.txt", new byte[100]));
        config.getBundle().setMaxExpandedBytes(der.length + 100);
        assertEquals(1, parse(bytes).index().size());
        config.getBundle().setMaxExpandedBytes(der.length + 99);
        assertThrows(SecurityException.class, () -> parse(bytes));
    }

    @Test
    void testParseSnapshot_LimiteContagemIncluiDiretorios_AceitaExato() {
        byte[] bytes = zip(Map.of("ca.crt", der, "dir/", new byte[0], "readme.txt", new byte[0]));
        config.getBundle().setMaxEntries(3);
        assertEquals(1, parse(bytes).index().size());
        config.getBundle().setMaxEntries(2);
        assertThrows(SecurityException.class, () -> parse(bytes));
    }

    @Test
    void testParseSnapshot_ContagemDeclaradaFalsa_NaoContornaLimiteDoDiretorio() {
        byte[] bytes = zip(Map.of("ca.crt", der, "dir/", new byte[0], "readme.txt", new byte[0]));
        var buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort(bytes.length - 22 + 8, (short) 1);
        buffer.putShort(bytes.length - 22 + 10, (short) 1);
        config.getBundle().setMaxEntries(2);
        assertThrows(SecurityException.class, () -> parse(bytes));
    }

    @Test
    void testParseSnapshot_ZipTruncado_RejeitaMesmoComHashCorretoDosBytesTruncados() {
        byte[] bytes = zip(ca);
        assertThrows(SecurityException.class, () -> parse(Arrays.copyOf(bytes, bytes.length - 22)));
    }

    @Test
    void testParseSnapshot_CertificadoValidoComConteudoResidualInvalido_Rejeita() {
        byte[] trailingDer = Arrays.copyOf(der, der.length + 3);
        trailingDer[der.length] = 1;
        assertThrows(SecurityException.class, () -> parse(zip(Map.of("ca.crt", trailingDer))));
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der)
                + "\n-----END CERTIFICATE-----\n";
        byte[] trailingPem = (pem + "invalid certificate data").getBytes(StandardCharsets.US_ASCII);
        assertThrows(SecurityException.class, () -> parse(zip(Map.of("ca.pem", trailingPem))));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testParseSnapshot_ZipBombComTamanhoDeclaradoFalso_LimitaDuranteStream(boolean total) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("ignored.txt", new byte[100_000]);
        entries.put("ca.crt", der);
        byte[] bytes = zip(entries);
        for (int i = 0; i < bytes.length - 28; i++) {
            if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b && bytes[i + 2] == 1 && bytes[i + 3] == 2) {
                Arrays.fill(bytes, i + 24, i + 28, (byte) 0);
                break;
            }
        }
        if (total) {
            config.getBundle().setMaxExpandedBytes(1024);
        } else {
            config.getBundle().setMaxEntryBytes(1024);
        }
        var failure = assertThrows(SecurityException.class, () -> parse(bytes));
        assertTrue(failure.getCause().getMessage().contains("Expansao ZIP"));
    }

    @Test
    void testParseSnapshot_CrcInvalido_RejeitaMesmoComHashDoZipCorreto() {
        byte[] bytes = zip(ca);
        for (int i = 0; i < bytes.length - 20; i++) {
            if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b && bytes[i + 2] == 1 && bytes[i + 3] == 2) {
                bytes[i + 16] ^= 1;
                break;
            }
        }
        var failure = assertThrows(SecurityException.class, () -> parse(bytes));
        assertTrue(failure.getCause().getMessage().contains("corrompida"));
    }

    @Test
    void testParseSnapshot_PemConcatenadoValido_AceitaTodos() {
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der)
                + "\n-----END CERTIFICATE-----\n";
        var parsed = parse(zip(Map.of("ca.pem", pem.repeat(2).getBytes(StandardCharsets.US_ASCII))));
        assertEquals(2, parsed.certificates().size());
        assertEquals(1, parsed.index().size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"compressed", "entry", "total", "count", "hash"})
    void testConfig_LimitesInvalidosRejeitadosNoCoreSemSpring(String field) {
        switch (field) {
            case "compressed" -> config.getBundle().setMaxCompressedBytes(0);
            case "entry" -> config.getBundle().setMaxEntryBytes(-1);
            case "total" -> config.getBundle().setMaxExpandedBytes(Long.MAX_VALUE);
            case "count" -> config.getBundle().setMaxEntries(0);
            default -> config.getBundle().setMaxHashBytes(Integer.MAX_VALUE);
        }
        assertThrows(IllegalStateException.class, this::provider);
    }

    private IcpBrasilCertificateProvider.ParsedSnapshot parse(byte[] bytes) {
        return provider().parseSnapshot(bytes, hash(bytes));
    }

    private IcpBrasilCertificateProvider provider() {
        return new IcpBrasilCertificateProvider(config, downloader, repository);
    }
}
