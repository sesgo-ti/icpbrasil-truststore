package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RaizDescartada;
import br.gov.go.saude.truststore.icpbrasil.support.TestBundleFactory;
import br.gov.go.saude.truststore.icpbrasil.support.TestResourceLoader;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RaizesFixadasTest {

    static KeyPair rootKp, otherKp, intKp;
    static X509Certificate root, intermediate, otherRoot, otherIntermediate;

    @BeforeAll
    static void gerar() {
        rootKp = TestBundleFactory.newKeyPair();
        otherKp = TestBundleFactory.newKeyPair();
        intKp = TestBundleFactory.newKeyPair();
        root = TestBundleFactory.caCert("Raiz Fixada", rootKp);
        intermediate = TestBundleFactory.intermediateCaCert("AC Fixada", intKp, root, rootKp);
        otherRoot = TestBundleFactory.caCert("Raiz Estranha", otherKp);
        otherIntermediate = TestBundleFactory.intermediateCaCert("AC Estranha", TestBundleFactory.newKeyPair(), otherRoot, otherKp);
    }

    @Test
    void testFiltrar_RaizNaoFixada_DescartaRaizEDescendentes() {
        RaizesFixadas fixadas = RaizesFixadas.de(Set.of(CertificateParser.getFingerprintSha256(root)));

        RaizesFixadas.Resultado resultado = fixadas.filtrar(List.of(root, intermediate, otherRoot, otherIntermediate));

        assertEquals(List.of(root, intermediate), resultado.certificados());
        assertEquals(List.of(new RaizDescartada(otherRoot.getSubjectX500Principal().getName(),
                CertificateParser.getFingerprintSha256(otherRoot))), resultado.raizesDescartadas());
    }

    @Test
    void testFiltrar_RaizFixadaAusente_AceitaOResto() {
        RaizesFixadas fixadas = RaizesFixadas.de(Set.of(CertificateParser.getFingerprintSha256(root), "ab".repeat(32)));

        assertEquals(List.of(root, intermediate), fixadas.filtrar(List.of(root, intermediate)).certificados());
    }

    @Test
    void testFiltrar_OrdemDoBundle_NaoAlteraResultado() {
        RaizesFixadas fixadas = RaizesFixadas.de(Set.of(CertificateParser.getFingerprintSha256(root)));

        assertEquals(List.of(intermediate, root),
                fixadas.filtrar(List.of(intermediate, otherIntermediate, root, otherRoot)).certificados());
    }

    @Test
    void testFiltrar_IntermediariaComAssinaturaInvalida_Descarta() {
        X509Certificate falsa = TestBundleFactory.intermediateCaCert("AC Fixada", TestBundleFactory.newKeyPair(),
                root, otherKp);
        RaizesFixadas fixadas = RaizesFixadas.de(Set.of(CertificateParser.getFingerprintSha256(root)));

        assertEquals(List.of(root), fixadas.filtrar(List.of(root, falsa)).certificados());
    }

    @Test
    @SneakyThrows
    void testFiltrar_RaizV7ComAlgoritmoNaoSuportado_MantemComoRaiz() {
        X509Certificate v7 = CertificateParser.parse(TestResourceLoader.getResource("icp/raiz-v7.crt"));

        assertEquals(List.of(v7), RaizesFixadas.producao().filtrar(List.of(v7)).certificados());
        assertTrue(CertificateParser.isSelfSignedRoot(v7));
    }

    @Test
    void testProducao_SeisRaizesVigentes() {
        assertEquals(Set.of(
                "caa53fc6091c6951887c976e378f6ef89aa6377c55d97b6475422b71ed7e9b17",
                "3bdb9b509352f1d3d71c2bf64d9a38a4e6cebda27809d77f7ac476cbde6e314a",
                "5657e70580eb678983f3ed7dfce091d84cae6549389a47fccda8d0e4dc2cf576",
                "6e0bff069a26994c15de2c4888cc54af84882e5495b7fbf66be9ccffec7489f6",
                "1406710058180fa4081aab3f246f1702429c552a11fa3143b84c88cb3ab8e5e7",
                "d8478e37ce19c690cf657381e68fe600e4e1a042536830f06847e03e554c4b01"),
                RaizesFixadas.producao().fingerprints());
    }

    @Test
    @SneakyThrows
    void testFixtureV7_Sha256_IgualConstanteDeProducao() {
        X509Certificate v7 = CertificateParser.parse(TestResourceLoader.getResource("icp/raiz-v7.crt"));

        assertTrue(RaizesFixadas.producao().fingerprints().contains(CertificateParser.getFingerprintSha256(v7)));
    }
}
