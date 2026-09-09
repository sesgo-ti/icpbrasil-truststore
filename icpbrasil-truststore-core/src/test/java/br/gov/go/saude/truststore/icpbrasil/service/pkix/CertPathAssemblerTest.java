package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.IncompleteChainException;
import br.gov.go.saude.truststore.icpbrasil.support.TestChain;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.PKIXReason;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CertPathAssemblerTest {

    static TestChain chain;

    CertificateChainResolver resolver;
    CertPathAssembler assembler;
    Instant now;

    @BeforeAll
    static void generateChain() {
        chain = TestChain.create();
    }

    @BeforeEach
    void setUp() {
        resolver = mock(CertificateChainResolver.class);
        assembler = new CertPathAssembler(resolver);
        now = Instant.now();
    }

    @Test
    void testAssemble_IntermediariaNoAcervo_ConstroiSemAia() {
        CertPathAssembler.Outcome outcome = assembler.assemble(chain.leaf(), List.of(),
                TrustMaterial.of(chain.authorities()), now);

        CertPathAssembler.Outcome.Built built = assertInstanceOf(CertPathAssembler.Outcome.Built.class, outcome);
        assertEquals(List.of(chain.leaf(), chain.intermediate()), built.certificates());
        assertEquals(chain.root(), built.anchorCertificate());
        assertEquals(chain.intermediate(), built.issuerOf(0));
        assertEquals(chain.root(), built.issuerOf(1));
        verifyNoInteractions(resolver);
    }

    @Test
    void testAssemble_IntermediariaFornecidaPeloChamador_ConstroiSemAia() {
        CertPathAssembler.Outcome outcome = assembler.assemble(chain.leaf(), List.of(chain.intermediate()),
                TrustMaterial.of(List.of(chain.root())), now);

        assertInstanceOf(CertPathAssembler.Outcome.Built.class, outcome);
        verifyNoInteractions(resolver);
    }

    @Test
    void testAssemble_IntermediariaAusente_BaixaViaAiaEConstroi() {
        when(resolver.resolveChain(chain.leaf()))
                .thenReturn(List.of(chain.leaf(), chain.intermediate(), chain.root()));

        CertPathAssembler.Outcome outcome = assembler.assemble(chain.leaf(), List.of(),
                TrustMaterial.of(List.of(chain.root())), now);

        CertPathAssembler.Outcome.Built built = assertInstanceOf(CertPathAssembler.Outcome.Built.class, outcome);
        assertEquals(List.of(chain.leaf(), chain.intermediate()), built.certificates());
        assertEquals(chain.root(), built.anchorCertificate());
    }

    @Test
    void testAssemble_CadeiaParcialDoResolverCompletaComOAcervo_Constroi() {
        // O resolver não alcançou a raiz (sem AIA na intermediária), mas a raiz está no acervo.
        when(resolver.resolveChain(chain.leaf())).thenThrow(
                new IncompleteChainException("sem AIA", List.of(chain.leaf(), chain.intermediate())));

        CertPathAssembler.Outcome outcome = assembler.assemble(chain.leaf(), List.of(),
                TrustMaterial.of(List.of(chain.root())), now);

        assertInstanceOf(CertPathAssembler.Outcome.Built.class, outcome);
    }

    @Test
    void testAssemble_IntermediariaAusenteESemAia_FalhaSemAncora() {
        when(resolver.resolveChain(chain.leaf()))
                .thenThrow(new IncompleteChainException("sem AIA", List.of(chain.leaf())));

        CertPathAssembler.Outcome outcome = assembler.assemble(chain.leaf(), List.of(),
                TrustMaterial.of(List.of(chain.root())), now);

        CertPathAssembler.Outcome.Failed failed = assertInstanceOf(CertPathAssembler.Outcome.Failed.class, outcome);
        assertEquals(PKIXReason.NO_TRUST_ANCHOR, failed.reason());
    }

    @Test
    void testAssemble_HierarquiaDesconhecida_FalhaSemAncoraMesmoComCadeiaCompleta() {
        TestChain outra = TestChain.create();
        when(resolver.resolveChain(outra.leaf()))
                .thenReturn(List.of(outra.leaf(), outra.intermediate(), outra.root()));

        CertPathAssembler.Outcome outcome = assembler.assemble(outra.leaf(), List.of(),
                TrustMaterial.of(chain.authorities()), now);

        CertPathAssembler.Outcome.Failed failed = assertInstanceOf(CertPathAssembler.Outcome.Failed.class, outcome);
        assertEquals(PKIXReason.NO_TRUST_ANCHOR, failed.reason());
    }

    @Test
    void testAssemble_FolhaExpirada_FalhaExpiredSemConsultarAia() {
        TestChain expirada = TestChain.create(TestChain.Endpoints.none(), TestChain.Endpoints.none(),
                now.minus(Duration.ofDays(10)), now.minus(Duration.ofDays(1)));

        CertPathAssembler.Outcome outcome = assembler.assemble(expirada.leaf(), List.of(),
                TrustMaterial.of(expirada.authorities()), now);

        CertPathAssembler.Outcome.Failed failed = assertInstanceOf(CertPathAssembler.Outcome.Failed.class, outcome);
        assertEquals(BasicReason.EXPIRED, failed.reason());
        verifyNoInteractions(resolver);
    }

    @Test
    void testAssemble_FolhaAindaNaoValida_FalhaNotYetValid() {
        TestChain futura = TestChain.create(TestChain.Endpoints.none(), TestChain.Endpoints.none(),
                now.plus(Duration.ofDays(1)), now.plus(Duration.ofDays(10)));

        CertPathAssembler.Outcome outcome = assembler.assemble(futura.leaf(), List.of(),
                TrustMaterial.of(futura.authorities()), now);

        assertEquals(BasicReason.NOT_YET_VALID,
                assertInstanceOf(CertPathAssembler.Outcome.Failed.class, outcome).reason());
    }

    @Test
    @SneakyThrows
    void testAssemble_ExtensaoCriticaDesconhecida_Falha() {
        X509Certificate folha = chain.anotherLeaf(TestChain.Endpoints.none(),
                new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), true,
                        new DERPrintableString("x").getEncoded()));
        when(resolver.resolveChain(any())).thenThrow(new IncompleteChainException("sem AIA", List.of(folha)));

        CertPathAssembler.Outcome outcome = assembler.assemble(folha, List.of(),
                TrustMaterial.of(chain.authorities()), now);

        assertInstanceOf(CertPathAssembler.Outcome.Failed.class, outcome);
    }

    @Test
    void testAssemble_AlvoEhAPropriaAncora_CaminhoVazio() {
        CertPathAssembler.Outcome outcome = assembler.assemble(chain.root(), List.of(),
                TrustMaterial.of(chain.authorities()), now);

        CertPathAssembler.Outcome.Built built = assertInstanceOf(CertPathAssembler.Outcome.Built.class, outcome);
        assertTrue(built.certificates().isEmpty());
        assertEquals(chain.root(), built.anchorCertificate());
    }

    @Test
    void testAssemble_ResolverLancaErroInesperado_FalhaSemPropagar() {
        when(resolver.resolveChain(chain.leaf())).thenThrow(new IllegalStateException("boom"));

        CertPathAssembler.Outcome outcome = assembler.assemble(chain.leaf(), List.of(),
                TrustMaterial.of(List.of(chain.root())), now);

        assertInstanceOf(CertPathAssembler.Outcome.Failed.class, outcome);
    }
}
