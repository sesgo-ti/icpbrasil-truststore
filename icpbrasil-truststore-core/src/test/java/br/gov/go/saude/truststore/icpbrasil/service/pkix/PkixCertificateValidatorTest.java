package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.IncompleteChainException;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import br.gov.go.saude.truststore.icpbrasil.support.TestChain;
import lombok.SneakyThrows;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.cert.CRLReason;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXReason;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Fiação do validador com a {@link RevocationService} simulada: cada teste declara a evidência
 * que a biblioteca teria obtido e observa a decisão final, inclusive a reavaliação dessa
 * evidência pelo verificador PKIX do JDK.
 */
class PkixCertificateValidatorTest {

    static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    static TestChain chain;

    RevocationService revocation;
    CertificateChainResolver resolver;
    PkixCertificateValidator validator;

    @BeforeAll
    static void generateChain() {
        chain = TestChain.create();
    }

    @BeforeEach
    void setUp() {
        revocation = mock(RevocationService.class);
        resolver = mock(CertificateChainResolver.class);
        validator = new PkixCertificateValidator(() -> Optional.of(TrustMaterial.of(chain.authorities())),
                resolver, revocation, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    // --- caminho válido ---

    @Test
    void testValidate_OcspGoodParaFolhaEIntermediaria_Valid() {
        byte[] leafOcsp = chain.intermediateOcsp(NOW, CertificateStatus.GOOD);
        byte[] intermediateOcsp = chain.rootOcsp(NOW, CertificateStatus.GOOD);
        when(revocation.lookup(chain.leaf(), chain.intermediate())).thenReturn(ocspGood(leafOcsp));
        when(revocation.lookup(chain.intermediate(), chain.root())).thenReturn(ocspGood(intermediateOcsp));

        ValidationResult result = validator.validate(chain.leaf());

        ValidationResult.Valid valid = assertInstanceOf(ValidationResult.Valid.class, result);
        assertEquals(List.of(chain.leaf(), chain.intermediate()), valid.path());
        assertEquals(chain.root(), valid.anchor());
        assertEquals(2, valid.evidence().size());
        assertArrayEquals(leafOcsp, assertInstanceOf(RevocationEvidence.OcspResponse.class, valid.evidence().get(0)).der());
        assertArrayEquals(intermediateOcsp,
                assertInstanceOf(RevocationEvidence.OcspResponse.class, valid.evidence().get(1)).der());
        verifyNoInteractions(resolver);
    }

    @Test
    void testValidate_CrlParaFolhaEIntermediaria_Valid() {
        when(revocation.lookup(chain.leaf(), chain.intermediate()))
                .thenReturn(crlGood(chain.intermediateCrl(NOW, Map.of())));
        when(revocation.lookup(chain.intermediate(), chain.root())).thenReturn(crlGood(chain.rootCrl(NOW, Map.of())));

        ValidationResult result = validator.validate(chain.leaf());

        ValidationResult.Valid valid = assertInstanceOf(ValidationResult.Valid.class, result);
        assertTrue(valid.evidence().stream().allMatch(e -> e instanceof RevocationEvidence.Crl));
    }

    @Test
    void testValidate_FolhaPorOcspEIntermediariaPorCrl_ValidComMecanismosDistintos() {
        when(revocation.lookup(chain.leaf(), chain.intermediate()))
                .thenReturn(ocspGood(chain.intermediateOcsp(NOW, CertificateStatus.GOOD)));
        when(revocation.lookup(chain.intermediate(), chain.root())).thenReturn(crlGood(chain.rootCrl(NOW, Map.of())));

        ValidationResult result = validator.validate(chain.leaf());

        ValidationResult.Valid valid = assertInstanceOf(ValidationResult.Valid.class, result);
        assertInstanceOf(RevocationEvidence.OcspResponse.class, valid.evidence().get(0));
        assertInstanceOf(RevocationEvidence.Crl.class, valid.evidence().get(1));
    }

    @Test
    void testValidate_IntermediariaFornecidaPeloChamador_ValidSemAia() {
        PkixCertificateValidator soRaiz = new PkixCertificateValidator(
                () -> Optional.of(TrustMaterial.of(List.of(chain.root()))), resolver, revocation,
                Clock.fixed(NOW, ZoneOffset.UTC));
        withCurrentCrls();

        ValidationResult result = soRaiz.validate(chain.leaf(), List.of(chain.intermediate()));

        assertInstanceOf(ValidationResult.Valid.class, result);
        verifyNoInteractions(resolver);
    }

    @Test
    void testValidate_IntermediariaBaixadaViaAia_Valid() {
        PkixCertificateValidator soRaiz = new PkixCertificateValidator(
                () -> Optional.of(TrustMaterial.of(List.of(chain.root()))), resolver, revocation,
                Clock.fixed(NOW, ZoneOffset.UTC));
        when(resolver.resolveChain(chain.leaf())).thenReturn(List.of(chain.leaf(), chain.intermediate(), chain.root()));
        withCurrentCrls();

        ValidationResult result = soRaiz.validate(chain.leaf());

        assertInstanceOf(ValidationResult.Valid.class, result);
    }

    @Test
    void testValidate_AncorasExplicitasDoChamador_ValidamSemAcervo() {
        PkixCertificateValidator semAcervo = new PkixCertificateValidator(Optional::empty, resolver, revocation,
                Clock.fixed(NOW, ZoneOffset.UTC));
        when(revocation.lookup(chain.leaf(), chain.intermediate()))
                .thenReturn(crlGood(chain.intermediateCrl(NOW, Map.of())));

        ValidationResult result = semAcervo.validate(chain.leaf(), List.of(),
                TrustMaterial.anchoredAt(List.of(chain.intermediate())));

        ValidationResult.Valid valid = assertInstanceOf(ValidationResult.Valid.class, result);
        assertEquals(chain.intermediate(), valid.anchor());
        assertEquals(1, valid.evidence().size(), "a revogação da própria âncora não é verificada");
    }

    @Test
    void testValidate_AlvoEhAPropriaAncora_ValidSemEvidencia() {
        ValidationResult result = validator.validate(chain.root());

        ValidationResult.Valid valid = assertInstanceOf(ValidationResult.Valid.class, result);
        assertTrue(valid.path().isEmpty());
        assertTrue(valid.evidence().isEmpty());
        verifyNoInteractions(revocation);
    }

    // --- revogado ---

    @Test
    void testValidate_FolhaRevogadaNaCrl_RevokedComDataEMotivoDoJdk() {
        Instant revokedAt = NOW.minus(Duration.ofHours(2));
        byte[] crl = chain.intermediateCrl(NOW, Map.of(chain.leaf().getSerialNumber(), revokedAt));
        when(revocation.lookup(chain.leaf(), chain.intermediate())).thenReturn(crlRevoked(crl));

        ValidationResult result = validator.validate(chain.leaf());

        ValidationResult.Revoked revoked = assertInstanceOf(ValidationResult.Revoked.class, result);
        assertEquals(chain.leaf(), revoked.certificate());
        assertEquals(revokedAt, revoked.revokedAt());
        assertEquals(CRLReason.KEY_COMPROMISE, revoked.reason());
        assertInstanceOf(RevocationEvidence.Crl.class, revoked.evidence());
        verify(revocation, never()).lookup(chain.intermediate(), chain.root());
    }

    @Test
    void testValidate_IntermediariaRevogadaNaCrlDaRaiz_Revoked() {
        when(revocation.lookup(chain.leaf(), chain.intermediate()))
                .thenReturn(crlGood(chain.intermediateCrl(NOW, Map.of())));
        when(revocation.lookup(chain.intermediate(), chain.root())).thenReturn(crlRevoked(
                chain.rootCrl(NOW, Map.of(chain.intermediate().getSerialNumber(), NOW.minus(Duration.ofHours(1))))));

        ValidationResult result = validator.validate(chain.leaf());

        assertEquals(chain.intermediate(), assertInstanceOf(ValidationResult.Revoked.class, result).certificate());
    }

    @Test
    void testValidate_FolhaRevogadaPorOcsp_RevokedComMotivoDaResposta() {
        RevokedStatus status = new RevokedStatus(Date.from(NOW.minus(Duration.ofDays(1))),
                org.bouncycastle.asn1.x509.CRLReason.superseded);
        byte[] ocsp = chain.intermediateOcsp(NOW, status);
        when(revocation.lookup(chain.leaf(), chain.intermediate()))
                .thenReturn(new RevocationLookup(new RevocationStatus.Revoked("OCSP"),
                        new RevocationEvidence.OcspResponse(ocsp)));

        ValidationResult result = validator.validate(chain.leaf());

        ValidationResult.Revoked revoked = assertInstanceOf(ValidationResult.Revoked.class, result);
        assertEquals(CRLReason.SUPERSEDED, revoked.reason());
        assertEquals(NOW.minus(Duration.ofDays(1)), revoked.revokedAt());
        assertInstanceOf(RevocationEvidence.OcspResponse.class, revoked.evidence());
    }

    // --- indeterminado ---

    @Test
    void testValidate_EvidenciaIndisponivelParaFolha_UndeterminedSemConsultarIntermediaria() {
        when(revocation.lookup(chain.leaf(), chain.intermediate()))
                .thenReturn(RevocationLookup.inconclusive(new RevocationStatus.CrlUnavailable()));

        ValidationResult result = validator.validate(chain.leaf());

        ValidationResult.RevocationUndetermined undetermined =
                assertInstanceOf(ValidationResult.RevocationUndetermined.class, result);
        assertEquals(chain.leaf(), undetermined.certificate());
        assertInstanceOf(RevocationStatus.CrlUnavailable.class, undetermined.status());
        verify(revocation, never()).lookup(chain.intermediate(), chain.root());
    }

    @Test
    void testValidate_SemPontosDeDistribuicao_UndeterminedNoDistributionPoints() {
        when(revocation.lookup(any(), any()))
                .thenReturn(RevocationLookup.inconclusive(new RevocationStatus.NoDistributionPoints()));

        ValidationResult result = validator.validate(chain.leaf());

        assertInstanceOf(RevocationStatus.NoDistributionPoints.class,
                assertInstanceOf(ValidationResult.RevocationUndetermined.class, result).status());
    }

    @Test
    void testValidate_OcspVencidaAceitaPelaBiblioteca_JdkRejeitaEFicaMalformed() {
        byte[] vencida = chain.intermediateOcsp(CertificateStatus.GOOD,
                NOW.minus(Duration.ofHours(3)), NOW.minus(Duration.ofHours(1)));
        when(revocation.lookup(chain.leaf(), chain.intermediate())).thenReturn(ocspGood(vencida));

        ValidationResult result = validator.validate(chain.leaf());

        ValidationResult.RevocationUndetermined undetermined =
                assertInstanceOf(ValidationResult.RevocationUndetermined.class, result);
        assertEquals(new RevocationStatus.Malformed("OCSP"), undetermined.status());
    }

    @Test
    void testValidate_CrlDeOutraChaveAceitaPelaBiblioteca_JdkRejeitaEFicaMalformed() {
        TestChain outra = TestChain.create();
        // CRL assinada pela intermediária de outra hierarquia, mas apresentada como evidência da folha
        when(revocation.lookup(chain.leaf(), chain.intermediate()))
                .thenReturn(crlGood(outra.intermediateCrl(NOW, Map.of())));

        ValidationResult result = validator.validate(chain.leaf());

        assertEquals(new RevocationStatus.Malformed("CRL"),
                assertInstanceOf(ValidationResult.RevocationUndetermined.class, result).status());
    }

    // --- não confiável ---

    @Test
    void testValidate_FolhaExpirada_UntrustedExpiredSemBuscarEvidencias() {
        TestChain expirada = TestChain.create(TestChain.Endpoints.none(), TestChain.Endpoints.none(),
                NOW.minus(Duration.ofDays(10)), NOW.minus(Duration.ofDays(1)));
        PkixCertificateValidator v = new PkixCertificateValidator(
                () -> Optional.of(TrustMaterial.of(expirada.authorities())), resolver, revocation,
                Clock.fixed(NOW, ZoneOffset.UTC));

        ValidationResult result = v.validate(expirada.leaf());

        assertEquals(BasicReason.EXPIRED, assertInstanceOf(ValidationResult.Untrusted.class, result).reason());
        verifyNoInteractions(revocation);
    }

    @Test
    void testValidate_HierarquiaDesconhecida_UntrustedNoTrustAnchor() {
        TestChain outra = TestChain.create();
        when(resolver.resolveChain(outra.leaf()))
                .thenThrow(new IncompleteChainException("sem AIA", List.of(outra.leaf())));

        ValidationResult result = validator.validate(outra.leaf(), List.of(outra.intermediate()));

        assertEquals(PKIXReason.NO_TRUST_ANCHOR, assertInstanceOf(ValidationResult.Untrusted.class, result).reason());
        verifyNoInteractions(revocation);
    }

    @Test
    void testValidate_AcervoIndisponivel_TrustStoreUnavailable() {
        PkixCertificateValidator semAcervo = new PkixCertificateValidator(Optional::empty, resolver, revocation);

        assertInstanceOf(ValidationResult.TrustStoreUnavailable.class, semAcervo.validate(chain.leaf()));
        assertInstanceOf(ValidationResult.TrustStoreUnavailable.class,
                semAcervo.validate(chain.leaf(), List.of(), TrustMaterial.anchoredAt(List.of())));
    }

    // --- helpers ---

    private void withCurrentCrls() {
        when(revocation.lookup(chain.leaf(), chain.intermediate()))
                .thenReturn(crlGood(chain.intermediateCrl(NOW, Map.of())));
        when(revocation.lookup(chain.intermediate(), chain.root())).thenReturn(crlGood(chain.rootCrl(NOW, Map.of())));
    }

    private static RevocationLookup ocspGood(byte[] response) {
        return new RevocationLookup(new RevocationStatus.Good("OCSP", response),
                new RevocationEvidence.OcspResponse(response));
    }

    private static RevocationLookup crlGood(byte[] crl) {
        return new RevocationLookup(new RevocationStatus.Good("CRL", crl), new RevocationEvidence.Crl(decode(crl)));
    }

    private static RevocationLookup crlRevoked(byte[] crl) {
        return new RevocationLookup(new RevocationStatus.Revoked("CRL"), new RevocationEvidence.Crl(decode(crl)));
    }

    @SneakyThrows
    private static X509CRL decode(byte[] crl) {
        return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(crl));
    }
}
