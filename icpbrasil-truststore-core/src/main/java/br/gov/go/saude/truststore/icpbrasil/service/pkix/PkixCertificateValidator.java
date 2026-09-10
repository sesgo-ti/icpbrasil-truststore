package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Valida certificados X.509 com o algoritmo PKIX do JDK (RFC 5280), ancorado nas raízes do
 * acervo ICP-Brasil, com verificação de revogação de todo o caminho.
 *
 * <p>A biblioteca obtém os artefatos (emissores via AIA, respostas OCSP e CRLs) dentro da sua
 * política de download e os valida; toda decisão de encadeamento, validade, restrições e
 * algoritmos é do {@code CertPathBuilder}/{@code CertPathValidator} do JDK, que também reavalia
 * cada evidência de revogação. O instante de referência vem do {@link Clock} e vale para o
 * caminho inteiro.</p>
 *
 * <p>Não realiza validação histórica (LTV): responde se o certificado é confiável agora. Um
 * consumidor que precise guardar as evidências encontra-as em {@link ValidationResult.Valid#evidence()}.</p>
 */
public class PkixCertificateValidator {

    private final TrustMaterialSource trustSource;
    private final CertPathAssembler assembler;
    private final RevocationVerifier verifier;
    private final Clock clock;

    public PkixCertificateValidator(TrustMaterialSource trustSource, CertificateChainResolver chainResolver,
                                    RevocationService revocationService) {
        this(trustSource, chainResolver, revocationService, Clock.systemUTC());
    }

    /** Variante com relógio injetável: {@code clock} fornece o instante de referência da validação. */
    public PkixCertificateValidator(TrustMaterialSource trustSource, CertificateChainResolver chainResolver,
                                    RevocationService revocationService, Clock clock) {
        this.trustSource = Objects.requireNonNull(trustSource, "trustSource");
        this.assembler = new CertPathAssembler(Objects.requireNonNull(chainResolver, "chainResolver"));
        this.verifier = new RevocationVerifier(Objects.requireNonNull(revocationService, "revocationService"));
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Valida contra as âncoras do acervo, sem certificados adicionais. */
    public ValidationResult validate(X509Certificate certificate) {
        return validate(certificate, List.of());
    }

    /**
     * Valida contra as âncoras do acervo.
     *
     * @param additionalCertificates intermediárias conhecidas pelo chamador (ex.: extraídas de uma
     *                               assinatura CMS); são candidatas, não confiáveis por si
     */
    public ValidationResult validate(X509Certificate certificate, Collection<X509Certificate> additionalCertificates) {
        Optional<TrustMaterial> trust = trustSource.current();
        if (trust.isEmpty()) {
            return new ValidationResult.TrustStoreUnavailable();
        }
        return validate(certificate, additionalCertificates, trust.get());
    }

    /**
     * Valida contra âncoras escolhidas pelo chamador — por exemplo, um emissor em que ele já confia
     * por outros meios (hierarquia de homologação). A revogação da própria âncora não é verificada.
     */
    public ValidationResult validate(X509Certificate certificate, Collection<X509Certificate> additionalCertificates,
                                     TrustMaterial trust) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(additionalCertificates, "additionalCertificates");
        if (!trust.hasAnchors()) {
            return new ValidationResult.TrustStoreUnavailable();
        }
        Instant at = clock.instant();
        return switch (assembler.assemble(certificate, additionalCertificates, trust, at)) {
            case CertPathAssembler.Outcome.Failed failed ->
                    new ValidationResult.Untrusted(failed.reason(), failed.detail());
            case CertPathAssembler.Outcome.Built built -> switch (verifier.verify(built, at)) {
                case RevocationVerifier.Outcome.Clear clear ->
                        new ValidationResult.Valid(built.certificates(), built.anchorCertificate(), clear.evidence());
                case RevocationVerifier.Outcome.Revoked revoked ->
                        new ValidationResult.Revoked(revoked.certificate(), revoked.revokedAt(), revoked.reason(),
                                revoked.evidence());
                case RevocationVerifier.Outcome.Undetermined undetermined ->
                        new ValidationResult.RevocationUndetermined(undetermined.certificate(), undetermined.status());
            };
        };
    }
}
