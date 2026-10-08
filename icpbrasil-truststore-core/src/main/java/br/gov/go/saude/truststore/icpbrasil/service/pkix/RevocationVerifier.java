package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import lombok.extern.slf4j.Slf4j;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLReason;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateRevokedException;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PKIXRevocationChecker.Option;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verifica a revogação de cada certificado de um caminho já construído, da folha até o último
 * intermediário, em duas camadas: a {@link RevocationService} da biblioteca obtém e valida a
 * evidência (OCSP, depois CRL) dentro da política de download, e o {@link PKIXRevocationChecker}
 * do JDK a reavalia, alimentado exclusivamente com essa evidência.
 *
 * <p>Cada certificado é submetido ao JDK como caminho de um só elemento ancorado no seu emissor,
 * o que permite que folha e intermediárias usem mecanismos diferentes (a folha por OCSP, a AC
 * por CRL). Com {@link Option#NO_FALLBACK} e a evidência sempre fornecida, o JDK nunca abre
 * conexões por conta própria: o download de CRL exige a propriedade global
 * {@code com.sun.security.enableCRLDP} e a consulta OCSP só ocorre sem resposta pré-fornecida.</p>
 *
 * <p>As duas camadas consideram o certificado revogado só a partir da data de revogação, e o
 * resultado exige que concordem: não revogado nas duas, ou revogado nas duas (com data e motivo
 * do JDK). Uma evidência aceita pela biblioteca e rejeitada pelo JDK, ou com vereditos
 * diferentes nas duas camadas, é tratada como {@link RevocationStatus.Malformed}: a divergência
 * é registrada em {@code WARN} e o certificado fica indeterminado, nunca aprovado.</p>
 */
@Slf4j
final class RevocationVerifier {

    sealed interface Outcome {
        /** @param evidence uma evidência por certificado do caminho, na ordem do caminho */
        record Clear(List<RevocationEvidence> evidence) implements Outcome {}

        record Revoked(X509Certificate certificate, Instant revokedAt, CRLReason reason,
                       RevocationEvidence evidence) implements Outcome {}

        record Undetermined(X509Certificate certificate, RevocationStatus status) implements Outcome {}
    }

    /** Decisão do JDK sobre a evidência de um certificado. */
    private sealed interface Verdict {
        record Clear() implements Verdict {}
        record Revoked(Instant revokedAt, CRLReason reason) implements Verdict {}
        record Rejected(String detail) implements Verdict {}
    }

    private final RevocationService revocationService;

    RevocationVerifier(RevocationService revocationService) {
        this.revocationService = revocationService;
    }

    Outcome verify(CertPathAssembler.Outcome.Built built, Instant at) {
        List<X509Certificate> certificates = built.certificates();
        List<RevocationEvidence> evidence = new ArrayList<>(certificates.size());
        for (int i = 0; i < certificates.size(); i++) {
            X509Certificate certificate = certificates.get(i);
            X509Certificate issuer = built.issuerOf(i);

            RevocationLookup lookup = revocationService.lookup(certificate, issuer);
            if (!lookup.isConclusive()) {
                return new Outcome.Undetermined(certificate, lookup.status());
            }

            boolean revokedByLibrary = lookup.status() instanceof RevocationStatus.Revoked;
            String source = sourceOf(lookup.status());
            String serialHex = certificate.getSerialNumber().toString(16);
            switch (verifyWithJdk(certificate, issuer, lookup.evidence(), at)) {
                case Verdict.Clear ignored when !revokedByLibrary -> evidence.add(lookup.evidence());
                case Verdict.Revoked revoked when revokedByLibrary -> {
                    return new Outcome.Revoked(certificate, revoked.revokedAt(), revoked.reason(), lookup.evidence());
                }
                case Verdict.Rejected rejected -> {
                    log.warn("Evidência {} aceita pela biblioteca foi rejeitada pelo verificador PKIX do JDK "
                                    + "para o certificado serial {}: {}", source, serialHex, rejected.detail());
                    return new Outcome.Undetermined(certificate, new RevocationStatus.Malformed(source));
                }
                case Verdict jdk -> {
                    log.warn("Veredito de revogação diverge entre a biblioteca ({}) e o verificador PKIX do JDK ({}) "
                                    + "para o certificado serial {} com evidência {}",
                            revokedByLibrary ? "revogado" : "não revogado",
                            jdk instanceof Verdict.Revoked ? "revogado" : "não revogado", serialHex, source);
                    return new Outcome.Undetermined(certificate, new RevocationStatus.Malformed(source));
                }
            }
        }
        return new Outcome.Clear(evidence);
    }

    private Verdict verifyWithJdk(X509Certificate certificate, X509Certificate issuer,
                                  RevocationEvidence evidence, Instant at) {
        try {
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXRevocationChecker checker = (PKIXRevocationChecker) validator.getRevocationChecker();
            EnumSet<Option> options = EnumSet.of(Option.NO_FALLBACK);

            PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(issuer, null)));
            params.setRevocationEnabled(false);
            params.setDate(Date.from(at));
            switch (evidence) {
                case RevocationEvidence.OcspResponse ocsp -> checker.setOcspResponses(Map.of(certificate, ocsp.der()));
                case RevocationEvidence.Crl crl -> {
                    options.add(Option.PREFER_CRLS);
                    params.addCertStore(TrustMaterial.collectionStore(List.of(crl.crl())));
                }
            }
            checker.setOptions(options);
            params.addCertPathChecker(checker);

            validator.validate(singlePath(certificate), params);
            return new Verdict.Clear();
        } catch (CertPathValidatorException e) {
            if (e.getReason() == BasicReason.REVOKED) {
                return revokedVerdict(e);
            }
            return new Verdict.Rejected(e.getMessage());
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | CertificateException e) {
            throw new IllegalStateException("Validador PKIX indisponível nesta JVM", e);
        }
    }

    private static CertPath singlePath(X509Certificate certificate) throws CertificateException {
        return CertificateFactory.getInstance("X.509").generateCertPath(List.of(certificate));
    }

    /** O JDK encadeia a {@link CertificateRevokedException} com data e motivo; sem ela, só o veredicto. */
    private static Verdict.Revoked revokedVerdict(CertPathValidatorException e) {
        if (e.getCause() instanceof CertificateRevokedException details) {
            return new Verdict.Revoked(details.getRevocationDate().toInstant(), details.getRevocationReason());
        }
        return new Verdict.Revoked(null, CRLReason.UNSPECIFIED);
    }

    private static String sourceOf(RevocationStatus status) {
        return switch (status) {
            case RevocationStatus.Good good -> good.source();
            case RevocationStatus.Revoked revoked -> revoked.source();
            default -> throw new IllegalStateException("Status inconclusivo não tem fonte: " + status);
        };
    }
}
