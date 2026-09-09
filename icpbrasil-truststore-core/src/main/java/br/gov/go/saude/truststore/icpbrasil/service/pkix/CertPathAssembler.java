package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import br.gov.go.saude.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.truststore.icpbrasil.service.IncompleteChainException;
import lombok.extern.slf4j.Slf4j;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Constrói e valida o caminho de certificação com o {@link CertPathBuilder} PKIX do JDK, usando
 * como candidatos o alvo, os certificados fornecidos pelo chamador, as intermediárias do acervo
 * e, em último recurso, os emissores que o {@link CertificateChainResolver} baixa via AIA.
 *
 * <p>A revogação fica desligada aqui: ela é verificada em separado, sobre o caminho já
 * construído, com evidências obtidas pela política de download da biblioteca. Como a revogação
 * também está desligada e o JDK só busca emissores por AIA com {@code com.sun.security.enableAIAcaIssuers},
 * o construtor não abre conexões por conta própria.</p>
 */
@Slf4j
final class CertPathAssembler {

    /**
     * Máximo de intermediárias entre o alvo e a âncora. Hierarquias ICP-Brasil têm dois ou três
     * níveis abaixo da AC Raiz; o limite só existe para conter cadeias construídas de má-fé.
     */
    static final int MAX_PATH_LENGTH = 10;

    sealed interface Outcome {
        /**
         * @param certificates os certificados de {@code path}, já tipados, da folha ao último
         *                     intermediário (a âncora não faz parte de um CertPath PKIX)
         */
        record Built(CertPath path, List<X509Certificate> certificates, TrustAnchor anchor) implements Outcome {
            Built(CertPath path, TrustAnchor anchor) {
                this(path, x509CertificatesOf(path), anchor);
            }

            X509Certificate anchorCertificate() {
                return anchor.getTrustedCert();
            }

            /** Emissor de um certificado do caminho: o seguinte na lista ou, para o último, a âncora. */
            X509Certificate issuerOf(int index) {
                return index + 1 < certificates.size() ? certificates.get(index + 1) : anchorCertificate();
            }
        }

        record Failed(CertPathValidatorException.Reason reason, String detail) implements Outcome {}
    }

    private static List<X509Certificate> x509CertificatesOf(CertPath path) {
        List<X509Certificate> certificates = new ArrayList<>();
        for (Certificate certificate : path.getCertificates()) {
            certificates.add((X509Certificate) certificate);
        }
        return List.copyOf(certificates);
    }

    private final CertificateChainResolver chainResolver;

    CertPathAssembler(CertificateChainResolver chainResolver) {
        this.chainResolver = chainResolver;
    }

    Outcome assemble(X509Certificate target, Collection<X509Certificate> additional, TrustMaterial trust, Instant at) {
        Date date = Date.from(at);
        try {
            target.checkValidity(date);
        } catch (CertificateExpiredException e) {
            return new Outcome.Failed(BasicReason.EXPIRED, e.getMessage());
        } catch (CertificateNotYetValidException e) {
            return new Outcome.Failed(BasicReason.NOT_YET_VALID, e.getMessage());
        }

        List<X509Certificate> candidates = new ArrayList<>();
        candidates.add(target);
        candidates.addAll(additional);
        try {
            return build(target, candidates, trust, date);
        } catch (CertPathBuilderException withoutAia) {
            List<X509Certificate> fetched = fetchViaAia(target);
            if (fetched.isEmpty()) {
                return failed(withoutAia);
            }
            candidates.addAll(fetched);
            try {
                return build(target, candidates, trust, date);
            } catch (CertPathBuilderException withAia) {
                return failed(withAia);
            }
        }
    }

    /** O alvo entra no CertStore porque o construtor PKIX só considera certificados encontrados em stores. */
    private Outcome.Built build(X509Certificate target, List<X509Certificate> candidates,
                                TrustMaterial trust, Date date) throws CertPathBuilderException {
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(target);
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(trust.anchors(), selector);
            params.setRevocationEnabled(false);
            params.setDate(date);
            params.setMaxPathLength(MAX_PATH_LENGTH);
            params.addCertStore(TrustMaterial.collectionStore(candidates));
            params.addCertStore(trust.intermediates());
            PKIXCertPathBuilderResult result =
                    (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(params);
            return new Outcome.Built(result.getCertPath(), result.getTrustAnchor());
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Construtor de caminhos PKIX indisponível", e);
        }
    }

    /**
     * O construtor do JDK não distingue os motivos de uma busca sem sucesso; quando a causa raiz
     * é uma falha de validação com motivo definido, ela é preservada.
     */
    private static Outcome.Failed failed(CertPathBuilderException e) {
        log.debug("Caminho de certificação não construído: {}", e.getMessage());
        if (e.getCause() instanceof CertPathValidatorException cause
                && cause.getReason() != BasicReason.UNSPECIFIED) {
            return new Outcome.Failed(cause.getReason(), cause.getMessage());
        }
        return new Outcome.Failed(PKIXReason.NO_TRUST_ANCHOR, e.getMessage());
    }

    /**
     * Emissores anunciados via AIA, baixados pelo resolver dentro da política de download. A cadeia
     * parcial de uma montagem incompleta também serve: o que faltou ao resolver pode estar no
     * acervo. O resolver não estabelece confiança — tudo o que ele devolve é apenas candidato.
     */
    private List<X509Certificate> fetchViaAia(X509Certificate target) {
        List<X509Certificate> chain;
        try {
            chain = chainResolver.resolveChain(target);
        } catch (IncompleteChainException e) {
            chain = e.getPartialChain();
        } catch (RuntimeException e) {
            log.warn("Falha ao buscar emissores via AIA para {}: {}", target.getSubjectX500Principal(), e.getMessage());
            return List.of();
        }
        return chain.size() > 1 ? chain.subList(1, chain.size()) : List.of();
    }
}
