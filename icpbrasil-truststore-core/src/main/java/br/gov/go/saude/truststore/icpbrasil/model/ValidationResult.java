package br.gov.go.saude.truststore.icpbrasil.model;

import java.security.cert.CRLReason;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * Resultado da validação PKIX de um certificado contra as âncoras de confiança.
 *
 * <p>Somente {@link Valid} autoriza o uso do certificado: o caminho foi construído até uma
 * âncora, validado pelo algoritmo PKIX do JDK no instante da consulta e nenhum certificado do
 * caminho consta como revogado. Os demais estados são terminais e devem ser tratados como
 * rejeição — inclusive {@link RevocationUndetermined}, que nunca equivale a "não revogado".</p>
 */
public sealed interface ValidationResult {

    /**
     * @param path     certificados validados, da folha até o último intermediário (âncora excluída)
     * @param anchor   âncora de confiança que fundamenta o caminho
     * @param evidence evidência de revogação aceita para cada certificado de {@code path}, na mesma
     *                 ordem; vazia quando o próprio alvo é a âncora
     */
    record Valid(List<X509Certificate> path, X509Certificate anchor,
                 List<RevocationEvidence> evidence) implements ValidationResult {
        public Valid {
            path = List.copyOf(path);
            evidence = List.copyOf(evidence);
        }
    }

    /**
     * @param certificate certificado do caminho apontado como revogado
     * @param revokedAt   instante de revogação informado pela evidência; {@code null} se ela não o
     *                    informou ao validador
     * @param reason      motivo informado pela evidência; {@link CRLReason#UNSPECIFIED} quando ausente
     * @param evidence    resposta OCSP ou CRL que sustenta a revogação
     */
    record Revoked(X509Certificate certificate, Instant revokedAt, CRLReason reason,
                   RevocationEvidence evidence) implements ValidationResult {}

    /**
     * O caminho não pôde ser construído ou validado até uma âncora.
     *
     * @param reason motivo PKIX reportado pelo JDK ({@code BasicReason} ou {@code PKIXReason})
     * @param detail mensagem do validador, apenas para diagnóstico
     */
    record Untrusted(CertPathValidatorException.Reason reason, String detail) implements ValidationResult {}

    /**
     * O caminho é confiável, mas o estado de revogação de {@code certificate} não pôde ser
     * determinado; {@code status} é o motivo, nos termos de {@link RevocationStatus} —
     * {@link RevocationStatus.Malformed} inclui o caso em que a evidência obtida pela biblioteca
     * foi rejeitada pelo verificador PKIX do JDK.
     */
    record RevocationUndetermined(X509Certificate certificate, RevocationStatus status) implements ValidationResult {}

    /** O acervo de âncoras não está disponível ou expirou; nenhuma validação é possível. */
    record TrustStoreUnavailable() implements ValidationResult {}
}
