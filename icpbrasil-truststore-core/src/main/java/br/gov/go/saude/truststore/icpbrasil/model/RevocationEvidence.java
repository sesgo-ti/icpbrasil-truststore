package br.gov.go.saude.truststore.icpbrasil.model;

import java.security.cert.X509CRL;

/**
 * Artefato verificado que fundamenta um veredicto de revogação ({@link RevocationStatus.Good} ou
 * {@link RevocationStatus.Revoked}). Serve a quem precisa da evidência além do veredicto: o
 * validador PKIX, que a submete também ao verificador da JVM, ou um consumidor que a preserve
 * para validação de longo prazo.
 */
public sealed interface RevocationEvidence {

    /** Resposta OCSP completa ({@code OCSPResponse}) em DER, tal como recebida do responder. */
    record OcspResponse(byte[] der) implements RevocationEvidence {}

    /** CRL completa e direta, já decodificada e com a assinatura do emissor verificada. */
    record Crl(X509CRL crl) implements RevocationEvidence {}
}
