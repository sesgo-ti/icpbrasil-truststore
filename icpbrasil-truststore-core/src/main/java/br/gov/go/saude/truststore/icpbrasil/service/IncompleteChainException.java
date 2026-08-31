package br.gov.go.saude.truststore.icpbrasil.service;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Lançada quando a montagem da cadeia de certificados não consegue
 * alcançar um certificado raiz (auto-assinado).
 *
 * <p>Carrega a cadeia parcial para fins de diagnóstico.</p>
 */
public class IncompleteChainException extends RuntimeException {
    private final List<X509Certificate> partialChain;

    public IncompleteChainException(String message, List<X509Certificate> partialChain) {
        super(message);
        this.partialChain = List.copyOf(partialChain);
    }

    public List<X509Certificate> getPartialChain() {
        return partialChain;
    }
}
