package br.gov.go.saude.truststore.icpbrasil.service;

public class RecoveryIcpBrasilResourceException extends RuntimeException {
    public RecoveryIcpBrasilResourceException(String message) {
        super(message);
    }

    public RecoveryIcpBrasilResourceException(String message, Throwable cause) {
        super(message, cause);
    }
}