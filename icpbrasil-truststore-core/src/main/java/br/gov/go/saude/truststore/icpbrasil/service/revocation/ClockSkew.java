package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import java.time.Duration;

/**
 * Tolerância de relógio compartilhada pelas verificações temporais de OCSP e CRL.
 */
final class ClockSkew {

    /**
     * Diferença máxima admitida entre este host e o emissor da evidência. Mesmo valor do padrão do
     * OpenJDK ({@code com.sun.security.ocsp.clockSkew} e {@code RevocationChecker.MAX_CLOCK_SKEW}),
     * para que uma evidência aceita pelo validador da JVM não seja rejeitada aqui apenas por desvio
     * de relógio.
     */
    static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(15);

    private ClockSkew() {}
}
