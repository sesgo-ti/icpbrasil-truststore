package br.gov.go.saude.truststore.icpbrasil.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * Relógio controlado pelo teste: começa em um instante fixo e só avança quando o teste pede.
 */
public final class TestClock extends Clock {

    private volatile Instant instant;

    public TestClock(Instant instant) {
        this.instant = instant;
    }

    public void advance(Duration duration) {
        instant = instant.plus(duration);
    }

    public void set(Instant novoInstante) {
        instant = novoInstante;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return instant;
    }
}
