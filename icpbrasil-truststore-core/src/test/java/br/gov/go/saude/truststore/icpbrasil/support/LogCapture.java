package br.gov.go.saude.truststore.icpbrasil.support;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Registra os avisos ({@code WARN} ou acima) de um logger enquanto aberto. Fechar restaura o
 * nível anterior, para que a captura de um teste não vaze para os seguintes.
 */
public final class LogCapture implements AutoCloseable {

    private final Logger logger;
    private final Level previousLevel;
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    private LogCapture(Class<?> source) {
        logger = (Logger) LoggerFactory.getLogger(source);
        previousLevel = logger.getLevel();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.WARN);
    }

    public static LogCapture warningsOf(Class<?> source) {
        return new LogCapture(source);
    }

    /** Mensagens já formatadas, na ordem em que foram registradas. */
    public List<String> messages() {
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    public boolean contains(String fragment) {
        return messages().stream().anyMatch(message -> message.contains(fragment));
    }

    @Override
    public void close() {
        logger.detachAppender(appender);
        logger.setLevel(previousLevel);
        appender.stop();
    }
}
