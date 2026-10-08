package br.gov.go.saude.truststore.icpbrasil.util;

import java.util.regex.Pattern;

/**
 * Prepara para o log valores vindos de fora (certificados, URLs, mensagens de erro), que podem
 * trazer quebras de linha para forjar entradas no log.
 */
public final class LogSanitizer {

    private static final Pattern CONTROLE = Pattern.compile("[\\p{Cc}\\u2028\\u2029]");

    private LogSanitizer() {
    }

    /**
     * Troca controles C0/C1 (inclusive CR/LF e NEL) e separadores de linha Unicode por {@code ?} e
     * trunca.
     *
     * @param valor         texto a registrar; {@code null} vira {@code "null"}
     * @param tamanhoMaximo caracteres mantidos antes de {@code "..."}
     */
    public static String sanitizar(String valor, int tamanhoMaximo) {
        if (valor == null) {
            return "null";
        }
        String limpo = CONTROLE.matcher(valor).replaceAll("?");
        return limpo.length() <= tamanhoMaximo ? limpo : limpo.substring(0, tamanhoMaximo) + "...";
    }
}
