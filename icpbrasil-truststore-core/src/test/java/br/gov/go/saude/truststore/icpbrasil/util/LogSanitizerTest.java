package br.gov.go.saude.truststore.icpbrasil.util;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogSanitizerTest {

    @Test
    void testSanitizar_CaracteresDeControle_SubstituidosPorInterrogacao() {
        assertEquals("http://x/?? WARN forjado?fim", LogSanitizer.sanitizar("http://x/\r\n WARN forjado fim", 200));
    }

    @Test
    void testSanitizar_ControleC1_SubstituidoPorInterrogacao() {
        assertEquals("a?b", LogSanitizer.sanitizar("a\u0085b", 200));
    }

    @Test
    void testSanitizar_AcimaDoLimite_Trunca() {
        assertEquals("abc...", LogSanitizer.sanitizar("abcdef", 3));
        assertEquals("abc", LogSanitizer.sanitizar("abc", 3));
    }

    @Test
    void testSanitizar_Nulo_RetornaTextoNull() {
        assertEquals("null", LogSanitizer.sanitizar(null, 10));
    }

    @Test
    @SneakyThrows
    void testSanitizar_SubjectComQuebraDeLinha_RemoveQuebra() {
        X500NameBuilder nome = new X500NameBuilder(BCStyle.INSTANCE);
        nome.addRDN(BCStyle.CN, new DERUTF8String("Raiz\r\nERROR forjado"));
        String subject = new X500Principal(nome.build().getEncoded()).getName();
        assertTrue(subject.contains("\r\n"), subject);

        assertEquals("CN=Raiz??ERROR forjado", LogSanitizer.sanitizar(subject, 200));
    }
}
