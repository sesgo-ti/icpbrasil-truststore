package br.gov.go.saude.truststore.icpbrasil;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * O LICENSE do projeto é copiado para {@code META-INF/} das classes do módulo e, daí, para os JARs
 * binário e de sources. A verificação olha o diretório de saída deste módulo, e não o classpath,
 * onde o {@code META-INF/LICENSE} de qualquer dependência também seria encontrado.
 */
class LicencaEmpacotadaTest {

    @Test
    void testLicenca_CopiadaParaMetaInfDoModulo() throws Exception {
        Path licenca = Path.of("target/classes/META-INF/LICENSE");

        assertEquals(Files.readString(Path.of("../LICENSE")), Files.readString(licenca));
    }
}
