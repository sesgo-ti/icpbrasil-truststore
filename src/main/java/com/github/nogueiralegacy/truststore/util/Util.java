package com.github.nogueiralegacy.truststore.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Component;

import java.io.InputStream;

@Slf4j
@Component
public class Util {

    public InputStream getResource(String resourceName) throws NullPointerException {
        if (resourceName == null) {
           log.error("resourceName não pode ser null");
        }
        InputStream is = this.getClass().getClassLoader().getResourceAsStream(resourceName);
        if (is == null) {
            log.warn("Recurso {} não encontrado", resourceName);
        }

        return is;
    }


    /**
     * Valida se o hash do InputStream corresponde ao hash esperado (SHA-512).
     *
     * @param inputStream Stream do artefato (ex: ZIP baixado)
     * @param expectedHex Hash esperado (hexadecimal, minúsculo ou maiúsculo)
     * @return true se coincidir, false caso contrário
     */
    public static boolean validateSha512(InputStream inputStream, String expectedHex) throws Exception {
        String calculatedHex = DigestUtils.sha512Hex(inputStream);

        // Compara ignorando diferenças de maiúscula/minúscula
        return calculatedHex.equalsIgnoreCase(expectedHex.trim());
    }
}
