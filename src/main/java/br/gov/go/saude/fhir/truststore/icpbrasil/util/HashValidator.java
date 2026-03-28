package br.gov.go.saude.fhir.truststore.icpbrasil.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.InputStream;

@Slf4j
public final class HashValidator {
    /**
     * Construtor privado para evitar instanciação.
     */
    private HashValidator() {
        throw new UnsupportedOperationException("Classe utilitária não deve ser instanciada");
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

    /**
     * Valida se o hash do InputStream corresponde ao hash esperado (SHA-256).
     *
     * @param inputStream Stream do artefato (ex: ZIP baixado)
     * @param expectedHex Hash esperado (hexadecimal, minúsculo ou maiúsculo)
     * @return true se coincidir, false caso contrário
     */
    public static boolean validateSha256(InputStream inputStream, String expectedHex) throws Exception {
        String calculatedHex = DigestUtils.sha256Hex(inputStream);

        // Compara ignorando diferenças de maiúscula/minúscula
        return calculatedHex.equalsIgnoreCase(expectedHex.trim());
    }

    /**
     * Valida se o hash do array de bytes corresponde ao hash esperado (SHA-512).
     *
     * @param data Array de bytes do artefato (ex: conteúdo de um arquivo ZIP)
     * @param expectedHex Hash esperado (hexadecimal, minúsculo ou maiúsculo)
     * @return true se coincidir, false caso contrário
     */
    public static boolean validateSha512(byte[] data, String expectedHex) {
        String calculatedHex = DigestUtils.sha512Hex(data);
        return calculatedHex.equalsIgnoreCase(expectedHex.trim());
    }

    /**
     * Valida se o hash do array de bytes corresponde ao hash esperado (SHA-256).
     *
     * @param data Array de bytes do artefato (ex: conteúdo de um arquivo ZIP)
     * @param expectedHex Hash esperado (hexadecimal, minúsculo ou maiúsculo)
     * @return true se coincidir, false caso contrário
     */
    public static boolean validateSha256(byte[] data, String expectedHex) {
        String calculatedHex = DigestUtils.sha256Hex(data);
        return calculatedHex.equalsIgnoreCase(expectedHex.trim());
    }
}