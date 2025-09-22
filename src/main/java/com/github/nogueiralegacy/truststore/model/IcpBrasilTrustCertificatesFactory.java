package com.github.nogueiralegacy.truststore.model;

import com.github.nogueiralegacy.truststore.util.Util;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * Fábrica responsável por criar artefatos de certificados ICP-Brasil
 * a partir do arquivo ZIP oficial publicado pelo ITI/ICP-Brasil e
 * validar sua integridade com o hash SHA-512 publicado em paralelo.

 * Fonte oficial:
 * - Artefato ZIP: https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip
 * - Hash SHA-512: https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/hashsha512.txt

 * Regras de validação:
 * - O hash deve ser calculado sobre o ZIP completo.
 * - Se o InputStream ou o hash forem nulos, uma exceção será lançada.
 * - Se o hash não coincidir, será lançada {@link SecurityHashValidationException}.
 */
@Getter
@Slf4j
public class IcpBrasilTrustCertificatesFactory {

    /** InputStream do ZIP validado e pronto para uso por outras operações. */
    private final InputStream zipInputStream;

    /** Hash SHA-512 esperado, publicado pelo ITI. */
    private final String expectedHash;

    /**
     * Construtor da fábrica. Realiza leitura completa do InputStream,
     * valida o hash e mantém o artefato em memória para uso posterior.
     *
     * @param inputStream InputStream do ZIP (não pode ser nulo).
     * @param hash        Valor esperado do hash SHA-512 em hexadecimal (não pode ser nulo/vazio).
     * @throws SecurityHashValidationException Se o hash for inválido ou ocorrer falha de leitura.
     */
    public IcpBrasilTrustCertificatesFactory(InputStream inputStream, String hash)
            throws SecurityHashValidationException {

        validateInputParameters(inputStream, hash);

        byte[] data;
        try {
            data = inputStream.readAllBytes();
            log.info("Artefato ICP-Brasil carregado. Tamanho: {} bytes", data.length);
        } catch (IOException e) {
            log.error("Falha ao carregar artefato ICP-Brasil: {}", e.getMessage());
            throw new UncheckedIOException("Erro ao carregar artefato ICP-Brasil", e);
        }

        this.zipInputStream = new ByteArrayInputStream(data);
        this.expectedHash = hash.trim();

        validateHash(new ByteArrayInputStream(data), expectedHash);
        log.info("Fábrica de certificados ICP-Brasil criada com sucesso e integridade validada");
    }

    /**
     * Valida os parâmetros de entrada do construtor.
     *
     * @param inputStream InputStream do artefato ZIP
     * @param hash Hash SHA-512 esperado
     * @throws IllegalArgumentException Se algum parâmetro for inválido
     */
    private void validateInputParameters(InputStream inputStream, String hash) {
        if (inputStream == null) {
            log.error("InputStream do artefato é obrigatório");
            throw new IllegalArgumentException("InputStream do artefato não pode ser nulo");
        }

        if (!StringUtils.hasText(hash)) {
            log.error("Hash SHA-512 é obrigatório");
            throw new IllegalArgumentException("Hash SHA-512 não pode ser nulo ou vazio");
        }

        String trimmedHash = hash.trim();
        if (!isValidSha512Hash(trimmedHash)) {
            log.error("Formato de hash SHA-512 inválido. Tamanho: {}", trimmedHash.length());
            throw new IllegalArgumentException(
                String.format("Hash deve conter exatamente 128 caracteres hexadecimais. " +
                            "Fornecido: %d caracteres", trimmedHash.length()));
        }
    }

    /**
     * Verifica se uma string representa um hash SHA-512 válido.
     *
     * @param hash String a ser validada
     * @return true se for um hash SHA-512 válido, false caso contrário
     */
    private boolean isValidSha512Hash(String hash) {
        final int SHA512_HEX_LENGTH = 128;
        final String SHA512_HEX_PATTERN = "^[a-fA-F0-9]{128}$";

        if (hash == null || hash.length() != SHA512_HEX_LENGTH) {
            return false;
        }
        // Verifica se contém apenas caracteres hexadecimais
        return hash.matches(SHA512_HEX_PATTERN);
    }

    /**
     * Valida se o conteúdo do InputStream corresponde ao hash esperado.
     *
     * @param stream InputStream do ZIP para validação.
     * @param expectedHash Hash SHA-512 esperado em formato hexadecimal.
     * @throws SecurityHashValidationException Se o hash não corresponder (falha de integridade).
     * @throws RuntimeException Se ocorrer erro técnico durante o cálculo do hash.
     */
    private void validateHash(InputStream stream, String expectedHash) throws SecurityHashValidationException {
        try {
            boolean valid = Util.validateSha512(stream, expectedHash);
            if (!valid) {
                log.error("Falha na validação de integridade do artefato ICP-Brasil");
                throw new SecurityHashValidationException("Integridade do artefato comprometida: hash SHA-512 inválido");
            }
        } catch (SecurityHashValidationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Erro durante validação de integridade: {}", e.getMessage());
            throw new RuntimeException("Falha técnica na validação de integridade", e);
        }
    }

    /**
     * Exceção customizada lançada em falhas de validação de integridade.
     */
    public static class SecurityHashValidationException extends RuntimeException {
        public SecurityHashValidationException(String message) {
            super(message);
        }

        public SecurityHashValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
