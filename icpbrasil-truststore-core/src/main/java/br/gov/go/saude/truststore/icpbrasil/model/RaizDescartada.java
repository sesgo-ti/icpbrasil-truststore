package br.gov.go.saude.truststore.icpbrasil.model;

/**
 * Raiz autoassinada presente no acervo, mas fora da lista de raízes fixadas.
 *
 * @param subject           subject do certificado, em RFC 2253
 * @param fingerprintSha256 SHA-256 do DER, em hexadecimal minúsculo sem separadores
 */
public record RaizDescartada(String subject, String fingerprintSha256) {}
