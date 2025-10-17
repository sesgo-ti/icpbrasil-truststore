package com.github.nogueiralegacy.truststore.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.Instant;

/**
 * Modelo que representa os dados de um certificado conforme definido no manual de gestão.
 * Este formato é usado para armazenar certificados no Vault.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateDTO {
    
    /**
     * URL de origem do certificado
     */
    @JsonProperty("sourceUrl")
    private String sourceUrl;
    
    /**
     * Fingerprint SHA-256 do certificado
     */
    @JsonProperty("fingerprintSha256")
    private String fingerprintSha256;
    
    /**
     * SPKI SHA-256 em Base64
     */
    @JsonProperty("spkiSha256_b64")
    private String spkiSha256Base64;
    
    /**
     * Formato do certificado (geralmente "pem")
     */
    @JsonProperty("format")
    private String format;
    
    /**
     * Emissor do certificado
     */
    @JsonProperty("issuer")
    private String issuer;
    
    /**
     * Sujeito do certificado
     */
    @JsonProperty("subject")
    private String subject;
    
    /**
     * Data de início da validade
     */
    @JsonProperty("notBefore")
    private Instant notBefore;
    
    /**
     * Data de fim da validade
     */
    @JsonProperty("notAfter")
    private Instant notAfter;
    
    /**
     * Conteúdo do certificado em formato PEM
     */
    @JsonProperty("pem")
    private String pem;
}