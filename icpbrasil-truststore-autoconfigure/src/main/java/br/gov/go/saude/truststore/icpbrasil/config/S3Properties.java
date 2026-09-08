package br.gov.go.saude.truststore.icpbrasil.config;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

/**
 * Propriedades de conexão com armazenamento S3-compatível (AWS S3, MinIO, Digital Ocean Spaces, etc.).
 *
 * <p>POJO puro de dados — sem Spring nem AWS SDK. O binding de {@code @ConfigurationProperties}
 * e a criação do {@code S3Client} são responsabilidade do módulo {@code autoconfigure}.</p>
 */
@Slf4j
@Getter
@Setter
public class S3Properties {

    @NotBlank(message = "S3 endpoint must be provided")
    private String endpoint;

    @NotBlank(message = "S3 region must be provided")
    private String region;

    @NotBlank(message = "S3 access key must be provided")
    private String accessKey;

    @NotBlank(message = "S3 secret key must be provided")
    private String secretKey;

    @NotBlank(message = "S3 bucket must be provided")
    private String bucket;

    /**
     * Caminho para o certificado PEM da CA usada pelo servidor S3 (classpath: ou file:).
     * Necessário apenas para endpoints S3 privados (MinIO, etc.) com CA não reconhecida pela JVM.
     * Quando não definido, o AWS SDK usa o JVM default truststore automaticamente.
     * Exemplo: icpbrasil-truststore.s3.ca-cert-path=file:/etc/ssl/certs/minha-ca.crt
     */
    private String caCertPath;
}
