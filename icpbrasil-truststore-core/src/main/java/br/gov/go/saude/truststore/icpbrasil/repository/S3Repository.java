package br.gov.go.saude.truststore.icpbrasil.repository;

import br.gov.go.saude.truststore.icpbrasil.config.S3Properties;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

@Slf4j
public class S3Repository implements TrustStoreRepository {

    private final S3Client s3Client;
    private final TrustStoreConfig trustStoreConfig;
    private final S3Properties s3Properties;

    public S3Repository(S3Client s3Client, TrustStoreConfig trustStoreConfig, S3Properties s3Properties) {
        this.s3Client = s3Client;
        this.trustStoreConfig = trustStoreConfig;
        this.s3Properties = s3Properties;
    }

    @Override
    public Optional<byte[]> recuperarZip() {
        try {
            byte[] bytes = s3Client.getObject(
                    GetObjectRequest.builder()
                            .bucket(s3Properties.getBucket())
                            .key(trustStoreConfig.getStorage().getTruststoreArchivePath())
                            .build(),
                    ResponseTransformer.toBytes()
            ).asByteArray();

            return Optional.of(bytes);
        } catch (NoSuchKeyException e) {
            log.debug("Zip não encontrado no S3: {}", trustStoreConfig.getStorage().getTruststoreArchivePath());
            return Optional.empty();
        } catch (Exception e) {
            log.error("Falha ao recuperar zip do S3", e);
            throw new RuntimeException("Falha ao recuperar zip do S3", e);
        }
    }

    @Override
    public Optional<String> recuperarHash() {
        try {
            String hash = s3Client.getObject(
                    GetObjectRequest.builder()
                            .bucket(s3Properties.getBucket())
                            .key(trustStoreConfig.getStorage().getHashFilePath())
                            .build(),
                    ResponseTransformer.toBytes()
            ).asUtf8String().trim();
            return Optional.of(hash);
        } catch (NoSuchKeyException e) {
            log.debug("Hash não encontrado no S3: {}", trustStoreConfig.getStorage().getHashFilePath());
            return Optional.empty();
        } catch (Exception e) {
            log.error("Falha ao recuperar hash do S3", e);
            throw new RuntimeException("Falha ao recuperar hash do S3", e);
        }
    }

    @Override
    public void armazenarZip(byte[] zip) {
        try {
            s3Client.putObject(
                    PutObjectRequest.builder()
                            .bucket(s3Properties.getBucket())
                            .key(trustStoreConfig.getStorage().getTruststoreArchivePath())
                            .contentType("application/zip")
                            .contentLength((long) zip.length)
                            .build(),
                    RequestBody.fromBytes(zip)
            );
        } catch (Exception e) {
            log.error("Falha ao armazenar zip no S3", e);
            throw new RuntimeException("Falha ao armazenar zip no S3", e);
        }
    }

    @Override
    public void armazenarHash(String hash) {
        byte[] hashBytes = hash.getBytes(StandardCharsets.UTF_8);
        try {
            s3Client.putObject(
                    PutObjectRequest.builder()
                            .bucket(s3Properties.getBucket())
                            .key(trustStoreConfig.getStorage().getHashFilePath())
                            .contentType("text/plain")
                            .contentLength((long) hashBytes.length)
                            .build(),
                    RequestBody.fromBytes(hashBytes)
            );
        } catch (Exception e) {
            log.error("Falha ao armazenar hash no S3", e);
            throw new RuntimeException("Falha ao armazenar hash no S3", e);
        }
    }

    @Override
    public Optional<Instant> recuperarUltimaConfirmacao() {
        try {
            String value = s3Client.getObject(
                    GetObjectRequest.builder()
                            .bucket(s3Properties.getBucket())
                            .key(trustStoreConfig.getStorage().getConfirmationFilePath())
                            .build(),
                    ResponseTransformer.toBytes()
            ).asUtf8String().trim();

            return Optional.of(Instant.parse(value));
        } catch (NoSuchKeyException e) {
            log.debug("Confirmação não encontrada no S3: {}", trustStoreConfig.getStorage().getConfirmationFilePath());
            return Optional.empty();
        } catch (Exception e) {
            log.error("Falha ao recuperar ultima_confirmacao do S3", e);
            throw new RuntimeException("Falha ao recuperar ultima_confirmacao do S3", e);
        }
    }

    @Override
    public void armazenarUltimaConfirmacao(Instant instant) {
        byte[] instantBytes = instant.toString().getBytes(StandardCharsets.UTF_8);
        try {
            s3Client.putObject(
                    PutObjectRequest.builder()
                            .bucket(s3Properties.getBucket())
                            .key(trustStoreConfig.getStorage().getConfirmationFilePath())
                            .contentType("text/plain")
                            .contentLength((long) instantBytes.length)
                            .build(),
                    RequestBody.fromBytes(instantBytes)
            );
        } catch (Exception e) {
            log.error("Falha ao armazenar ultima_confirmacao no S3", e);
            throw new RuntimeException("Falha ao armazenar ultima_confirmacao no S3", e);
        }
    }
}
