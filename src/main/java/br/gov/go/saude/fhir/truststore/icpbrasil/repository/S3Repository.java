package br.gov.go.saude.fhir.truststore.icpbrasil.repository;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.S3Properties;
import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import io.minio.GetObjectArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

@Service
@Slf4j
@ConditionalOnProperty(name = "truststore-icpbrasil.storage.type", havingValue = "s3")
public class S3Repository implements TrustStoreRepository {
    private final MinioClient minioClient;
    private final TrustStoreConfig trustStoreConfig;
    private final S3Properties s3Properties;

    public S3Repository(MinioClient minioClient, TrustStoreConfig trustStoreConfig, S3Properties s3Properties) {
        this.minioClient = minioClient;
        this.trustStoreConfig = trustStoreConfig;
        this.s3Properties = s3Properties;
    }

    @Override
    public InputStream recuperarZip() {
        try {
            var zipStream = minioClient.getObject(
                    GetObjectArgs.builder()
                            .bucket(s3Properties.getBucket())
                            .object(trustStoreConfig.getStorage().getTruststoreArchivePath())
                            .build()
            );

            if (zipStream == null) {
                throw new RuntimeException("Zip file not found in S3");
            }
            return zipStream;
        } catch (Exception e) {
            log.error("Failed to retrieve zip from S3", e);
            throw new RuntimeException("Failed to retrieve zip from S3", e);
        }
    }

    @Override
    public String recuperarHash() {
        try {
            byte[] hashBytes = minioClient.getObject(
                    GetObjectArgs.builder()
                            .bucket(s3Properties.getBucket())
                            .object(trustStoreConfig.getStorage().getHashFilePath())
                            .build()
            ).readAllBytes();

            return new String(hashBytes, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            log.error("Failed to retrieve hash from S3", e);
            throw new RuntimeException("Failed to retrieve hash from S3", e);
        }
    }

    @Override
    public void armazenarZip(byte[] zip) {
        try (InputStream inputStream = new ByteArrayInputStream(zip)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(s3Properties.getBucket())
                            .object(trustStoreConfig.getStorage().getTruststoreArchivePath())
                            .stream(inputStream, zip.length, -1)
                            .contentType("application/zip")
                            .build()
            );
        } catch (Exception e) {
            log.error("Failed to upload zip to S3", e);
            throw new RuntimeException("Failed to upload zip to S3", e);
        }
    }

    @Override
    public void armazenarHash(String hash) {
        byte[] hashBytes = hash.getBytes(StandardCharsets.UTF_8);

        try (InputStream inputStream = new ByteArrayInputStream(hashBytes)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(s3Properties.getBucket())
                            .object(trustStoreConfig.getStorage().getHashFilePath())
                            .stream(inputStream, hashBytes.length, -1)
                            .contentType("text/plain")
                            .build()
            );
        } catch (Exception e) {
            log.error("Failed to upload hash to S3", e);
            throw new RuntimeException("Failed to upload hash to S3", e);
        }
    }

    @Override
    public Instant recuperarUltimaConfirmacao() {
        try {
            byte[] instantBytes = minioClient.getObject(
                    GetObjectArgs.builder()
                            .bucket(s3Properties.getBucket())
                            .object(trustStoreConfig.getStorage().getConfirmationFilePath())
                            .build()
            ).readAllBytes();

            String instantString = new String(instantBytes, StandardCharsets.UTF_8);
            return Instant.parse(instantString.trim());
        } catch (Exception e) {
            log.error("Failed to retrieve ultima_confirmacao from S3", e);
            throw new RuntimeException("Failed to retrieve ultima_confirmacao from S3", e);
        }
    }

    @Override
    public void armazenarUltimaConfirmacao(Instant instant) {
        byte[] instantBytes = instant.toString().getBytes(StandardCharsets.UTF_8);

        try (InputStream inputStream = new ByteArrayInputStream(instantBytes)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(s3Properties.getBucket())
                            .object(trustStoreConfig.getStorage().getConfirmationFilePath())
                            .stream(inputStream, instantBytes.length, -1)
                            .contentType("text/plain")
                            .build()
            );
        } catch (Exception e) {
            log.error("Failed to upload ultima_confirmacao to S3", e);
            throw new RuntimeException("Failed to upload ultima_confirmacao to S3", e);
        }
    }
}
