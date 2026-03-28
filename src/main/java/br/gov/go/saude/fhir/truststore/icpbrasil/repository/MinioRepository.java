package br.gov.go.saude.fhir.truststore.icpbrasil.repository;

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
@ConditionalOnProperty(name = "truststore-icpbrasil.storage.type", havingValue = "minio")
public class MinioRepository implements TrustStoreRepository {
    private final MinioClient minioClient;
    private final TrustStoreConfig trustStoreConfig;

    public MinioRepository(MinioClient minioClient, TrustStoreConfig trustStoreConfig) {
        this.minioClient = minioClient;
        this.trustStoreConfig = trustStoreConfig;
    }

    @Override
    public InputStream recuperarZip() {
        try {
            var zipStream = minioClient.getObject(
                    GetObjectArgs.builder()
                            .bucket(trustStoreConfig.getStorage().getBucketName())
                            .object(trustStoreConfig.getStorage().getTruststoreArchivePath())
                            .build()
            );

            if (zipStream == null) {
                throw new RuntimeException("Zip file not found in MinIO");
            }
            return zipStream;
        } catch (Exception e) {
            log.error("Failed to retrieve zip from MinIO", e);
            throw new RuntimeException("Failed to retrieve zip from MinIO", e);
        }
    }

    @Override
    public String recuperarHash() {
        try {
            byte[] hashBytes = minioClient.getObject(
                    GetObjectArgs.builder()
                            .bucket(trustStoreConfig.getStorage().getBucketName())
                            .object(trustStoreConfig.getStorage().getHashFilePath())
                            .build()
            ).readAllBytes();

            return new String(hashBytes, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            log.error("Failed to retrieve hash from MinIO", e);
            throw new RuntimeException("Failed to retrieve hash from MinIO", e);
        }
    }

    @Override
    public void armazenarZip(byte[] zip) {
        try (InputStream inputStream = new ByteArrayInputStream(zip)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(trustStoreConfig.getStorage().getBucketName())
                            .object(trustStoreConfig.getStorage().getTruststoreArchivePath())
                            .stream(inputStream, zip.length, -1)
                            .contentType("application/zip")
                            .build()
            );
        } catch (Exception e) {
            log.error("Failed to upload zip to MinIO", e);
            throw new RuntimeException("Failed to upload zip to MinIO", e);
        }
    }

    @Override
    public void armazenarHash(String hash) {
        byte[] hashBytes = hash.getBytes(StandardCharsets.UTF_8);

        try (InputStream inputStream = new ByteArrayInputStream(hashBytes)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(trustStoreConfig.getStorage().getBucketName())
                            .object(trustStoreConfig.getStorage().getHashFilePath())
                            .stream(inputStream, hashBytes.length, -1)
                            .contentType("text/plain")
                            .build()
            );
        } catch (Exception e) {
            log.error("Failed to upload hash to MinIO", e);
            throw new RuntimeException("Failed to upload hash to MinIO", e);
        }
    }

    @Override
    public Instant recuperarUltimaConfirmacao() {
        try {
            byte[] instantBytes = minioClient.getObject(
                    GetObjectArgs.builder()
                            .bucket(trustStoreConfig.getStorage().getBucketName())
                            .object(trustStoreConfig.getStorage().getConfirmationFilePath())
                            .build()
            ).readAllBytes();

            String instantString = new String(instantBytes, StandardCharsets.UTF_8);
            return Instant.parse(instantString.trim());
        } catch (Exception e) {
            log.error("Failed to retrieve ultima_confirmacao from MinIO", e);
            throw new RuntimeException("Failed to retrieve ultima_confirmacao from MinIO", e);
        }
    }

    @Override
    public void armazenarUltimaConfirmacao(Instant instant) {
        byte[] instantBytes = instant.toString().getBytes(StandardCharsets.UTF_8);

        try (InputStream inputStream = new ByteArrayInputStream(instantBytes)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(trustStoreConfig.getStorage().getBucketName())
                            .object(trustStoreConfig.getStorage().getConfirmationFilePath())
                            .stream(inputStream, instantBytes.length, -1)
                            .contentType("text/plain")
                            .build()
            );
        } catch (Exception e) {
            log.error("Failed to upload ultima_confirmacao to MinIO", e);
            throw new RuntimeException("Failed to upload ultima_confirmacao to MinIO", e);
        }
    }
}
