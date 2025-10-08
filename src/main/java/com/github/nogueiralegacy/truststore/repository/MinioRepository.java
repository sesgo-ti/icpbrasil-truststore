package com.github.nogueiralegacy.truststore.repository;

import io.minio.GetObjectArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

@Service
@Slf4j
public class MinioRepository implements TrustStoreRepository {
    private MinioClient minioClient;
    private final String BUCKET_NAME = "staging";
    private final String ZIP_OBJECT_NAME = "truststore/ACcompactado.zip";
    private final String HASH_OBJECT_NAME = "truststore/hash.txt";
    private final String ULTIMA_CONFIRMACAO_OBJECT_NAME = "truststore/ultima_confirmacao.txt";

    public MinioRepository(MinioClient minioClient) {
        this.minioClient = minioClient;
    }

    @Override
    public InputStream recuperarZip() {
        try {
            return minioClient.getObject(
                    GetObjectArgs.builder()
                            .bucket(BUCKET_NAME)
                            .object(ZIP_OBJECT_NAME)
                            .build()
            );
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
                            .bucket(BUCKET_NAME)
                            .object(HASH_OBJECT_NAME)
                            .build()
            ).readAllBytes();

            return new String(hashBytes, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            log.error("Failed to retrieve zip from MinIO", e);
            throw new RuntimeException("Failed to retrieve zip from MinIO", e);
        }
    }

    @Override
    public void armazenarZip(byte[] zip) {
        try (InputStream inputStream = new ByteArrayInputStream(zip)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(BUCKET_NAME)
                            .object(ZIP_OBJECT_NAME)
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
                            .bucket(BUCKET_NAME)
                            .object(HASH_OBJECT_NAME)
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
                            .bucket(BUCKET_NAME)
                            .object(ULTIMA_CONFIRMACAO_OBJECT_NAME)
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
                            .bucket(BUCKET_NAME)
                            .object(ULTIMA_CONFIRMACAO_OBJECT_NAME)
                            .stream(inputStream, instantBytes.length, -1)
                            .contentType("text/plain")
                            .build()
            );
        } catch (Exception e) {
            log.error("Failed to upload hash to MinIO", e);
            throw new RuntimeException("Failed to upload hash to MinIO", e);
        }
    }
}
