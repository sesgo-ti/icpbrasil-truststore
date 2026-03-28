package com.github.nogueiralegacy.truststore.config;

import io.minio.MinioClient;
import io.minio.messages.Bucket;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

@SpringBootTest
@ActiveProfiles("test")
@Disabled("Teste de integração com MinIO — requer storage.type=minio e servidor MinIO acessível")
public class MinioPropertiesTest {
    @Autowired
    MinioClient minioClient;

    @SneakyThrows
    @Test
    void testConnectionWithMinIO() {
        List<Bucket> buckets =  minioClient.listBuckets();

        assertFalse(buckets.isEmpty());
    }
}
