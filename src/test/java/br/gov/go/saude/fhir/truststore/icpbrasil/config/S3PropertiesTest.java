package br.gov.go.saude.fhir.truststore.icpbrasil.config;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;

import static org.junit.jupiter.api.Assertions.assertFalse;

@SpringBootTest
@Disabled("Teste de integração com S3 — requer storage.type=s3 e servidor S3 acessível")
public class S3PropertiesTest {

    @Autowired
    S3Client s3Client;

    @Test
    void testConnectionWithS3() {
        ListBucketsResponse response = s3Client.listBuckets();
        assertFalse(response.buckets().isEmpty());
    }
}
