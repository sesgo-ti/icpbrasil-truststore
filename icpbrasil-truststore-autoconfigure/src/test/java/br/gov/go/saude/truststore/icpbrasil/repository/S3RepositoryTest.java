package br.gov.go.saude.truststore.icpbrasil.repository;

import br.gov.go.saude.truststore.icpbrasil.config.S3Properties;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository.Geracao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Mesmo contrato de geração do filesystem sobre S3: objetos da geração em {@code geracoes/<hash>/}
 * e ponteiro gravado por último (o PUT de um objeto é atômico). O bucket é simulado em memória.
 */
class S3RepositoryTest {

    private static final Instant T0 = Instant.parse("2026-01-10T12:00:00Z");
    private static final String HASH_A = "a".repeat(128);
    private static final String HASH_B = "b".repeat(128);
    private static final byte[] ZIP_A = {1, 2, 3};
    private static final byte[] ZIP_B = {4, 5, 6, 7};

    private record Objeto(byte[] conteudo, Instant modificadoEm) {}

    Map<String, Objeto> bucket;
    S3Repository repository;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        bucket = new ConcurrentSkipListMap<>();
        S3Client s3 = mock(S3Client.class);
        when(s3.getObject(any(GetObjectRequest.class), any(ResponseTransformer.class))).thenAnswer(inv -> {
            GetObjectRequest request = inv.getArgument(0);
            Objeto objeto = bucket.get(request.key());
            if (objeto == null) {
                throw NoSuchKeyException.builder().message(request.key()).build();
            }
            return ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), objeto.conteudo());
        });
        when(s3.putObject(any(PutObjectRequest.class), any(RequestBody.class))).thenAnswer(inv -> {
            PutObjectRequest request = inv.getArgument(0);
            RequestBody body = inv.getArgument(1);
            try (InputStream in = body.contentStreamProvider().newStream()) {
                bucket.put(request.key(), new Objeto(in.readAllBytes(), Instant.now()));
            }
            return null;
        });
        when(s3.listObjectsV2(any(ListObjectsV2Request.class))).thenAnswer(inv -> {
            ListObjectsV2Request request = inv.getArgument(0);
            List<S3Object> contents = bucket.entrySet().stream()
                    .filter(e -> e.getKey().startsWith(request.prefix()))
                    .map(e -> S3Object.builder().key(e.getKey()).lastModified(e.getValue().modificadoEm()).build())
                    .toList();
            return ListObjectsV2Response.builder().contents(contents).isTruncated(false).build();
        });
        when(s3.deleteObject(any(DeleteObjectRequest.class))).thenAnswer(inv -> {
            bucket.remove(((DeleteObjectRequest) inv.getArgument(0)).key());
            return null;
        });

        S3Properties properties = new S3Properties();
        properties.setBucket("acervo");
        repository = new S3Repository(s3, new TrustStoreConfig(), properties);
    }

    @Test
    void testArmazenarGeracao_LeituraDevolveAMesmaGeracaoEPonteiroGravadoPorUltimo() {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);

        Geracao geracao = repository.recuperarGeracao().orElseThrow();
        assertArrayEquals(ZIP_A, geracao.zip());
        assertEquals(HASH_A, geracao.hash());
        assertEquals(T0, geracao.ultimaConfirmacao());
        assertTrue(bucket.containsKey("geracoes/" + HASH_A + "/ACcompactado.zip"));
        assertEquals(HASH_A, texto("hash.txt"));
    }

    @Test
    void testInterrupcaoAntesDoPonteiro_LeitorObservaGeracaoAnterior() {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        bucket.put("geracoes/" + HASH_B + "/ACcompactado.zip", new Objeto(ZIP_B, Instant.now()));
        bucket.put("geracoes/" + HASH_B + "/ultima_confirmacao.txt", new Objeto(T0.toString().getBytes(StandardCharsets.UTF_8), Instant.now()));

        assertEquals(HASH_A, repository.recuperarGeracao().orElseThrow().hash());
    }

    @Test
    void testArmazenarUltimaConfirmacao_RenovaGeracaoVigente() {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        Instant t1 = T0.plus(Duration.ofHours(2));

        repository.armazenarUltimaConfirmacao(t1);

        assertEquals(t1, repository.recuperarGeracao().orElseThrow().ultimaConfirmacao());
        assertThrows(IllegalArgumentException.class, () -> repository.armazenarGeracao(ZIP_A, "../x", T0));
    }

    @Test
    void testLayoutLegado_LidoEMigradoNoPrimeiroCommit() {
        bucket.put("ACcompactado.zip", new Objeto(ZIP_A, Instant.now()));
        bucket.put("hash.txt", new Objeto(HASH_A.getBytes(StandardCharsets.UTF_8), Instant.now()));
        bucket.put("ultima_confirmacao.txt", new Objeto(T0.toString().getBytes(StandardCharsets.UTF_8), Instant.now()));

        assertArrayEquals(ZIP_A, repository.recuperarGeracao().orElseThrow().zip());

        repository.armazenarGeracao(ZIP_B, HASH_B, T0);
        assertFalse(bucket.containsKey("ACcompactado.zip"));
        assertFalse(bucket.containsKey("ultima_confirmacao.txt"));
        assertEquals(HASH_B, repository.recuperarGeracao().orElseThrow().hash());
    }

    @Test
    void testLimpeza_RemoveSomenteGeracoesNaoReferenciadasAntigas() {
        String hashC = "c".repeat(128);
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        repository.armazenarGeracao(ZIP_B, HASH_B, T0);
        envelhecer(HASH_A);

        repository.armazenarGeracao(new byte[]{8}, hashC, T0);

        assertTrue(bucket.keySet().stream().noneMatch(key -> key.startsWith("geracoes/" + HASH_A)));
        assertTrue(bucket.containsKey("geracoes/" + HASH_B + "/ACcompactado.zip"));
        assertTrue(bucket.containsKey("geracoes/" + hashC + "/ACcompactado.zip"));
    }

    private void envelhecer(String hash) {
        Instant antes = Instant.now().minus(Duration.ofDays(2));
        bucket.replaceAll((key, objeto) -> key.startsWith("geracoes/" + hash + "/")
                ? new Objeto(objeto.conteudo(), antes) : objeto);
    }

    private String texto(String key) {
        return new String(bucket.get(key).conteudo(), StandardCharsets.UTF_8);
    }
}
