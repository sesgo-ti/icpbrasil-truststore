package br.gov.go.saude.truststore.icpbrasil.repository;

import br.gov.go.saude.truststore.icpbrasil.config.S3Properties;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Repositório do acervo em armazenamento S3-compatível, com o mesmo contrato de geração do
 * {@link FilesystemTrustStoreRepository}.
 *
 * <p>Layout: os objetos de cada geração ficam sob {@code geracoes/<hash>/} (ZIP e última
 * confirmação) e o objeto de hash na raiz ({@code hash.txt}) é o ponteiro para a geração vigente,
 * gravado por último. Como o PUT de um objeto é atômico, leitores observam a geração nova completa
 * ou a anterior.</p>
 *
 * <p>Várias instâncias podem compartilhar o bucket: gerações são imutáveis e endereçadas pelo
 * hash, e o ponteiro segue o último PUT. A limpeza remove apenas gerações que não são a vigente nem
 * a anterior e cujos objetos não mudam há mais de {@link FilesystemTrustStoreRepository#RETENCAO}.
 * O layout legado (ZIP e confirmação na raiz) é lido como geração e removido no primeiro commit.</p>
 */
@Slf4j
public class S3Repository implements TrustStoreRepository {

    private static final String GERACOES = "geracoes/";
    private static final Pattern HASH = Pattern.compile("[0-9A-Fa-f]{1,128}");

    private final S3Client s3Client;
    private final String bucket;
    private final String ponteiro;
    private final String nomeZip;
    private final String nomeConfirmacao;

    public S3Repository(S3Client s3Client, TrustStoreConfig trustStoreConfig, S3Properties s3Properties) {
        this.s3Client = s3Client;
        this.bucket = s3Properties.getBucket();
        this.ponteiro = trustStoreConfig.getStorage().getHashFilePath();
        this.nomeZip = trustStoreConfig.getStorage().getTruststoreArchivePath();
        this.nomeConfirmacao = trustStoreConfig.getStorage().getConfirmationFilePath();
    }

    @Override
    public Optional<Geracao> recuperarGeracao() {
        Optional<String> hash = recuperarHash();
        if (hash.isEmpty()) {
            return Optional.empty();
        }
        String prefixo = GERACOES + hash.get() + "/";
        Optional<Geracao> geracao = ler(prefixo + nomeZip, prefixo + nomeConfirmacao, hash.get());
        if (geracao.isEmpty()) {
            geracao = ler(nomeZip, nomeConfirmacao, hash.get());
        }
        if (geracao.isEmpty()) {
            log.warn("Geração vigente {} incompleta no S3", hash.get());
        }
        return geracao;
    }

    @Override
    public Optional<String> recuperarHash() {
        return obter(ponteiro).map(bytes -> new String(bytes, StandardCharsets.UTF_8).trim())
                .filter(hash -> {
                    boolean valido = HASH.matcher(hash).matches();
                    if (!valido) {
                        log.warn("Ponteiro de geração com conteúdo inválido no S3: {}", ponteiro);
                    }
                    return valido;
                });
    }

    @Override
    public void armazenarGeracao(byte[] zip, String hash, Instant confirmacao) {
        if (hash == null || !HASH.matcher(hash).matches()) {
            throw new IllegalArgumentException("Hash de geração deve ser hexadecimal (até 128 dígitos)");
        }
        Optional<String> anterior = hashAnterior();
        String prefixo = GERACOES + hash + "/";
        gravar(prefixo + nomeZip, zip, "application/zip");
        gravar(prefixo + nomeConfirmacao, confirmacao.toString().getBytes(StandardCharsets.UTF_8), "text/plain");
        gravar(ponteiro, hash.getBytes(StandardCharsets.UTF_8), "text/plain");
        limpar(hash, anterior.orElse(null));
    }

    @Override
    public void armazenarUltimaConfirmacao(Instant instant) {
        String hash = recuperarHash().orElseThrow(
                () -> new IllegalStateException("Nenhuma geração vigente para renovar a confirmação"));
        String prefixo = GERACOES + hash + "/";
        if (obter(prefixo + nomeZip).isEmpty()) {
            obter(nomeZip).ifPresent(legado -> gravar(prefixo + nomeZip, legado, "application/zip"));
        }
        gravar(prefixo + nomeConfirmacao, instant.toString().getBytes(StandardCharsets.UTF_8), "text/plain");
    }

    private Optional<Geracao> ler(String chaveZip, String chaveConfirmacao, String hash) {
        Optional<byte[]> zip = obter(chaveZip);
        Optional<byte[]> confirmacao = obter(chaveConfirmacao);
        if (zip.isEmpty() || confirmacao.isEmpty()) {
            return Optional.empty();
        }
        Instant confirmadoEm = Instant.parse(new String(confirmacao.get(), StandardCharsets.UTF_8).trim());
        return Optional.of(new Geracao(zip.get(), hash, confirmadoEm));
    }

    /** Só orienta a limpeza: um ponteiro ilegível não impede o commit da geração nova. */
    private Optional<String> hashAnterior() {
        try {
            return recuperarHash();
        } catch (RuntimeException e) {
            log.warn("Ponteiro de geração ilegível antes do commit: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<byte[]> obter(String key) {
        try {
            byte[] bytes = s3Client.getObject(
                    GetObjectRequest.builder().bucket(bucket).key(key).build(),
                    ResponseTransformer.toBytes()
            ).asByteArray();
            return Optional.of(bytes);
        } catch (NoSuchKeyException e) {
            log.debug("Objeto não encontrado no S3: {}", key);
            return Optional.empty();
        } catch (RuntimeException e) {
            log.error("Falha ao recuperar {} do S3", key, e);
            throw new IllegalStateException("Falha ao recuperar " + key + " do S3", e);
        }
    }

    private void gravar(String key, byte[] conteudo, String contentType) {
        try {
            s3Client.putObject(
                    PutObjectRequest.builder()
                            .bucket(bucket)
                            .key(key)
                            .contentType(contentType)
                            .contentLength((long) conteudo.length)
                            .build(),
                    RequestBody.fromBytes(conteudo)
            );
        } catch (RuntimeException e) {
            log.error("Falha ao armazenar {} no S3", key, e);
            throw new IllegalStateException("Falha ao armazenar " + key + " no S3", e);
        }
    }

    /**
     * Remove o layout legado e as gerações que não são a vigente nem a anterior, cujos objetos não
     * mudam há mais de {@link FilesystemTrustStoreRepository#RETENCAO}. Falhas só são registradas:
     * a geração nova já está vigente.
     */
    private void limpar(String vigente, String anterior) {
        try {
            remover(nomeZip);
            remover(nomeConfirmacao);
            Set<String> preservadas = new HashSet<>();
            preservadas.add(vigente);
            if (anterior != null) {
                preservadas.add(anterior);
            }
            Instant limite = Instant.now().minus(FilesystemTrustStoreRepository.RETENCAO);
            Map<String, List<S3Object>> porGeracao = new HashMap<>();
            for (S3Object objeto : listar(GERACOES)) {
                String resto = objeto.key().substring(GERACOES.length());
                int barra = resto.indexOf('/');
                if (barra > 0) {
                    porGeracao.computeIfAbsent(resto.substring(0, barra), k -> new ArrayList<>()).add(objeto);
                }
            }
            porGeracao.forEach((hash, objetos) -> {
                boolean antiga = objetos.stream().allMatch(objeto -> objeto.lastModified().isBefore(limite));
                if (!preservadas.contains(hash) && antiga) {
                    objetos.forEach(objeto -> remover(objeto.key()));
                    log.info("Geração {} removida do S3", hash);
                }
            });
        } catch (RuntimeException e) {
            log.warn("Falha na limpeza de gerações antigas no S3: {}", e.getMessage());
        }
    }

    private List<S3Object> listar(String prefixo) {
        List<S3Object> objetos = new ArrayList<>();
        String continuacao = null;
        do {
            ListObjectsV2Response resposta = s3Client.listObjectsV2(ListObjectsV2Request.builder()
                    .bucket(bucket).prefix(prefixo).continuationToken(continuacao).build());
            objetos.addAll(resposta.contents());
            continuacao = Boolean.TRUE.equals(resposta.isTruncated()) ? resposta.nextContinuationToken() : null;
        } while (continuacao != null);
        return objetos;
    }

    private void remover(String key) {
        s3Client.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).build());
    }
}
