package br.gov.go.saude.truststore.icpbrasil.repository;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Implementação do repositório de artefatos do truststore usando o sistema de arquivos local.
 *
 * <p>Layout: cada geração vive em {@code geracoes/<hash>/}, com o ZIP e a última confirmação; o
 * arquivo de hash na base ({@code hash.txt}) é o ponteiro para a geração vigente. Todo arquivo é
 * escrito num temporário e movido atomicamente para o destino, e o ponteiro é trocado por último:
 * leitores observam a geração nova completa ou a anterior, nunca uma mistura das duas.</p>
 *
 * <p>Várias instâncias podem compartilhar o diretório. Gerações são imutáveis e endereçadas pelo
 * hash — duas instâncias gravando a mesma geração escrevem o mesmo conteúdo —, e o ponteiro segue
 * a última troca. A limpeza só remove gerações que não são a vigente nem a anterior e temporários
 * sem modificação há mais de {@link #RETENCAO}, para não apagar o commit em andamento de outra
 * instância.</p>
 *
 * <p>Layout legado (ZIP e confirmação na base, sem {@code geracoes/}) é lido como geração e
 * migrado no primeiro commit ou renovação.</p>
 *
 * <p>Ativado quando {@code icpbrasil-truststore.storage.type=filesystem} (padrão).</p>
 */
@Slf4j
public class FilesystemTrustStoreRepository implements TrustStoreRepository {

    static final Duration RETENCAO = Duration.ofHours(24);
    private static final Pattern HASH = Pattern.compile("[0-9A-Fa-f]{1,128}");
    private static final String TEMPORARIO = ".tmp-";

    private final Path baseDir;
    private final Path geracoesDir;
    private final Path ponteiro;
    private final String nomeZip;
    private final String nomeConfirmacao;

    public FilesystemTrustStoreRepository(TrustStoreConfig trustStoreConfig) {
        TrustStoreConfig.FilesystemConfig filesystem = trustStoreConfig.getFilesystem();
        if (filesystem == null || filesystem.getBaseDir() == null || filesystem.getBaseDir().isBlank()) {
            throw new IllegalStateException(
                    "[Erro de Configuração] Filesystem base-dir não configurado. Propriedade: 'icpbrasil-truststore.filesystem.base-dir'");
        }
        this.baseDir = Path.of(filesystem.getBaseDir()).normalize();
        this.geracoesDir = baseDir.resolve("geracoes");
        this.ponteiro = baseDir.resolve(trustStoreConfig.getStorage().getHashFilePath());
        this.nomeZip = trustStoreConfig.getStorage().getTruststoreArchivePath();
        this.nomeConfirmacao = trustStoreConfig.getStorage().getConfirmationFilePath();
        init();
    }

    private void init() {
        try {
            Files.createDirectories(geracoesDir);
            Files.createDirectories(ponteiro.getParent());
            log.info("Repositório filesystem inicializado em: {}", baseDir.toAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException("Falha ao criar diretórios do repositório: " + baseDir, e);
        }
    }

    @Override
    public Optional<Geracao> recuperarGeracao() {
        Optional<String> hash = recuperarHash();
        if (hash.isEmpty()) {
            return Optional.empty();
        }
        try {
            Path dir = geracoesDir.resolve(hash.get());
            Optional<Geracao> geracao = ler(dir.resolve(nomeZip), dir.resolve(nomeConfirmacao), hash.get());
            if (geracao.isEmpty()) {
                geracao = ler(baseDir.resolve(nomeZip), baseDir.resolve(nomeConfirmacao), hash.get());
            }
            if (geracao.isEmpty()) {
                log.warn("Geração vigente {} incompleta no filesystem", hash.get());
            }
            return geracao;
        } catch (IOException e) {
            log.error("Falha ao recuperar geração do filesystem: {}", e.getMessage());
            throw new UncheckedIOException("Falha ao recuperar geração do filesystem", e);
        }
    }

    @Override
    public Optional<String> recuperarHash() {
        try {
            String hash = Files.readString(ponteiro, StandardCharsets.UTF_8).trim();
            if (!HASH.matcher(hash).matches()) {
                log.warn("Ponteiro de geração com conteúdo inválido em {}", ponteiro);
                return Optional.empty();
            }
            return Optional.of(hash);
        } catch (NoSuchFileException e) {
            return Optional.empty();
        } catch (IOException e) {
            log.error("Falha ao recuperar hash do filesystem: {}", e.getMessage());
            throw new UncheckedIOException("Falha ao recuperar hash do filesystem", e);
        }
    }

    @Override
    public void armazenarGeracao(byte[] zip, String hash, Instant confirmacao) {
        validarHash(hash);
        try {
            Optional<String> anterior = hashAnterior();
            Path dir = Files.createDirectories(geracoesDir.resolve(hash));
            gravarAtomicamente(dir.resolve(nomeZip), zip);
            gravarAtomicamente(dir.resolve(nomeConfirmacao), confirmacao.toString().getBytes(StandardCharsets.UTF_8));
            gravarAtomicamente(ponteiro, hash.getBytes(StandardCharsets.UTF_8));
            log.debug("Geração {} gravada e vigente em {}", hash, dir);
            limpar(hash, anterior.orElse(null));
        } catch (IOException e) {
            log.error("Falha ao armazenar geração no filesystem: {}", e.getMessage());
            throw new UncheckedIOException("Falha ao armazenar geração no filesystem", e);
        }
    }

    @Override
    public void armazenarUltimaConfirmacao(Instant instant) {
        String hash = recuperarHash().orElseThrow(
                () -> new IllegalStateException("Nenhuma geração vigente para renovar a confirmação"));
        try {
            Path dir = Files.createDirectories(geracoesDir.resolve(hash));
            Path zip = dir.resolve(nomeZip);
            Path zipLegado = baseDir.resolve(nomeZip);
            if (!Files.exists(zip) && Files.exists(zipLegado)) {
                gravarAtomicamente(zip, Files.readAllBytes(zipLegado));
            }
            gravarAtomicamente(dir.resolve(nomeConfirmacao), instant.toString().getBytes(StandardCharsets.UTF_8));
            log.debug("Última confirmação da geração {} armazenada", hash);
        } catch (IOException e) {
            log.error("Falha ao armazenar última confirmação no filesystem: {}", e.getMessage());
            throw new UncheckedIOException("Falha ao armazenar última confirmação no filesystem", e);
        }
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

    private static Optional<Geracao> ler(Path zip, Path confirmacao, String hash) throws IOException {
        try {
            byte[] conteudo = Files.readAllBytes(zip);
            Instant confirmadoEm = Instant.parse(Files.readString(confirmacao, StandardCharsets.UTF_8).trim());
            return Optional.of(new Geracao(conteudo, hash, confirmadoEm));
        } catch (NoSuchFileException e) {
            return Optional.empty();
        }
    }

    private static void validarHash(String hash) {
        if (hash == null || !HASH.matcher(hash).matches()) {
            throw new IllegalArgumentException("Hash de geração deve ser hexadecimal (até 128 dígitos)");
        }
    }

    /** Temporário exclusivo desta escrita, movido atomicamente sobre o destino. */
    private static void gravarAtomicamente(Path destino, byte[] conteudo) throws IOException {
        Path temporario = destino.resolveSibling(destino.getFileName() + TEMPORARIO + UUID.randomUUID());
        try {
            Files.write(temporario, conteudo);
            Files.move(temporario, destino, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temporario);
        }
    }

    /**
     * Remove o layout legado, temporários abandonados e gerações que não são a vigente nem a
     * anterior, sem modificação há mais de {@link #RETENCAO}. Falhas só são registradas: a geração
     * nova já está vigente.
     */
    private void limpar(String vigente, String anterior) {
        try {
            Files.deleteIfExists(baseDir.resolve(nomeZip));
            Files.deleteIfExists(baseDir.resolve(nomeConfirmacao));
            Instant limite = Instant.now().minus(RETENCAO);
            removerTemporariosAntigos(ponteiro.getParent(), limite);
            Set<String> preservadas = new HashSet<>();
            preservadas.add(vigente);
            if (anterior != null) {
                preservadas.add(anterior);
            }
            try (DirectoryStream<Path> geracoes = Files.newDirectoryStream(geracoesDir, Files::isDirectory)) {
                for (Path dir : geracoes) {
                    if (preservadas.contains(dir.getFileName().toString())) {
                        removerTemporariosAntigos(dir, limite);
                    } else if (Files.getLastModifiedTime(dir).toInstant().isBefore(limite)) {
                        removerRecursivo(dir);
                        log.info("Geração {} removida do filesystem", dir.getFileName());
                    }
                }
            }
        } catch (IOException | UncheckedIOException e) {
            log.warn("Falha na limpeza de gerações antigas: {}", e.getMessage());
        }
    }

    private static void removerTemporariosAntigos(Path dir, Instant limite) throws IOException {
        try (DirectoryStream<Path> arquivos = Files.newDirectoryStream(dir,
                arquivo -> arquivo.getFileName().toString().contains(TEMPORARIO))) {
            for (Path arquivo : arquivos) {
                if (Files.getLastModifiedTime(arquivo).toInstant().isBefore(limite)) {
                    Files.deleteIfExists(arquivo);
                }
            }
        }
    }

    private static void removerRecursivo(Path dir) throws IOException {
        try (Stream<Path> caminhos = Files.walk(dir)) {
            for (Path caminho : caminhos.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(caminho);
            }
        }
    }
}
