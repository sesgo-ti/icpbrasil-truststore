package br.gov.go.saude.truststore.icpbrasil.repository;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository.Geracao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Commit de geração no filesystem: ZIP e confirmação são gravados no diretório da geração e só
 * então o ponteiro ({@code hash.txt}) passa a apontar para ela, por troca atômica. Os testes
 * reproduzem no disco o estado deixado por uma interrupção após cada etapa.
 */
class FilesystemTrustStoreRepositoryTest {

    private static final Instant T0 = Instant.parse("2026-01-10T12:00:00Z");
    private static final String HASH_A = "a".repeat(128);
    private static final String HASH_B = "b".repeat(128);
    private static final byte[] ZIP_A = {1, 2, 3};
    private static final byte[] ZIP_B = {4, 5, 6, 7};

    @TempDir
    Path baseDir;

    TrustStoreConfig config;
    FilesystemTrustStoreRepository repository;

    @BeforeEach
    void setUp() {
        config = new TrustStoreConfig();
        config.getFilesystem().setBaseDir(baseDir.toString());
        repository = new FilesystemTrustStoreRepository(config);
    }

    @Test
    void testRecuperarGeracao_RepositorioVazio_Vazio() {
        assertTrue(repository.recuperarGeracao().isEmpty());
        assertTrue(repository.recuperarHash().isEmpty());
    }

    @Test
    void testArmazenarGeracao_LeituraDevolveZipHashEConfirmacaoDaMesmaGeracao() {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);

        Geracao geracao = repository.recuperarGeracao().orElseThrow();
        assertArrayEquals(ZIP_A, geracao.zip());
        assertEquals(HASH_A, geracao.hash());
        assertEquals(T0, geracao.ultimaConfirmacao());
        assertEquals(HASH_A, repository.recuperarHash().orElseThrow());
        assertArrayEquals(ZIP_A, repository.recuperarZip().orElseThrow());
        assertEquals(T0, repository.recuperarUltimaConfirmacao().orElseThrow());
    }

    @Test
    void testArmazenarGeracao_NovaGeracao_SubstituiAAnterior() {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        Instant t1 = T0.plus(Duration.ofHours(2));

        repository.armazenarGeracao(ZIP_B, HASH_B, t1);

        Geracao geracao = repository.recuperarGeracao().orElseThrow();
        assertArrayEquals(ZIP_B, geracao.zip());
        assertEquals(HASH_B, geracao.hash());
        assertEquals(t1, geracao.ultimaConfirmacao());
    }

    @Test
    void testInterrupcaoAposGravarZip_LeitorObservaGeracaoAnterior_EReinicioConclui() throws Exception {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        Path parcial = Files.createDirectories(baseDir.resolve("geracoes").resolve(HASH_B));
        Files.write(parcial.resolve("ACcompactado.zip"), ZIP_B);

        assertEquals(HASH_A, repository.recuperarGeracao().orElseThrow().hash());

        FilesystemTrustStoreRepository reiniciado = new FilesystemTrustStoreRepository(config);
        reiniciado.armazenarGeracao(ZIP_B, HASH_B, T0);
        assertArrayEquals(ZIP_B, reiniciado.recuperarGeracao().orElseThrow().zip());
    }

    @Test
    void testInterrupcaoAntesDoPonteiro_GeracaoCompletaNaoReferenciada_LeitorObservaAnterior() throws Exception {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        Path completa = Files.createDirectories(baseDir.resolve("geracoes").resolve(HASH_B));
        Files.write(completa.resolve("ACcompactado.zip"), ZIP_B);
        Files.writeString(completa.resolve("ultima_confirmacao.txt"), T0.toString());

        Geracao geracao = repository.recuperarGeracao().orElseThrow();

        assertEquals(HASH_A, geracao.hash());
        assertArrayEquals(ZIP_A, geracao.zip());
    }

    @Test
    void testInterrupcaoDuranteEscritaTemporaria_TemporarioIgnoradoERemovidoQuandoAntigo() throws Exception {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        Path antigo = baseDir.resolve("hash.txt.tmp-interrompido");
        Path recente = baseDir.resolve("hash.txt.tmp-outra-instancia");
        Files.writeString(antigo, HASH_B);
        Files.writeString(recente, HASH_B);
        Files.setLastModifiedTime(antigo, FileTime.from(Instant.now().minus(Duration.ofDays(2))));

        assertEquals(HASH_A, repository.recuperarHash().orElseThrow());

        repository.armazenarGeracao(ZIP_B, HASH_B, T0);
        assertFalse(Files.exists(antigo));
        assertTrue(Files.exists(recente), "temporário recente pode ser o commit em andamento de outra instância");
    }

    @Test
    void testPonteiroParaGeracaoIncompleta_Vazio() throws Exception {
        Files.writeString(baseDir.resolve("hash.txt"), HASH_A);

        assertTrue(repository.recuperarGeracao().isEmpty());
    }

    @Test
    void testArmazenarUltimaConfirmacao_RenovaApenasAGeracaoVigente() {
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        Instant t1 = T0.plus(Duration.ofHours(2));

        repository.armazenarUltimaConfirmacao(t1);

        assertEquals(t1, repository.recuperarGeracao().orElseThrow().ultimaConfirmacao());
    }

    @Test
    void testArmazenarUltimaConfirmacao_SemGeracao_Falha() {
        assertThrows(IllegalStateException.class, () -> repository.armazenarUltimaConfirmacao(T0));
    }

    @Test
    void testArmazenarGeracao_HashForaDoAlfabetoHexadecimal_Rejeitado() {
        assertThrows(IllegalArgumentException.class, () -> repository.armazenarGeracao(ZIP_A, "../fora", T0));
        assertThrows(IllegalArgumentException.class, () -> repository.armazenarGeracao(ZIP_A, "", T0));
    }

    @Test
    void testLayoutLegado_LidoComoGeracaoERemovidoNoPrimeiroCommit() throws Exception {
        Files.write(baseDir.resolve("ACcompactado.zip"), ZIP_A);
        Files.writeString(baseDir.resolve("hash.txt"), HASH_A);
        Files.writeString(baseDir.resolve("ultima_confirmacao.txt"), T0.toString());

        Geracao legado = repository.recuperarGeracao().orElseThrow();
        assertArrayEquals(ZIP_A, legado.zip());
        assertEquals(HASH_A, legado.hash());
        assertEquals(T0, legado.ultimaConfirmacao());

        repository.armazenarGeracao(ZIP_B, HASH_B, T0);
        assertFalse(Files.exists(baseDir.resolve("ACcompactado.zip")));
        assertFalse(Files.exists(baseDir.resolve("ultima_confirmacao.txt")));
        assertEquals(HASH_B, repository.recuperarGeracao().orElseThrow().hash());
    }

    @Test
    void testLayoutLegado_RenovacaoMigraParaGeracao() throws Exception {
        Files.write(baseDir.resolve("ACcompactado.zip"), ZIP_A);
        Files.writeString(baseDir.resolve("hash.txt"), HASH_A);
        Files.writeString(baseDir.resolve("ultima_confirmacao.txt"), T0.toString());
        Instant t1 = T0.plus(Duration.ofHours(2));

        repository.armazenarUltimaConfirmacao(t1);

        Geracao geracao = repository.recuperarGeracao().orElseThrow();
        assertArrayEquals(ZIP_A, geracao.zip());
        assertEquals(t1, geracao.ultimaConfirmacao());
        assertTrue(Files.exists(baseDir.resolve("geracoes").resolve(HASH_A).resolve("ACcompactado.zip")));
    }

    @Test
    void testLimpeza_RemoveSomenteGeracoesNaoReferenciadasAntigas() throws Exception {
        String hashC = "c".repeat(128);
        String hashD = "d".repeat(128);
        repository.armazenarGeracao(ZIP_A, HASH_A, T0);
        repository.armazenarGeracao(ZIP_B, HASH_B, T0);
        repository.armazenarGeracao(new byte[]{8}, hashC, T0);
        envelhecer(HASH_A, Duration.ofDays(2));
        envelhecer(HASH_B, Duration.ofDays(2));

        repository.armazenarGeracao(new byte[]{9}, hashD, T0);

        assertEquals(List.of(hashC, hashD), geracoesNoDisco());
    }

    @Test
    void testDuasInstanciasNoMesmoDiretorio_CommitsConcorrentes_LeitorSempreObservaGeracaoCompleta() throws Exception {
        FilesystemTrustStoreRepository outra = new FilesystemTrustStoreRepository(config);
        Map<String, byte[]> conteudo = Map.of(HASH_A, ZIP_A, HASH_B, ZIP_B);
        ExecutorService executor = Executors.newFixedThreadPool(3);
        try {
            List<Future<?>> tarefas = new ArrayList<>();
            tarefas.add(executor.submit(() -> repetir(() -> repository.armazenarGeracao(ZIP_A, HASH_A, T0))));
            tarefas.add(executor.submit(() -> repetir(() -> outra.armazenarGeracao(ZIP_B, HASH_B, T0))));
            tarefas.add(executor.submit(() -> repetir(() -> repository.recuperarGeracao().ifPresent(geracao ->
                    assertArrayEquals(conteudo.get(geracao.hash()), geracao.zip())))));
            for (Future<?> tarefa : tarefas) {
                tarefa.get();
            }
        } finally {
            executor.shutdownNow();
        }

        Geracao ultima = repository.recuperarGeracao().orElseThrow();
        assertArrayEquals(conteudo.get(ultima.hash()), ultima.zip());
    }

    private static void repetir(Runnable acao) {
        for (int i = 0; i < 50; i++) {
            acao.run();
        }
    }

    private void envelhecer(String hash, Duration idade) throws Exception {
        Path dir = baseDir.resolve("geracoes").resolve(hash);
        FileTime antes = FileTime.from(Instant.now().minus(idade));
        try (Stream<Path> arquivos = Files.list(dir)) {
            for (Path arquivo : arquivos.toList()) {
                Files.setLastModifiedTime(arquivo, antes);
            }
        }
        Files.setLastModifiedTime(dir, antes);
    }

    private List<String> geracoesNoDisco() throws Exception {
        try (Stream<Path> dirs = Files.list(baseDir.resolve("geracoes"))) {
            return dirs.map(dir -> dir.getFileName().toString()).sorted().toList();
        }
    }
}
