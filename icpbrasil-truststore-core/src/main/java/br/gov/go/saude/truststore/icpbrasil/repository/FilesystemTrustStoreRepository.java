package br.gov.go.saude.truststore.icpbrasil.repository;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

/**
 * Implementação do repositório de artefatos do truststore usando o sistema de arquivos local.
 *
 * <p>Armazena o ZIP de certificados ICP-Brasil, hash e timestamp de última confirmação
 * em um diretório configurável no disco local. Alternativa ao S3 para ambientes
 * com infraestrutura mínima.</p>
 *
 * <p>Ativado quando {@code icpbrasil-truststore.storage.type=filesystem} (padrão).</p>
 */
@Slf4j
public class FilesystemTrustStoreRepository implements TrustStoreRepository {

    private final Path baseDir;
    private final Path zipPath;
    private final Path hashPath;
    private final Path confirmationPath;

    public FilesystemTrustStoreRepository(TrustStoreConfig trustStoreConfig) {
        TrustStoreConfig.FilesystemConfig filesystem = trustStoreConfig.getFilesystem();
        if (filesystem == null || filesystem.getBaseDir() == null || filesystem.getBaseDir().isBlank()) {
            throw new IllegalStateException(
                    "[Erro de Configuração] Filesystem base-dir não configurado. Propriedade: 'icpbrasil-truststore.filesystem.base-dir'");
        }
        this.baseDir = Path.of(filesystem.getBaseDir()).normalize();
        this.zipPath = baseDir.resolve(trustStoreConfig.getStorage().getTruststoreArchivePath());
        this.hashPath = baseDir.resolve(trustStoreConfig.getStorage().getHashFilePath());
        this.confirmationPath = baseDir.resolve(trustStoreConfig.getStorage().getConfirmationFilePath());
        init();
    }

    private void init() {
        try {
            Files.createDirectories(zipPath.getParent());
            Files.createDirectories(hashPath.getParent());
            Files.createDirectories(confirmationPath.getParent());
            log.info("Repositório filesystem inicializado em: {}", baseDir.toAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException("Falha ao criar diretórios do repositório: " + baseDir, e);
        }
    }

    @Override
    public Optional<byte[]> recuperarZip() {
        if (!Files.exists(zipPath)) {
            return Optional.empty();
        }
        try {
            return Optional.of(Files.readAllBytes(zipPath));
        } catch (IOException e) {
            log.error("Falha ao recuperar ZIP do filesystem: {}", e.getMessage());
            throw new RuntimeException("Falha ao recuperar ZIP do filesystem", e);
        }
    }

    @Override
    public Optional<String> recuperarHash() {
        if (!Files.exists(hashPath)) {
            return Optional.empty();
        }
        try {
            return Optional.of(Files.readString(hashPath, StandardCharsets.UTF_8).trim());
        } catch (IOException e) {
            log.error("Falha ao recuperar hash do filesystem: {}", e.getMessage());
            throw new RuntimeException("Falha ao recuperar hash do filesystem", e);
        }
    }

    @Override
    public void armazenarZip(byte[] zip) {
        try {
            Files.write(zipPath, zip);
            log.debug("ZIP armazenado em: {}", zipPath);
        } catch (IOException e) {
            log.error("Falha ao armazenar ZIP no filesystem: {}", e.getMessage());
            throw new RuntimeException("Falha ao armazenar ZIP no filesystem", e);
        }
    }

    @Override
    public void armazenarHash(String hash) {
        try {
            Files.writeString(hashPath, hash, StandardCharsets.UTF_8);
            log.debug("Hash armazenado em: {}", hashPath);
        } catch (IOException e) {
            log.error("Falha ao armazenar hash no filesystem: {}", e.getMessage());
            throw new RuntimeException("Falha ao armazenar hash no filesystem", e);
        }
    }

    @Override
    public Optional<Instant> recuperarUltimaConfirmacao() {
        if (!Files.exists(confirmationPath)) {
            return Optional.empty();
        }
        try {
            String content = Files.readString(confirmationPath, StandardCharsets.UTF_8).trim();
            return Optional.of(Instant.parse(content));
        } catch (IOException e) {
            log.error("Falha ao recuperar última confirmação do filesystem: {}", e.getMessage());
            throw new RuntimeException("Falha ao recuperar última confirmação do filesystem", e);
        }
    }

    @Override
    public void armazenarUltimaConfirmacao(Instant instant) {
        try {
            Files.writeString(confirmationPath, instant.toString(), StandardCharsets.UTF_8);
            log.debug("Última confirmação armazenada em: {}", confirmationPath);
        } catch (IOException e) {
            log.error("Falha ao armazenar última confirmação no filesystem: {}", e.getMessage());
            throw new RuntimeException("Falha ao armazenar última confirmação no filesystem", e);
        }
    }
}
