package com.github.nogueiralegacy.truststore.repository;

import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

/**
 * Implementação do repositório de artefatos do truststore usando o sistema de arquivos local.
 *
 * <p>Armazena o ZIP de certificados ICP-Brasil, hash e timestamp de última confirmação
 * em um diretório configurável no disco local. Alternativa ao MinIO para ambientes
 * com infraestrutura mínima.</p>
 *
 * <p>Ativado quando {@code truststore.storage.type=filesystem} (padrão).</p>
 */
@Service
@Slf4j
@ConditionalOnProperty(name = "truststore.storage.type", havingValue = "filesystem", matchIfMissing = true)
public class FilesystemTrustStoreRepository implements TrustStoreRepository {

    private final Path baseDir;
    private final Path zipPath;
    private final Path hashPath;
    private final Path confirmationPath;

    public FilesystemTrustStoreRepository(TrustStoreConfig trustStoreConfig) {
        TrustStoreConfig.StorageConfig storage = trustStoreConfig.getStorage();
        this.baseDir = Path.of(storage.getFilesystemBaseDir()).normalize();
        this.zipPath = baseDir.resolve(storage.getTruststoreArchivePath());
        this.hashPath = baseDir.resolve(storage.getHashFilePath());
        this.confirmationPath = baseDir.resolve(storage.getConfirmationFilePath());
    }

    @PostConstruct
    public void init() {
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
    public InputStream recuperarZip() {
        try {
            if (!Files.exists(zipPath)) {
                throw new RuntimeException("Arquivo ZIP não encontrado: " + zipPath);
            }
            return new ByteArrayInputStream(Files.readAllBytes(zipPath));
        } catch (IOException e) {
            log.error("Falha ao recuperar ZIP do filesystem: {}", e.getMessage());
            throw new RuntimeException("Falha ao recuperar ZIP do filesystem", e);
        }
    }

    @Override
    public String recuperarHash() {
        try {
            if (!Files.exists(hashPath)) {
                throw new RuntimeException("Arquivo de hash não encontrado: " + hashPath);
            }
            return Files.readString(hashPath, StandardCharsets.UTF_8).trim();
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
    public Instant recuperarUltimaConfirmacao() {
        try {
            if (!Files.exists(confirmationPath)) {
                throw new RuntimeException("Arquivo de confirmação não encontrado: " + confirmationPath);
            }
            String content = Files.readString(confirmationPath, StandardCharsets.UTF_8).trim();
            return Instant.parse(content);
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
