package com.github.nogueiralegacy.truststore.service;

import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import com.github.nogueiralegacy.truststore.repository.MinioRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.InputStream;
import java.time.Instant;

@EnableScheduling
//Para o cron job não rodar em testes
@Profile("!test")
@Slf4j
@Service
public class TrustStoreService {
    private final MinioRepository minioRepository;
    private final IcpBrasilCertificateProvider icpBrasilCertificateProvider;
    private final TrustStoreConfig trustStoreConfig;
    private final long valor = 1000 * 5;

    public TrustStoreService(MinioRepository minioRepository,
                             IcpBrasilCertificateProvider icpBrasilCertificateProvider,
                             TrustStoreConfig trustStoreConfig) {
        this.minioRepository = minioRepository;
        this.icpBrasilCertificateProvider = icpBrasilCertificateProvider;
        this.trustStoreConfig = trustStoreConfig;
    }

    public void assegurarDisponibilidade() {
        if (verificarDisponibilidadeRepositorioLocal()
                .equals(DisponibilidadeRepositorio.DISPONIVEL)) {
            log.info("Artefatos estão disponíveis no repositório local");
        } else {
            log.warn("Artefatos não estão disponíveis no resppositório local");
            log.info("Iniciando processo de download e armazenamento dos artefatos do truststore no repositório local");
            try {
                reposicaoArtefatosRepositorioLocal();
            } catch (Exception e1) {
                log.error("Falha ao repor artefatos no repositório local", e1);
            }
        }
    }

    public void reposicaoArtefatosRepositorioLocal() {
        byte[] zipData = icpBrasilCertificateProvider.baixarZipIcpBrasil();
        String hash = icpBrasilCertificateProvider.baixarHashIcpBrasil();

        reposicaoArtefatosRepositorioLocal(zipData, hash);
    }

    public void reposicaoArtefatosRepositorioLocal(byte[] zipData, String hash) {
        Instant ultimaConfirmacao;
        try {
            ultimaConfirmacao =
                    icpBrasilCertificateProvider.validateZipIntegrity(zipData, hash);
        } catch (SecurityException e) {
            log.error("Falha na validação de integridade do zip ICP-Brasil durante a reposição: {}", e.getMessage());
            return;
        }
        carregarArtefatosNoRepositorioLocal(zipData, hash, ultimaConfirmacao);
    }

    public void carregarArtefatosNoRepositorioLocal(byte[] zipData, String hash, Instant ultimaConfirmacao) throws RuntimeException {
        log.info("Carregando artefatos no repositório local");
        try {
            minioRepository.armazenarZip(zipData);
            minioRepository.armazenarHash(hash);
            minioRepository.armazenarUltimaConfirmacao(ultimaConfirmacao);
        } catch (Exception e) {
            throw new RuntimeException("Falha ao carregar artefatos no repositório local", e);
        }
    }

    public DisponibilidadeRepositorio verificarDisponibilidadeRepositorioLocal() {
        try (InputStream zipStream = minioRepository.recuperarZip()) {
            String hash = minioRepository.recuperarHash();
            Instant ultimaConfirmacao = minioRepository.recuperarUltimaConfirmacao();

            boolean disponivel = zipStream != null && StringUtils.hasText(hash) && ultimaConfirmacao != null;

            return disponivel ? DisponibilidadeRepositorio.DISPONIVEL :
                    DisponibilidadeRepositorio.INDISPONIVEL;
        } catch (Exception e) {
            log.warn("Falha ao verificar repositório local", e);
            return DisponibilidadeRepositorio.INDISPONIVEL;
        }
    }

    public void verificarSincronizacaoRepositorioLocal() {
        log.info("Iniciando verificação de sincronização do repositório local");
        try {
            String hashIcpBrasil = icpBrasilCertificateProvider.baixarHashIcpBrasil();
            String hashLocal = minioRepository.recuperarHash();
            if (!hashIcpBrasil.equals(hashLocal)) {
                log.warn("O repositório local está desatualizado. Iniciando atualização.");
                reposicaoArtefatosRepositorioLocal();
            } else {
                log.info("O repositório local está sincronizado com a fonte ICP-Brasil");
            }

        } catch (Exception e) {
            log.error("Erro ao verificar sincronização do repositório local", e);
        }
    }

    @Scheduled(fixedRate = valor)
    public void refresh() {
        log.info("Iniciando verificação automática de sincronização do repositório local");
        assegurarDisponibilidade();

        verificarSincronizacaoRepositorioLocal();

        Cache.refreshCache(icpBrasilCertificateProvider.getCertificates());
    }

    public enum DisponibilidadeRepositorio {
        DISPONIVEL,
        INDISPONIVEL
    }
}
