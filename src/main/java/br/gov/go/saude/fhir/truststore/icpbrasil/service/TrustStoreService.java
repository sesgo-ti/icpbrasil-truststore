package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.repository.TrustStoreRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.InputStream;
import java.time.Instant;
@Slf4j
@Service
public class TrustStoreService {
    private final TrustStoreRepository trustStoreRepository;
    private final IcpBrasilCertificateProvider icpBrasilCertificateProvider;
    private final TrustStoreConfig trustStoreConfig;

    public TrustStoreService(TrustStoreRepository trustStoreRepository,
                             IcpBrasilCertificateProvider icpBrasilCertificateProvider,
                             TrustStoreConfig trustStoreConfig) {
        this.trustStoreRepository = trustStoreRepository;
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
            trustStoreRepository.armazenarZip(zipData);
            trustStoreRepository.armazenarHash(hash);
            trustStoreRepository.armazenarUltimaConfirmacao(ultimaConfirmacao);
        } catch (Exception e) {
            throw new RuntimeException("Falha ao carregar artefatos no repositório local", e);
        }
    }

    public DisponibilidadeRepositorio verificarDisponibilidadeRepositorioLocal() {
        try (InputStream zipStream = trustStoreRepository.recuperarZip()) {
            String hash = trustStoreRepository.recuperarHash();
            Instant ultimaConfirmacao = trustStoreRepository.recuperarUltimaConfirmacao();

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
            String hashLocal = trustStoreRepository.recuperarHash();
            if (!hashIcpBrasil.equals(hashLocal)) {
                log.warn("O repositório local está desatualizado. Iniciando atualização.");
                reposicaoArtefatosRepositorioLocal();
            } else {
                log.info("O repositório local está sincronizado com a fonte ICP-Brasil");
                trustStoreRepository.armazenarUltimaConfirmacao(Instant.now());
            }

        } catch (Exception e) {
            log.error("Erro ao verificar sincronização do repositório local", e);
        }
    }

    public void assegurrarNaoExpiracaoCache() {
        try {
            Instant ultimaConfirmacao = trustStoreRepository.recuperarUltimaConfirmacao();
            long idadeCache = Instant.now().toEpochMilli() - ultimaConfirmacao.toEpochMilli();

            if (idadeCache <= trustStoreConfig.getRefreshIntervalMillis()) {
                log.info("Cache está atualizado e válido");
                Cache.setCacheValid(true);
                return;
            }

            // Falha na atualização do cache, mas ainda estável
            if (idadeCache <= trustStoreConfig.getCacheTtlCriticalMillis()) {
                log.warn("Falha na atualização do cache, utilizando cache local válido");
                Cache.setCacheValid(true);
                return;
            }

            // Cache passaou do tempo crítico de vida. Estado crítico
            if (idadeCache <= trustStoreConfig.getCacheTtlMaxMillis()) {
                log.error("Cache crítico - falha prolongada na atualização do cache, utilizando cache local válido");

                // TODO: Implementar notificação ao operador (e-mail, SMS, etc.)
                log.info("Operador notificado sobre estado crítico do cache");
                Cache.setCacheValid(true);
                return;
            }

            // Cache expirou completamente
            if (idadeCache > trustStoreConfig.getCacheTtlMaxMillis()) {
                log.error("Cache expirado - não há como garantir segurança");

                // TODO: Implementar notificação ao operador (e-mail, SMS, etc.)
                log.info("Operador notificado sobre expiração do cache");
                Cache.setCacheValid(false);
            }
        } catch (Exception e) {
            log.error("Erro ao assegurar não expiração do cache", e);
            Cache.setCacheValid(false);
        }
    }

    public void refresh() {
        try {
            log.info("Iniciando verificação automática de sincronização do repositório local");
            assegurarDisponibilidade();

            verificarSincronizacaoRepositorioLocal();
        } catch (Exception e) {
            log.error("Erro durante a verificação automática de sincronização do repositório local", e);
        } finally {
            assegurrarNaoExpiracaoCache();
            if (Cache.isCacheValid()) {
                var certificates = icpBrasilCertificateProvider.getCertificates();
                Cache.refreshCache(certificates);
            } else {
                log.warn("Cache inválido, não será atualizado");
            }
        }
    }

    public enum DisponibilidadeRepositorio {
        DISPONIVEL,
        INDISPONIVEL
    }
}
