package com.github.nogueiralegacy.truststore.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import com.github.nogueiralegacy.truststore.model.CertificateDTO;
import com.github.nogueiralegacy.truststore.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.vault.core.VaultTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Provedor de certificados confiáveis ARMAZENADOS no Vault como dados de aplicação.
 * 
 * IMPORTANTE: Não confundir com VaultCertificateManager:
 * - VaultCertificateProvider: Busca certificados CONFIÁVEIS armazenados no Vault (dados)
 * - VaultCertificateManager: Carrega certificado SSL do SERVIÇO Vault (infraestrutura)
 * 
 * Este provider busca certificados de terceiros que a aplicação deve confiar,
 * armazenados no key-value store do Vault para gestão centralizada.
 */
@Slf4j
@Component
public class VaultCertificateProvider implements CertificateProvider {
    private Map<String, CertificateDTO> certificatesData;

    private final VaultTemplate vaultTemplate;

    private final ObjectMapper objectMapper;

    private final String DEFAULT_CERT_PATH;

    public VaultCertificateProvider(VaultTemplate vaultTemplate, ObjectMapper objectMapper, TrustStoreConfig trustStoreConfig) {
        this.vaultTemplate = vaultTemplate;
        this.objectMapper = objectMapper;
        this.DEFAULT_CERT_PATH = trustStoreConfig.getVaultProperties().getCertificatePath();
    }

    @Override
    public List<X509Certificate> getCertificates() {
        try {
            loadCertificatesFromVault();

            if (certificatesData == null || certificatesData.isEmpty()) {
                return List.of();
            }

            log.info("Convertendo {} certificados confiáveis em X509", certificatesData.size());
            return certificatesData.entrySet().stream()
                    .map(this::convertToX509Certificate)
                    .toList();            
        } catch (Exception e) {
            log.error("Erro ao converter certificados confiáveis: {}", e.getMessage(), e);
            throw new RuntimeException("Erro no parse de certificados confiáveis do Vault", e);
        }
    }

    private X509Certificate convertToX509Certificate(Map.Entry<String, CertificateDTO> certificateEntry) {
        String certificateName = certificateEntry.getKey();
        CertificateDTO certificateDTO = certificateEntry.getValue();
        
        String pemContent = certificateDTO.getPem();
        if (!StringUtils.hasText(pemContent)) {
            throw new IllegalArgumentException("Certificado PEM vazio para o certificado: " + certificateName);
        }

        byte[] certificateBytes = pemContent.getBytes(StandardCharsets.UTF_8);
        try {
            return CertificateParser.parse(certificateBytes);
        } catch (CertificateParsingException e) {
            throw new RuntimeException("Erro ao fazer parse do certificado: " + certificateName, e);
        }
    }

    private void loadCertificatesFromVault() {
        try {
            if (certificatesData != null) {
                log.info("Atualizando certificados confiáveis armazenados no Vault");
            } else {
                log.info("Buscando certificados confiáveis no Vault (path: {})", DEFAULT_CERT_PATH);
            }
            
            certificatesData = new HashMap<>();

            var kvOps = vaultTemplate.opsForVersionedKeyValue("kv");
            var versionedSecret = kvOps.get(DEFAULT_CERT_PATH);
            var dataMap = versionedSecret.getRequiredData();

            for (var certEntry : dataMap.entrySet()) {
                CertificateDTO cert = objectMapper.readValue(
                        certEntry.getValue().toString(), CertificateDTO.class
                );

                if (cert == null) {
                    throw new IOException("Certificado nulo encontrado: " + certEntry.getKey());
                }

                certificatesData.put(certEntry.getKey(), cert);
            }
            
            if (certificatesData.isEmpty()) {
                log.warn("Nenhum certificado confiável encontrado no path: {}", DEFAULT_CERT_PATH);
            } else {
                log.info("Carregados {} certificados confiáveis do Vault", certificatesData.size());
            }
        } catch (Exception e) {
            log.error("Erro ao buscar certificados confiáveis no Vault: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao carregar certificados confiáveis do Vault", e);
        }
    }
}
