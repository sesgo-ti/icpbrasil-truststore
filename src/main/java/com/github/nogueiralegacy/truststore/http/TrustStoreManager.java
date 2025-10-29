package com.github.nogueiralegacy.truststore.http;

import com.github.nogueiralegacy.truststore.model.CertificateParser;
import com.github.nogueiralegacy.truststore.service.VaultCertificateProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Gerenciador do Trust Store principal da aplicação para validar conexões
 * a outros serviços (não ao Vault).
 * 
 * IMPORTANTE: Depende explicitamente do VaultClientHttpRequestFactory estar inicializado
 * pois precisa buscar certificados confiáveis do Vault, que por sua vez requer
 * o certificado SSL do Vault estar carregado primeiro.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TrustStoreManager {
    
    private final VaultCertificateProvider vaultCertificateProvider;
    
    /**
     * Cria o SSL Context principal EXCLUSIVAMENTE com certificados confiáveis do Vault.
     * Este SSL Context é usado para validar outros serviços (não o Vault).
     * IMPORTANTE: Não inclui certificados do sistema Java padrão por questões de segurança.
     */
    @Bean
    public SSLContext sslContext() {
        try {
            log.info("Criando SSL context principal com certificados confiáveis do Vault");
            
            KeyStore trustStore = createTrustStore();
            addTrustedCertificatesFromVault(trustStore);
            
            return buildSSLContext(trustStore);
            
        } catch (Exception e) {
            log.error("Erro crítico ao criar SSL context principal: {}", e.getMessage(), e);
            throw new TrustStoreCreationException("Falha na criação do Trust Store principal", e);
        }
    }
    
    private KeyStore createTrustStore() throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        
        return trustStore;
    }
    
    private void addTrustedCertificatesFromVault(KeyStore trustStore) {
        try {
            List<X509Certificate> certificates = vaultCertificateProvider.getCertificates();
            
            if (certificates.isEmpty()) {
                log.error("Nenhum certificado confiável encontrado no Vault - TrustStore ficará vazio!");
                throw new TrustStoreCreationException("TrustStore não pode ser criado sem certificados do Vault", null);
            }

            for (X509Certificate certificate : certificates) {
                addCertificateToTrustStore(trustStore, certificate);
            }
            
            log.info("Adicionados {} certificados confiáveis do Vault ao TrustStore principal", certificates.size());
            
        } catch (TrustStoreCreationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Erro crítico ao carregar certificados confiáveis do Vault: {}", e.getMessage(), e);
            throw new TrustStoreCreationException("Falha ao carregar certificados do Vault", e);
        }
    }
    
    private void addCertificateToTrustStore(KeyStore trustStore, X509Certificate certificate) {
        try {
            String certName = extractCertName(certificate);
            trustStore.setCertificateEntry(certName, certificate);
            log.debug("Certificado confiável adicionado: {}", certName);
            
        } catch (Exception e) {
            String subject = certificate.getSubjectX500Principal().getName();
            log.error("Erro ao adicionar certificado confiável {} ao TrustStore: {}", subject, e.getMessage(), e);
            throw new CertificateAdditionException("Falha ao adicionar certificado confiável: " + subject, e);
        }
    }
    
    private SSLContext buildSSLContext(KeyStore trustStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        
        return sslContext;
    }
    
    /**
     * Extrai nome do certificado baseado no CN (Common Name)
     * aplicando sanitização para compatibilidade com sistemas de arquivos
     */
    private String extractCertName(X509Certificate certificate) {
        String subjectCN = CertificateParser.getSubjectCommonName(certificate);

        if (StringUtils.hasText(subjectCN)) {
            return sanitizeCertificateName(subjectCN);
        }

        // Fallback: usar número serial
        return "cert-" + certificate.getSerialNumber();
    }
    
    /**
     * Sanitiza o nome do certificado removendo caracteres problemáticos
     */
    private String sanitizeCertificateName(String name) {
        // Remove caracteres problemáticos e substitui por hífen
        String cleanName = name.replaceAll("[^a-zA-Z0-9.-]", "-")
                .replaceAll("-+", "-")
                .replaceAll("^-|-$", "")
                .toLowerCase();

        // Limita tamanho se muito longo
        if (cleanName.length() > 50) {
            cleanName = cleanName.substring(0, 50);
            // Remove hífen no final se foi cortado
            cleanName = cleanName.replaceAll("-$", "");
        }

        return cleanName;
    }
    
    /**
     * Exceção específica para falhas na criação do Trust Store principal
     */
    public static class TrustStoreCreationException extends RuntimeException {
        public TrustStoreCreationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    /**
     * Exceção específica para falhas na adição de certificados confiáveis
     */
    public static class CertificateAdditionException extends RuntimeException {
        public CertificateAdditionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}