package com.github.nogueiralegacy.truststore.http;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import org.springframework.core.annotation.Order;
import org.springframework.core.Ordered;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Gerenciador do certificado SSL do Vault para estabelecer conexão segura.
 * Este certificado é usado APENAS para conectar com o Vault, não para validar outros serviços.
 * 
 * IMPORTANTE: Este componente tem prioridade MÁXIMA de inicialização pois o SSLContext
 * que ele cria é necessário ANTES da criação do VaultTemplate.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class VaultCertificateManager {
    
    private final ResourceLoader resourceLoader;
    
    @Value("${truststore.vault.ssl-certificate-path:classpath:vault-ssl-cert.pem}")
    private String vaultSSLCertificatePath;
    
    private SSLContext vaultSSLContext;
    
    public VaultCertificateManager(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }
    
    @PostConstruct
    public void initializeVaultSSLCertificate() {
        try {
            loadVaultSSLCertificate();
        } catch (Exception e) {
            log.error("Erro ao carregar certificado SSL do Vault: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao carregar certificado SSL do Vault", e);
        }
    }
    
    /**
     * Retorna o SSL Context configurado com o certificado SSL do Vault
     * Este SSL Context é usado APENAS para conectar com o Vault
     */
    public SSLContext getVaultSSLContext() {
        if (vaultSSLContext == null) {
            throw new IllegalStateException("Certificado SSL do Vault não foi inicializado");
        }
        return vaultSSLContext;
    }
    
    private void loadVaultSSLCertificate() throws Exception {
        log.info("Carregando certificado SSL do Vault de: {}", vaultSSLCertificatePath);

        Resource resource = resourceLoader.getResource(vaultSSLCertificatePath);
        
        if (!resource.exists()) {
            String errorMsg = String.format("Certificado SSL do Vault não encontrado em: %s. " +
                    "Verifique se o arquivo existe em src/main/resources/", vaultSSLCertificatePath);
            log.error(errorMsg);
            throw new RuntimeException(errorMsg);
        }
        
        try (InputStream certStream = resource.getInputStream()) {
            // Parse do certificado PEM
            X509Certificate vaultSSLCert = parsePEMCertificate(certStream);
            
            // Validar certificado
            validateVaultSSLCertificate(vaultSSLCert);
            
            // Criar trust store com o certificado SSL do Vault
            KeyStore trustStore = createTrustStoreWithVaultSSLCert(vaultSSLCert);
            
            // Criar SSL context
            vaultSSLContext = createSSLContext(trustStore);
            
            log.info("Certificado SSL do Vault carregado com sucesso");
        } catch (Exception e) {
            log.error("Erro ao carregar certificado SSL do Vault: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao carregar certificado SSL do Vault", e);
        }
    }
    
    /**
     * Valida o certificado SSL do Vault
     */
    private void validateVaultSSLCertificate(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificado SSL do Vault é null");
        }
        
        try {
            certificate.checkValidity();
            log.debug("Certificado SSL do Vault é válido");
        } catch (Exception e) {
            log.error("Certificado SSL do Vault é inválido: {}", e.getMessage());
            throw new RuntimeException("Certificado SSL do Vault é inválido", e);
        }
    }
    
    private X509Certificate parsePEMCertificate(InputStream certStream) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(certStream);
    }
    
    private KeyStore createTrustStoreWithVaultSSLCert(X509Certificate vaultSSLCert) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        
        // Adicionar APENAS o certificado SSL específico do Vault (certificate pinning)
        // NÃO adiciona certificados do sistema por questões de segurança
        trustStore.setCertificateEntry("vault-ssl-cert", vaultSSLCert);
        
        log.debug("Certificado SSL do Vault adicionado ao trust store (certificate pinning)");
        log.debug("Truststore contém APENAS o certificado do Vault (não inclui CAs do sistema)");
        return trustStore;
    }
    
    private SSLContext createSSLContext(KeyStore trustStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        
        return sslContext;
    }
}