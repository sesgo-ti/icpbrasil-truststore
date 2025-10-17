package com.github.nogueiralegacy.truststore.http;

import com.github.nogueiralegacy.truststore.model.CertificateParser;
import com.github.nogueiralegacy.truststore.service.VaultCertificateProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Provider responsável pela criação e configuração do SSL Context
 * com certificados confiáveis do Vault
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SSLContextProvider {

    private final VaultCertificateProvider vaultCertificateProvider;

    /**
     * Cria e configura o SSL Context com certificados confiáveis
     */
    @Bean
    public SSLContext sslContext() {
        try {
            log.info("Criando SSL context com certificados confiáveis");
            
            KeyStore trustStore = createTrustStore();
            addTrustedCertificates(trustStore);
            
            return buildSSLContext(trustStore);
            
        } catch (Exception e) {
            log.error("Erro crítico ao criar SSL context: {}", e.getMessage(), e);
            throw new SSLContextCreationException("Falha na criação do SSL Context", e);
        }
    }

    private KeyStore createTrustStore() throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        return trustStore;
    }

    private void addTrustedCertificates(KeyStore trustStore) {
        List<X509Certificate> certificates = vaultCertificateProvider.getCertificates();
        
        if (certificates.isEmpty()) {
            log.warn("Nenhum certificado confiável encontrado no Vault");
            return;
        }

        for (X509Certificate certificate : certificates) {
            addCertificateToTrustStore(trustStore, certificate);
        }
        
        log.info("Adicionados {} certificados confiáveis ao TrustStore", certificates.size());
    }

    private void addCertificateToTrustStore(KeyStore trustStore, X509Certificate certificate) {
        try {
            String certName = extractCertName(certificate);
            trustStore.setCertificateEntry(certName, certificate);
            log.debug("Certificado adicionado: {}", certName);
            
        } catch (Exception e) {
            String subject = certificate.getSubjectX500Principal().getName();
            log.error("Erro ao adicionar certificado {} ao TrustStore: {}", subject, e.getMessage(), e);
            throw new CertificateAdditionException("Falha ao adicionar certificado: " + subject, e);
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
     * Exceção específica para falhas na criação do SSL Context
     */
    public static class SSLContextCreationException extends RuntimeException {
        public SSLContextCreationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Exceção específica para falhas na adição de certificados
     */
    public static class CertificateAdditionException extends RuntimeException {
        public CertificateAdditionException(String message, Throwable cause) {
            super(message, cause);
        }
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
}