package br.gov.go.saude.fhir.truststore.icpbrasil.http;

import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.CertificateProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Gerenciador do Trust Store principal da aplicação para validar conexões
 * a outros serviços.
 * <p>
 * Usa o {@link CertificateProvider} do filesystem para obter certificados confiáveis
 * de terceiros (ex: Let's Encrypt) e monta o SSLContext para conexões HTTPS.
 */
@Slf4j
@Component
public class TrustStoreManager {
    
    private final CertificateProvider certificateProvider;

    public TrustStoreManager(@Qualifier("filesystemCertificateProvider") CertificateProvider certificateProvider) {
        this.certificateProvider = certificateProvider;
    }
    
    /**
     * Cria o X509TrustManager com os certificados confiáveis do provider.
     * Exposto como bean para ser reutilizado por outros clientes HTTP (ex: S3/MinIO).
     */
    @Bean
    public X509TrustManager trustManager() {
        try {
            log.info("Criando TrustManager com certificados confiáveis");

            KeyStore trustStore = createTrustStore();
            addTrustedCertificates(trustStore);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            return Arrays.stream(tmf.getTrustManagers())
                    .filter(tm -> tm instanceof X509TrustManager)
                    .map(tm -> (X509TrustManager) tm)
                    .findFirst()
                    .orElseThrow(() -> new TrustStoreCreationException("Nenhum X509TrustManager encontrado", null));

        } catch (TrustStoreCreationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Erro crítico ao criar TrustManager: {}", e.getMessage(), e);
            throw new TrustStoreCreationException("Falha na criação do TrustManager", e);
        }
    }

    /**
     * Cria o SSL Context principal usando o TrustManager já construído.
     * IMPORTANTE: Não inclui certificados do sistema Java padrão por questões de segurança.
     */
    @Bean
    public SSLContext sslContext(X509TrustManager trustManager) {
        try {
            log.info("Criando SSL context principal com certificados confiáveis");
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, null);
            return sslContext;
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
    
    private void addTrustedCertificates(KeyStore trustStore) {
        try {
            List<X509Certificate> certificates = certificateProvider.getCertificates();
            
            if (certificates.isEmpty()) {
                log.error("Nenhum certificado confiável encontrado - TrustStore ficará vazio!");
                throw new TrustStoreCreationException("TrustStore não pode ser criado sem certificados confiáveis", null);
            }

            for (X509Certificate certificate : certificates) {
                addCertificateToTrustStore(trustStore, certificate);
            }
            
            log.info("Adicionados {} certificados confiáveis ao TrustStore principal", certificates.size());
            
        } catch (TrustStoreCreationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Erro crítico ao carregar certificados confiáveis: {}", e.getMessage(), e);
            throw new TrustStoreCreationException("Falha ao carregar certificados confiáveis", e);
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