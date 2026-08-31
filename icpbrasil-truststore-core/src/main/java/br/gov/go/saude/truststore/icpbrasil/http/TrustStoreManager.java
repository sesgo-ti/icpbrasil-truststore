package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.service.provider.CertificateProvider;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Gerenciador do SSLContext interno usado exclusivamente para download do bundle ICP-Brasil.
 * <p>
 * Constrói um SSLContext com as CAs embutidas em {@code registries/certificates/} (ex: Let's Encrypt),
 * isolando as conexões de download do truststore padrão da JVM e do contexto SSL do consumidor.
 */
@Slf4j
public class TrustStoreManager {

    private final CertificateProvider certificateProvider;

    private SSLContext sslContext;

    public TrustStoreManager(CertificateProvider certificateProvider) {
        this.certificateProvider = certificateProvider;
    }

    @PostConstruct
    void init() {
        X509TrustManager trustManager = buildTrustManager();
        sslContext = buildSslContext(trustManager);
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    private X509TrustManager buildTrustManager() {
        try {
            log.info("Criando TrustManager interno com certificados embutidos");

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

    private SSLContext buildSslContext(X509TrustManager trustManager) {
        try {
            log.info("Criando SSLContext interno com certificados embutidos");
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{trustManager}, null);
            return ctx;
        } catch (Exception e) {
            log.error("Erro crítico ao criar SSLContext interno: {}", e.getMessage(), e);
            throw new TrustStoreCreationException("Falha na criação do SSLContext interno", e);
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

            log.info("Adicionados {} certificados confiáveis ao TrustStore interno", certificates.size());

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

    private String extractCertName(X509Certificate certificate) {
        String subjectCN = CertificateParser.getSubjectCommonName(certificate);

        if (subjectCN != null && !subjectCN.isBlank()) {
            return sanitizeCertificateName(subjectCN);
        }

        return "cert-" + certificate.getSerialNumber();
    }

    private String sanitizeCertificateName(String name) {
        String cleanName = name.replaceAll("[^a-zA-Z0-9.-]", "-")
                .replaceAll("-+", "-")
                .replaceAll("^-|-$", "")
                .toLowerCase();

        if (cleanName.length() > 50) {
            cleanName = cleanName.substring(0, 50);
            cleanName = cleanName.replaceAll("-$", "");
        }

        return cleanName;
    }

    public static class TrustStoreCreationException extends RuntimeException {
        public TrustStoreCreationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class CertificateAdditionException extends RuntimeException {
        public CertificateAdditionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
