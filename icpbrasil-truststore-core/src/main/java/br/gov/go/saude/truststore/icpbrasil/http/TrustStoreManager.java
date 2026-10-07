package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.http.tls.TlsTrust;
import br.gov.go.saude.truststore.icpbrasil.service.provider.CertificateProvider;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Gerenciador do SSLContext interno usado exclusivamente para download do bundle ICP-Brasil.
 * <p>
 * Constrói um SSLContext com as CAs embutidas em {@code registries/certificates/} (ex: Let's Encrypt),
 * isolando as conexões de download do truststore padrão da JVM e do contexto SSL do consumidor.
 * A construção da confiança é delegada a {@link TlsTrust#dedicatedCa}.
 */
@Slf4j
public class TrustStoreManager {

    private final TlsTrust trust;
    private final SSLContext sslContext;

    /**
     * @throws TrustStoreCreationException se o provedor não fornecer nenhum certificado
     */
    public TrustStoreManager(CertificateProvider certificateProvider) {
        List<X509Certificate> anchors = certificateProvider.getCertificates();
        if (anchors.isEmpty()) {
            throw new TrustStoreCreationException("TrustStore não pode ser criado sem certificados confiáveis", null);
        }
        this.trust = TlsTrust.dedicatedCa(anchors);
        this.sslContext = trust.sslContext();
        log.info("Download do acervo ITI confia em {}", trust.describe());
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    /** Âncoras do TrustManager interno; certificados idênticos aparecem uma vez. */
    public X509Certificate[] getAcceptedIssuers() {
        return trust.trustManager().getAcceptedIssuers();
    }

    public static class TrustStoreCreationException extends RuntimeException {
        public TrustStoreCreationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
