package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.http.tls.TlsTrust;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import java.security.cert.X509Certificate;

/**
 * Gerenciador do SSLContext interno usado exclusivamente para download do bundle ICP-Brasil.
 * <p>
 * Expõe o SSLContext derivado de um {@link TlsTrust}, isolando as conexões de download do
 * truststore padrão da JVM e do contexto SSL do consumidor.
 */
@Slf4j
public class TrustStoreManager {

    private final TlsTrust trust;
    private final SSLContext sslContext;

    public TrustStoreManager(TlsTrust trust) {
        this.trust = trust;
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
}
