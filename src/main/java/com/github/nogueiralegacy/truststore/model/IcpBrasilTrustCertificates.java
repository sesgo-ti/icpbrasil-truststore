package com.github.nogueiralegacy.truststore.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Classe que representa o conjunto de certificados de confiança ICP Brasil.
 * Contém todos os certificados extraídos do arquivo oficial do ITI/ICP-Brasil.
 */
@Getter
@Slf4j
public class IcpBrasilTrustCertificates {
    /** Lista imutável de certificados X509 do ICP Brasil. */
    private List<X509Certificate> certificates;

    
    /**
     * Retorna uma lista imutável dos certificados.
     *
     * @return Lista imutável de certificados X509
     */
    public List<X509Certificate> getCertificates() {
        return Collections.unmodifiableList(certificates);
    }
    
    /**
     * Retorna o número total de certificados.
     *
     * @return Quantidade de certificados
     */
    public int size() {
        return certificates.size();
    }

}
