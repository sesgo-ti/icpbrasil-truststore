package com.github.nogueiralegacy.truststore.service;

import com.github.nogueiralegacy.truststore.model.CertificateParser;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
@Slf4j
@Service
public class Cache {
    private Map<String, X509Certificate> skiIndex;

    public Cache(List<X509Certificate> certificates) {
        createMapSkiToCertificate(certificates);
    }

    private void createMapSkiToCertificate(List<X509Certificate> certificates) {
        this.skiIndex = new HashMap<>();

        for (X509Certificate certificate : certificates) {
            try {
                String ski = CertificateParser.getSubjectKeyIdentifier(certificate);
                this.skiIndex.put(ski, certificate);
            } catch (RuntimeException e) {
                log.error("Erro ao extrair Subject Key Identifier do certificado: {}", e.getMessage(), e);
            }
        }
    }

    public X509Certificate getCertificateBySki(String ski) {
        return this.skiIndex.get(ski);
    }
}
