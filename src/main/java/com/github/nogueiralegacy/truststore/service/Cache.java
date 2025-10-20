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
    private static Map<String, X509Certificate> skiIndex;

    public static void refreshCache(List<X509Certificate> certificates) {
        log.info("Atualizando cache de certificados...");
        createMapSkiToCertificate(certificates);
        log.info("Cache de certificados atualizado com {} entradas.", skiIndex.size());
    }

    private static void createMapSkiToCertificate(List<X509Certificate> certificates) {
        skiIndex = new HashMap<>();

        for (X509Certificate certificate : certificates) {
            try {
                String ski = CertificateParser.getSubjectKeyIdentifier(certificate);
                skiIndex.put(ski, certificate);
            } catch (RuntimeException e) {
                log.error("Erro ao extrair Subject Key Identifier do certificado: {}", e.getMessage(), e);
            }
        }

        log.info("Cache ski criado com sucesso");
    }

    public static X509Certificate getCertificateBySki(String ski) {
        return skiIndex.get(ski);
    }
}
