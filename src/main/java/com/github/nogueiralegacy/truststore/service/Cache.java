package com.github.nogueiralegacy.truststore.service;

import com.github.nogueiralegacy.truststore.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class Cache {
    private static boolean isCacheValid = false;
    private static Map<String, X509Certificate> skiIndex = new HashMap<>();

    /**\
     * Se a cache estiver válida, atualiza o cache de certificados
     * Se a cache estiver inválida, não faz nada
     *
     * @param certificates Lista de certificados para atualizar o cache
     */
    public static void refreshCache(List<X509Certificate> certificates) {
        if (isCacheValid) {
            log.info("Atualizando cache de certificados...");
            createMapSkiToCertificate(certificates);
            log.info("Cache de certificados atualizado com {} entradas.", skiIndex.size());
            return;
        }

        log.warn("Cache inválido, não foi possível atualizar.");
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

    public static void setCacheValid(boolean cacheValid) {
        isCacheValid = cacheValid;
        if (!cacheValid) {
            skiIndex.clear();
        }
    }

    public static boolean isCacheValid() {
        return isCacheValid;
    }
}
