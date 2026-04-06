package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class Cache {
    private static volatile boolean isCacheValid = false;
    private static volatile Map<String, X509Certificate> skiIndex = new HashMap<>();

    /**
     * Carrega os certificados no cache incondicionalmente, marcando-o como válido.
     * Este é o entry point recomendado para consumidores da lib que desejam
     * popular o cache manualmente.
     *
     * @param certificates Lista de certificados para carregar no cache
     */
    public static void load(List<X509Certificate> certificates) {
        log.info("Carregando cache de certificados...");
        isCacheValid = true;
        createMapSkiToCertificate(certificates);
        log.info("Cache de certificados carregado com {} entradas.", skiIndex.size());
    }

    /**
     * Se a cache estiver válida, atualiza o cache de certificados.
     * Se a cache estiver inválida, não faz nada.
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

    /**
     * Retorna uma cópia do mapa de certificados indexados por SKI.
     *
     * @return Mapa SKI → X509Certificate (cópia defensiva)
     */
    public static Map<String, X509Certificate> getAllCertificates() {
        return new HashMap<>(skiIndex);
    }

    /**
     * Retorna os certificados raiz (auto-assinados) indexados por SKI.
     * Um certificado é considerado raiz quando subject e issuer são iguais
     * e a assinatura é verificável com a própria chave pública.
     *
     * @return Mapa SKI → X509Certificate contendo apenas certificados raiz
     */
    public static Map<String, X509Certificate> getRootCertificates() {
        Map<String, X509Certificate> roots = new HashMap<>();
        for (Map.Entry<String, X509Certificate> entry : skiIndex.entrySet()) {
            X509Certificate cert = entry.getValue();
            if (CertificateParser.isSelfSigned(cert)) {
                roots.put(entry.getKey(), cert);
            }
        }
        return roots;
    }

    public static void setCacheValid(boolean cacheValid) {
        isCacheValid = cacheValid;
        if (!cacheValid) {
            skiIndex = new HashMap<>();
        }
    }

    public static boolean isCacheValid() {
        return isCacheValid;
    }
}
