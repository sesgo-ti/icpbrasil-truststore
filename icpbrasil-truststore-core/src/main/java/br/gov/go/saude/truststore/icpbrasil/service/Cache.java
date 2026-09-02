package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Índice em memória do acervo ICP-Brasil (SKI → certificado), servido aos consumidores.
 *
 * <p><strong>Modelo de segurança:</strong> a leitura é pública; a <em>escrita</em> é
 * restrita ao pipeline legítimo de carga ({@link TrustStoreService}, mesmo pacote),
 * preservando a cadeia de custódia: download com TLS dedicado → validação SHA-512 →
 * armazenamento → indexação. Código fora do pipeline não consegue substituir nem
 * revalidar o acervo.</p>
 *
 * <p><strong>Concorrência:</strong> o índice é reconstruído em um mapa local e publicado
 * por troca atômica de referência {@code volatile} — leitores nunca observam estado
 * parcial durante uma atualização.</p>
 *
 * <p>Uma instância por aplicação: a auto-configuração expõe o bean compartilhado.</p>
 */
@Slf4j
public class Cache {

    private volatile boolean cacheValid = false;
    private volatile Map<String, X509Certificate> skiIndex = Map.of();

    /**
     * Carrega os certificados no cache e o marca como válido.
     * A validade só é sinalizada após o índice estar completamente populado.
     */
    void load(List<X509Certificate> certificates) {
        log.info("Carregando cache de certificados...");
        skiIndex = indexarPorSki(certificates);
        cacheValid = true;
        log.info("Cache de certificados carregado com {} entradas.", skiIndex.size());
    }

    /**
     * Atualiza o índice se o cache estiver válido; caso contrário, não faz nada.
     */
    void refreshCache(List<X509Certificate> certificates) {
        if (cacheValid) {
            log.info("Atualizando cache de certificados...");
            skiIndex = indexarPorSki(certificates);
            log.info("Cache de certificados atualizado com {} entradas.", skiIndex.size());
            return;
        }

        log.warn("Cache inválido, não foi possível atualizar.");
    }

    /**
     * Constrói o índice em um mapa local — a publicação acontece por atribuição
     * atômica da referência, nunca por mutação do mapa visível aos leitores.
     */
    private static Map<String, X509Certificate> indexarPorSki(List<X509Certificate> certificates) {
        Map<String, X509Certificate> novoIndice = new HashMap<>();

        for (X509Certificate certificate : certificates) {
            try {
                String ski = CertificateParser.getSubjectKeyIdentifier(certificate);
                novoIndice.put(ski, certificate);
            } catch (RuntimeException e) {
                log.error("Erro ao extrair Subject Key Identifier do certificado: {}", e.getMessage(), e);
            }
        }

        return novoIndice;
    }

    public X509Certificate getCertificateBySki(String ski) {
        return skiIndex.get(ski);
    }

    /**
     * Retorna uma cópia do mapa de certificados indexados por SKI.
     *
     * @return Mapa SKI → X509Certificate (cópia defensiva)
     */
    public Map<String, X509Certificate> getAllCertificates() {
        return new HashMap<>(skiIndex);
    }

    /**
     * Retorna os certificados raiz (auto-assinados) indexados por SKI.
     * Um certificado é considerado raiz quando subject e issuer são iguais
     * e a assinatura é verificável com a própria chave pública.
     *
     * @return Mapa SKI → X509Certificate contendo apenas certificados raiz
     */
    public Map<String, X509Certificate> getRootCertificates() {
        Map<String, X509Certificate> roots = new HashMap<>();
        for (Map.Entry<String, X509Certificate> entry : skiIndex.entrySet()) {
            X509Certificate cert = entry.getValue();
            if (CertificateParser.isSelfSigned(cert)) {
                roots.put(entry.getKey(), cert);
            }
        }
        return roots;
    }

    /**
     * Marca a validade do cache; ao invalidar, o índice é descartado (fail-closed).
     */
    void setCacheValid(boolean cacheValid) {
        this.cacheValid = cacheValid;
        if (!cacheValid) {
            skiIndex = Map.of();
        }
    }

    public boolean isCacheValid() {
        return cacheValid;
    }
}
