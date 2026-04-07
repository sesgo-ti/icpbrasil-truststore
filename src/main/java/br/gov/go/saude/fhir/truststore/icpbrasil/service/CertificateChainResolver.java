package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Slf4j
@Service
public class CertificateChainResolver {
    private static final int MAX_CHAIN_DEPTH = 10;

    /**
     * Constrói a cadeia de certificados a partir de um certificado folha (leaf),
     * caminhando pela relação AKI→SKI até encontrar um certificado raiz
     * (auto-assinado) ou um emissor não presente no cache.
     *
     * @param leaf certificado folha (end-entity) a partir do qual a cadeia será montada
     * @return Lista ordenada [leaf, intermediário1, ..., raiz]
     */
    public static List<X509Certificate> mountChain(X509Certificate leaf) {
        List<X509Certificate> chain = new ArrayList<>();
        Set<String> visited = new HashSet<>();

        X509Certificate current = leaf;
        chain.add(current);

        for (int i = 0; i < MAX_CHAIN_DEPTH; i++) {
            if (CertificateParser.isSelfSigned(current)) {
                break;
            }

            String aki;
            try {
                aki = CertificateParser.getAuthorityKeyIdentifier(current);
            } catch (RuntimeException e) {
                log.warn("Não foi possível extrair AKI do certificado: {}", e.getMessage());
                break;
            }

            if (visited.contains(aki)) {
                log.warn("Referência circular detectada na cadeia de certificados (AKI: {})", aki);
                break;
            }

            X509Certificate issuer = Cache.getCertificateBySki(aki);
            if (issuer == null) {
                log.info("Emissor com SKI {} não encontrado no cache. Cadeia parcial retornada.", aki);
                break;
            }

            chain.add(issuer);
            visited.add(aki);
            current = issuer;
        }

        return chain;
    }
}
