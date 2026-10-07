package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RaizDescartada;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Raízes ICP-Brasil aceitas como âncora, fixadas por fingerprint SHA-256.
 *
 * <p>Um acervo pode trazer raiz fora da lista (raiz nova legítima ou injetada); ela e tudo que
 * só encadeia até ela são descartados, e o restante segue publicado. Trocar a lista exige
 * release. Certificado cuja assinatura não pode ser verificada não encadeia e também sai.</p>
 */
public final class RaizesFixadas {

    private static final Set<String> PRODUCAO = Set.of(
            "caa53fc6091c6951887c976e378f6ef89aa6377c55d97b6475422b71ed7e9b17", // v5
            "3bdb9b509352f1d3d71c2bf64d9a38a4e6cebda27809d77f7ac476cbde6e314a", // v6
            "5657e70580eb678983f3ed7dfce091d84cae6549389a47fccda8d0e4dc2cf576", // v7
            "6e0bff069a26994c15de2c4888cc54af84882e5495b7fbf66be9ccffec7489f6", // v10
            "1406710058180fa4081aab3f246f1702429c552a11fa3143b84c88cb3ab8e5e7", // v11
            "d8478e37ce19c690cf657381e68fe600e4e1a042536830f06847e03e554c4b01"); // v12

    private final Set<String> fingerprints;

    private RaizesFixadas(Set<String> fingerprints) {
        this.fingerprints = Set.copyOf(fingerprints);
    }

    /** Raízes ICP-Brasil vigentes: v5, v6, v7, v10, v11 e v12. */
    public static RaizesFixadas producao() {
        return new RaizesFixadas(PRODUCAO);
    }

    /**
     * Lista própria de raízes, para testes e código do consumidor.
     *
     * @param fingerprintsSha256 SHA-256 do DER em hexadecimal minúsculo sem separadores
     */
    public static RaizesFixadas de(Set<String> fingerprintsSha256) {
        return new RaizesFixadas(fingerprintsSha256);
    }

    /** Fingerprints SHA-256 fixados, em hexadecimal minúsculo sem separadores. */
    public Set<String> fingerprints() {
        return fingerprints;
    }

    /**
     * Mantém as raízes fixadas e todo certificado que encadeia até elas, descartando as demais
     * raízes autoassinadas e seus descendentes. Raiz fixada ausente do acervo é aceita.
     * Ambas as listas do resultado seguem a ordem do acervo.
     */
    public Resultado filtrar(List<X509Certificate> acervo) {
        Set<X509Certificate> aceitos = new HashSet<>();
        List<RaizDescartada> descartadas = new ArrayList<>();
        List<X509Certificate> pendentes = new ArrayList<>();
        for (X509Certificate certificate : acervo) {
            if (!CertificateParser.isSelfSignedRoot(certificate)) {
                pendentes.add(certificate);
            } else if (fingerprints.contains(CertificateParser.getFingerprintSha256(certificate))) {
                aceitos.add(certificate);
            } else {
                descartadas.add(new RaizDescartada(certificate.getSubjectX500Principal().getName(),
                        CertificateParser.getFingerprintSha256(certificate)));
            }
        }
        // Fecho transitivo: entra quem é assinado por alguém já aceito, até não mudar mais.
        boolean mudou = true;
        while (mudou) {
            mudou = false;
            for (Iterator<X509Certificate> it = pendentes.iterator(); it.hasNext(); ) {
                X509Certificate candidato = it.next();
                if (aceitos.stream().anyMatch(emissor -> emitiu(emissor, candidato))) {
                    aceitos.add(candidato);
                    it.remove();
                    mudou = true;
                }
            }
        }
        return new Resultado(acervo.stream().filter(aceitos::contains).toList(), List.copyOf(descartadas));
    }

    private static boolean emitiu(X509Certificate emissor, X509Certificate certificate) {
        if (!emissor.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(emissor.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Resultado do filtro.
     *
     * @param certificados      certificados mantidos, na ordem do acervo
     * @param raizesDescartadas raízes fora da lista, na ordem do acervo
     */
    public record Resultado(List<X509Certificate> certificados, List<RaizDescartada> raizesDescartadas) {}
}
