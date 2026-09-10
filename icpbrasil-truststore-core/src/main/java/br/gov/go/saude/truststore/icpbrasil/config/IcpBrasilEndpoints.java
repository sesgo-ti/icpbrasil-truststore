package br.gov.go.saude.truststore.icpbrasil.config;

/**
 * Endereços oficiais do ITI para o acervo de Autoridades Certificadoras da ICP-Brasil.
 *
 * <p>São os defaults de {@code icpbrasil-truststore.certificate-url} e {@code hash-url}; uma
 * aplicação pode sobrescrevê-los (espelho interno, homologação) e o valor final passa pela mesma
 * validação em {@link TrustStoreConfig#validateProperties()}.</p>
 */
public final class IcpBrasilEndpoints {

    private static final String BASE_URL = "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/";

    /** ZIP com os certificados das ACs vigentes. */
    public static final String BUNDLE_ZIP_URL = BASE_URL + "ACcompactado.zip";

    /** Hash SHA-512 do ZIP, no formato {@code sha512sum}. */
    public static final String BUNDLE_HASH_URL = BASE_URL + "hashsha512.txt";

    private IcpBrasilEndpoints() {}
}
