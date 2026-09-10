package br.gov.go.saude.truststore.icpbrasil.service.provider;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.RecoveryIcpBrasilResourceException;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.util.HashValidator;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.utils.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Acesso ao acervo de ACs publicado pelo ITI: download do ZIP e do hash, verificação de
 * integridade e parsing estrito do bundle.
 *
 * <p>Nenhum método desta classe persiste ou publica o acervo; isso é papel exclusivo do
 * {@code TrustStoreService}, que só o faz após {@link #validateZipIntegrity} e
 * {@link #parseCertificates} terem sucesso.</p>
 */
@Slf4j
public class IcpBrasilCertificateProvider implements CertificateProvider {

    /**
     * Limites do bundle, aplicados durante a descompressão para que um ZIP malicioso ou
     * corrompido falhe antes de consumir memória. O acervo real tem ~160 certificados de
     * poucos KB em ~300 KB compactados; as margens são de várias ordens de grandeza.
     */
    static final int MAX_ZIP_BYTES = 64 * 1024 * 1024;
    static final int MAX_ENTRIES = 10_000;
    static final int MAX_ENTRY_BYTES = 1024 * 1024;
    static final long MAX_TOTAL_BYTES = 64L * 1024 * 1024;

    private static final Pattern SHA512_HEX = Pattern.compile("[0-9a-f]{128}");
    private static final String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";

    private final Downloader downloader;
    private final String icpBrasilZipUrl;
    private final String icpBrasilHashUrl;
    private final TrustStoreRepository trustStoreRepository;

    public IcpBrasilCertificateProvider(TrustStoreConfig trustStoreConfig, Downloader downloader,
            TrustStoreRepository trustStoreRepository) {
        this.downloader = downloader;
        this.icpBrasilZipUrl = trustStoreConfig.getCertificateUrl();
        this.icpBrasilHashUrl = trustStoreConfig.getHashUrl();
        this.trustStoreRepository = trustStoreRepository;
    }

    /**
     * Lê apenas o acervo já persistido no repositório local, valida o hash e parseia o bundle.
     * Não acessa a rede; o download é responsabilidade do pipeline de sincronização.
     *
     * @throws IllegalStateException    se o repositório local não contém ZIP e hash
     * @throws SecurityException        se o ZIP não corresponde ao hash persistido
     * @throws IllegalArgumentException se o bundle viola as regras de {@link #parseCertificates}
     */
    @Override
    public List<X509Certificate> getCertificates() {
        byte[] zipData = trustStoreRepository.recuperarZip()
                .filter(zip -> zip.length > 0)
                .orElseThrow(() -> new IllegalStateException("ZIP ICP-Brasil ausente no repositório local"));
        String expectedHash = trustStoreRepository.recuperarHash()
                .filter(hash -> !hash.isBlank())
                .orElseThrow(() -> new IllegalStateException("Hash ICP-Brasil ausente no repositório local"));

        validateZipIntegrity(zipData, expectedHash);
        return parseCertificates(zipData);
    }

    public byte[] baixarZipIcpBrasil() {
        log.info("Baixando ZIP da URL remota");
        try {
            byte[] zipData = downloader.downloadBytes(icpBrasilZipUrl);
            if (zipData == null || zipData.length == 0) {
                throw new IOException("Dados do ZIP vazios ou inválidos");
            }
            return zipData;
        } catch (Exception e) {
            throw new RecoveryIcpBrasilResourceException("Falha ao baixar ZIP: " + icpBrasilZipUrl, e);
        }
    }

    /**
     * Baixa o arquivo de hash publicado pelo ITI (formato {@code sha512sum}: hash, espaços,
     * nome do arquivo) e devolve o hash em hexadecimal minúsculo.
     *
     * @throws RecoveryIcpBrasilResourceException se o download falhar ou o conteúdo não for
     *                                            um SHA-512 em hexadecimal
     */
    public String baixarHashIcpBrasil() {
        log.info("Baixando hash da URL remota");
        try {
            String hashContent = downloader.downloadText(icpBrasilHashUrl);
            if (hashContent == null || hashContent.isBlank()) {
                throw new IOException("Hash vazio ou inválido");
            }
            String hash = hashContent.trim().split("\\s+")[0].toLowerCase(Locale.ROOT);
            if (!SHA512_HEX.matcher(hash).matches()) {
                throw new IOException("Conteúdo do arquivo de hash não é um SHA-512 em hexadecimal");
            }
            return hash;
        } catch (Exception e) {
            throw new RecoveryIcpBrasilResourceException("Falha ao baixar hash: " + icpBrasilHashUrl, e);
        }
    }

    /**
     * Verifica que {@code zipData} corresponde ao SHA-512 esperado.
     *
     * @param expectedHash SHA-512 em hexadecimal (maiúsculo ou minúsculo)
     * @throws SecurityException se o hash esperado não é um SHA-512 em hexadecimal ou se o
     *                           conteúdo não corresponde a ele
     */
    public void validateZipIntegrity(byte[] zipData, String expectedHash) {
        String normalizado = expectedHash == null ? "" : expectedHash.trim().toLowerCase(Locale.ROOT);
        if (!SHA512_HEX.matcher(normalizado).matches()) {
            throw new SecurityException("Hash esperado não é um SHA-512 em hexadecimal");
        }
        if (!HashValidator.validateSha512(zipData, normalizado)) {
            throw new SecurityException("Hash do arquivo ZIP não confere com o esperado");
        }
        log.info("Integridade do ZIP validada com sucesso");
    }

    /**
     * Extrai os certificados do bundle de forma estrita: o resultado só é devolvido se o ZIP
     * inteiro for aceitável, pois um bundle parcialmente legível substituiria uma geração boa
     * por um acervo incompleto.
     *
     * <p>Regras: todo arquivo com extensão de certificado ({@code .crt}, {@code .cer},
     * {@code .pem}, {@code .der}) deve ser um X.509 parseável, com extensão SKI e
     * {@code basicConstraints} de CA; demais arquivos são ignorados, mas contam nos limites.
     * O bundle deve ter ao menos um certificado e respeitar {@code MAX_ZIP_BYTES},
     * {@code MAX_ENTRIES}, {@code MAX_ENTRY_BYTES} e {@code MAX_TOTAL_BYTES}; os limites por
     * entrada e total são aplicados durante a descompressão.</p>
     *
     * @throws IllegalArgumentException se qualquer regra for violada ou o ZIP for ilegível
     */
    public List<X509Certificate> parseCertificates(byte[] zipData) {
        if (zipData == null || zipData.length == 0) {
            throw new IllegalArgumentException("Bundle ICP-Brasil vazio");
        }
        if (zipData.length > MAX_ZIP_BYTES) {
            throw new IllegalArgumentException("Bundle ICP-Brasil excede " + MAX_ZIP_BYTES
                    + " bytes compactados: " + zipData.length);
        }

        List<X509Certificate> certificates = new ArrayList<>();
        int entries = 0;
        long totalBytes = 0;

        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(zipData))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > MAX_ENTRIES) {
                    throw new IllegalArgumentException("Bundle ICP-Brasil excede " + MAX_ENTRIES + " entradas");
                }
                if (entry.isDirectory()) {
                    continue;
                }
                // Lê um byte além do limite para distinguir "exatamente no limite" de "excedeu"
                // sem confiar no tamanho declarado no cabeçalho, que é controlado pelo emissor.
                byte[] data = IOUtils.readRange(zip, MAX_ENTRY_BYTES + 1);
                if (data.length > MAX_ENTRY_BYTES) {
                    throw new IllegalArgumentException("Entrada " + entry.getName() + " excede "
                            + MAX_ENTRY_BYTES + " bytes");
                }
                totalBytes += data.length;
                if (totalBytes > MAX_TOTAL_BYTES) {
                    throw new IllegalArgumentException("Bundle ICP-Brasil excede " + MAX_TOTAL_BYTES
                            + " bytes descompactados");
                }
                if (isCertificateFile(entry.getName())) {
                    certificates.add(parseCaCertificate(entry.getName(), data));
                }
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Bundle ICP-Brasil ilegível: " + e.getMessage(), e);
        }

        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("Bundle ICP-Brasil sem certificados");
        }
        log.info("Extraídos {} certificados do ZIP", certificates.size());
        return certificates;
    }

    private static X509Certificate parseCaCertificate(String fileName, byte[] data) {
        X509Certificate certificate;
        try {
            certificate = CertificateParser.parse(data);
        } catch (CertificateParsingException | RuntimeException e) {
            throw new IllegalArgumentException("Entrada " + fileName + " não é um certificado X.509 válido", e);
        }
        if (certificate.getBasicConstraints() == -1) {
            throw new IllegalArgumentException("Entrada " + fileName + " não é um certificado de AC");
        }
        if (certificate.getExtensionValue(SUBJECT_KEY_IDENTIFIER_OID) == null) {
            throw new IllegalArgumentException("Entrada " + fileName + " não possui Subject Key Identifier");
        }
        return certificate;
    }

    private static boolean isCertificateFile(String fileName) {
        String lowerFileName = fileName.toLowerCase(Locale.ROOT);
        return lowerFileName.endsWith(".crt") ||
                lowerFileName.endsWith(".cer") ||
                lowerFileName.endsWith(".pem") ||
                lowerFileName.endsWith(".der");
    }
}
