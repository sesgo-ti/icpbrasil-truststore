package br.gov.go.saude.truststore.icpbrasil.service.provider;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.http.Downloader;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.repository.TrustStoreRepository;
import br.gov.go.saude.truststore.icpbrasil.service.RecoveryIcpBrasilResourceException;
import br.gov.go.saude.truststore.icpbrasil.util.HashValidator;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.CRC32;

/** Valida integralmente o bundle antes de fornecer certificados ou uma geracao ao pipeline. */
public class IcpBrasilCertificateProvider implements CertificateProvider {
    private final Downloader downloader;
    private final String zipUrl;
    private final String hashUrl;
    private final TrustStoreRepository repository;
    private final int maxCompressedBytes;
    private final int maxEntryBytes;
    private final long maxExpandedBytes;
    private final int maxEntries;

    /** Os limites sao validados tambem no core, sem depender do ciclo de vida Spring. */
    public IcpBrasilCertificateProvider(TrustStoreConfig config, Downloader downloader,
                                       TrustStoreRepository repository) {
        config.getBundle().validate();
        this.downloader = downloader;
        this.zipUrl = config.getCertificateUrl();
        this.hashUrl = config.getHashUrl();
        this.repository = repository;
        this.maxCompressedBytes = config.getBundle().getMaxCompressedBytes();
        this.maxEntryBytes = config.getBundle().getMaxEntryBytes();
        this.maxExpandedBytes = config.getBundle().getMaxExpandedBytes();
        this.maxEntries = config.getBundle().getMaxEntries();
    }

    /** Valida hash, ZIP e todas as entradas de certificado; nao confirma nem persiste o acervo. */
    @Override
    public List<X509Certificate> getCertificates() {
        var zip = repository.recuperarZip();
        var hash = repository.recuperarHash();
        ParsedSnapshot parsed = zip.isPresent() && hash.isPresent()
                ? parseSnapshot(zip.get(), hash.get())
                : parseSnapshot(baixarZipIcpBrasil(), baixarHashIcpBrasil());
        return parsed.certificates();
    }

    /** Baixa apenas os bytes; a geracao ainda precisa passar por {@link #parseSnapshot}. */
    public byte[] baixarZipIcpBrasil() {
        try {
            return downloader.downloadBytes(zipUrl);
        } catch (Exception e) {
            throw new RecoveryIcpBrasilResourceException("Falha ao baixar ZIP: " + zipUrl, e);
        }
    }

    /** Retorna a identidade SHA-512 normalizada, sem renovar qualquer confirmacao. */
    public String baixarHashIcpBrasil() {
        try {
            String content = downloader.downloadText(hashUrl);
            return normalizeHash(content.strip().split("\\s+")[0]);
        } catch (Exception e) {
            throw new RecoveryIcpBrasilResourceException("Falha ao baixar hash: " + hashUrl, e);
        }
    }

    /**
     * Valida uma geracao sem I/O de storage ou rede. Nenhuma entrada de certificado invalida
     * e ignorada. Exige CA e SKI, mas nao raiz minima nem validade X.509 atual (acervo historico).
     * Arquivos auxiliares sao ignorados semanticamente, mas consomem todos os orcamentos ZIP.
     *
     * @throws SecurityException se hash, estrutura, limites ou certificados forem invalidos
     */
    public ParsedSnapshot parseSnapshot(byte[] data, String expectedHash) {
        if (data == null || data.length == 0 || data.length > maxCompressedBytes) {
            throw new SecurityException("Tamanho do ZIP invalido");
        }
        byte[] zip = data.clone();
        String hash = normalizeHash(expectedHash);
        if (!HashValidator.validateSha512(zip, hash)) {
            throw new SecurityException("Hash do ZIP nao confere");
        }
        validateDirectory(zip);
        List<X509Certificate> certificates = new ArrayList<>();
        Map<String, X509Certificate> index = new HashMap<>();
        try (var channel = new SeekableInMemoryByteChannel(zip);
             var archive = ZipFile.builder().setSeekableByteChannel(channel).get()) {
            long total = 0;
            int count = 0;
            var entries = archive.getEntriesInPhysicalOrder();
            byte[] buffer = new byte[8192];
            while (entries.hasMoreElements()) {
                ZipArchiveEntry entry = entries.nextElement();
                if (++count > maxEntries || entry.getSize() > maxEntryBytes
                        || entry.getSize() > maxExpandedBytes - total || !archive.canReadEntryData(entry)) {
                    throw new SecurityException("Entrada ZIP excede limites ou usa formato nao suportado");
                }
                String name = entry.getName().toLowerCase(Locale.ROOT);
                boolean certificateFile = !entry.isDirectory() && (name.endsWith(".crt")
                        || name.endsWith(".cer") || name.endsWith(".pem") || name.endsWith(".der"));
                try (InputStream in = archive.getInputStream(entry);
                     var out = new ByteArrayOutputStream()) {
                    CRC32 crc = new CRC32();
                    int size = 0;
                    int read;
                    while ((read = in.read(buffer)) != -1) {
                        if (read > maxEntryBytes - size || read > maxExpandedBytes - total) {
                            throw new SecurityException("Expansao ZIP excede limites");
                        }
                        size += read;
                        total += read;
                        crc.update(buffer, 0, read);
                        if (certificateFile) {
                            out.write(buffer, 0, read);
                        }
                    }
                    if (size != entry.getSize() || crc.getValue() != entry.getCrc()) {
                        throw new SecurityException("Entrada ZIP truncada ou corrompida");
                    }
                    if (certificateFile) {
                        List<X509Certificate> parsed = parseEntry(out.toByteArray());
                        if (parsed.isEmpty()) {
                            throw new SecurityException("Entrada de certificado vazia");
                        }
                        for (X509Certificate certificate : parsed) {
                            String ski = CertificateParser.getSubjectKeyIdentifier(certificate);
                            if (ski.isBlank() || certificate.getBasicConstraints() < 0) {
                                throw new SecurityException("Certificado do acervo deve ser CA com SKI");
                            }
                            certificates.add(certificate);
                            // Preserva a selecao da ultima ocorrencia para CAs com mesmo SKI (cross-signing).
                            index.put(ski, certificate);
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new SecurityException("Bundle ICP-Brasil invalido", e);
        }
        if (index.isEmpty()) {
            throw new SecurityException("Bundle ICP-Brasil sem certificados utilizaveis");
        }
        return new ParsedSnapshot(zip, hash, certificates, index);
    }

    private static String normalizeHash(String hash) {
        if (hash == null || !hash.strip().matches("[0-9a-fA-F]{128}")) {
            throw new SecurityException("Hash SHA-512 invalido");
        }
        return hash.strip().toLowerCase(Locale.ROOT);
    }

    private void validateDirectory(byte[] zip) {
        // ZipFile materializa o diretorio inteiro no construtor; limitar antes evita amplificacao por entradas.
        ByteBuffer buffer = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
        for (int end = zip.length - 22; end >= Math.max(0, zip.length - 22 - 65535); end--) {
            if (buffer.getInt(end) != 0x06054b50
                    || end + 22 + Short.toUnsignedInt(buffer.getShort(end + 20)) != zip.length) {
                continue;
            }
            int count = Short.toUnsignedInt(buffer.getShort(end + 10));
            long size = Integer.toUnsignedLong(buffer.getInt(end + 12));
            long offset = Integer.toUnsignedLong(buffer.getInt(end + 16));
            if (buffer.getInt(end + 4) != 0 || count == 65535 || count > maxEntries
                    || Short.toUnsignedInt(buffer.getShort(end + 8)) != count || offset + size != end) {
                throw new SecurityException("Diretorio ZIP invalido, excedente, multipart ou ZIP64");
            }
            int position = (int) offset;
            int actualCount = 0;
            while (position < end) {
                if (++actualCount > maxEntries || end - position < 46 || buffer.getInt(position) != 0x02014b50) {
                    throw new SecurityException("Diretorio ZIP invalido ou excedente");
                }
                position += 46 + Short.toUnsignedInt(buffer.getShort(position + 28))
                        + Short.toUnsignedInt(buffer.getShort(position + 30))
                        + Short.toUnsignedInt(buffer.getShort(position + 32));
            }
            if (position != end || actualCount != count) {
                throw new SecurityException("Contagem ou tamanho do diretorio ZIP invalido");
            }
            return;
        }
        throw new SecurityException("ZIP sem diretorio final completo");
    }

    private static List<X509Certificate> parseEntry(byte[] bytes) throws CertificateParsingException {
        List<byte[]> encoded = new ArrayList<>();
        if (bytes.length > 0 && bytes[0] == 0x30) {
            encoded.add(bytes);
        } else {
            // CertificateFactory tolera lixo apos PEM; cada entrada deve ser consumida integralmente.
            String text = new String(bytes, StandardCharsets.US_ASCII).strip();
            String begin = "-----BEGIN CERTIFICATE-----";
            String end = "-----END CERTIFICATE-----";
            while (!text.isEmpty()) {
                int endIndex = text.indexOf(end);
                if (!text.startsWith(begin) || endIndex < begin.length()) {
                    throw new SecurityException("Entrada PEM invalida ou com conteudo residual");
                }
                String base64 = text.substring(begin.length(), endIndex).replaceAll("[\\r\\n\\t ]", "");
                encoded.add(Base64.getDecoder().decode(base64));
                text = text.substring(endIndex + end.length()).strip();
            }
        }
        List<X509Certificate> certificates = new ArrayList<>();
        for (byte[] der : encoded) {
            X509Certificate certificate = CertificateParser.parse(der);
            try {
                if (!Arrays.equals(der, certificate.getEncoded())) {
                    throw new SecurityException("Entrada deve conter certificado DER completo sem residuos");
                }
            } catch (CertificateEncodingException e) {
                throw new SecurityException("Codificacao DER invalida", e);
            }
            certificates.add(certificate);
        }
        return certificates;
    }

    /** Geracao imutavel cuja construcao e restrita ao parsing integral do provider. */
    public static final class ParsedSnapshot {
        private final byte[] zip;
        private final String hash;
        private final List<X509Certificate> certificates;
        private final Map<String, X509Certificate> index;

        private ParsedSnapshot(byte[] zip, String hash, List<X509Certificate> certificates,
                               Map<String, X509Certificate> index) {
            this.zip = zip;
            this.hash = hash;
            this.certificates = List.copyOf(certificates);
            this.index = Map.copyOf(index);
        }

        /** Copia defensiva dos bytes cuja identidade foi validada. */
        public byte[] zip() { return zip.clone(); }

        /** Identidade SHA-512 dos bytes do ZIP. */
        public String hash() { return hash; }

        /** Todos os certificados validados, inclusive ocorrencias com mesmo SKI. */
        public List<X509Certificate> certificates() { return certificates; }

        /** Indice imutavel pronto para publicacao, sem novo parsing. */
        public Map<String, X509Certificate> index() { return index; }
    }
}
