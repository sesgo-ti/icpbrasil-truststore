package br.gov.go.saude.truststore.icpbrasil.service.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateDTO;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;

/**
 * Provedor de certificados confiáveis armazenados no classpath ou no sistema de arquivos.
 *
 * <p>Suporta dois modos de operação via a propriedade {@code truststore.trusted-certs.dir}:</p>
 * <ul>
 *   <li>{@code classpath:registries/certificates} — lê do classpath (embutido no JAR)</li>
 *   <li>{@code ./registries/certificates} — lê do sistema de arquivos externo</li>
 * </ul>
 *
 * <p>Cada arquivo JSON deve seguir o formato {@link CertificateDTO}, conforme
 * definido no manual de gestão de certificados confiáveis.</p>
 */
@Slf4j
public class FilesystemCertificateProvider implements CertificateProvider {

    private static final String CLASSPATH_PREFIX = "classpath:";

    private final ObjectMapper objectMapper;
    private final String configuredDir;

    public FilesystemCertificateProvider(TrustStoreConfig trustStoreConfig) {
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        this.configuredDir = trustStoreConfig.getTrustedCerts().getDir();
    }

    @PostConstruct
    public void validate() {
        if (configuredDir == null || configuredDir.isBlank()) {
            throw new IllegalStateException(
                    "Diretório de certificados confiáveis não configurado. " +
                    "Configure a propriedade 'truststore.trusted-certs.dir'");
        }

        if (isClasspath()) {
            validateClasspath();
        } else {
            validateFilesystem();
        }
    }

    private boolean isClasspath() {
        return configuredDir.startsWith(CLASSPATH_PREFIX);
    }

    private String classpathDir() {
        return configuredDir.substring(CLASSPATH_PREFIX.length());
    }

    private void validateClasspath() {
        try {
            List<URL> urls = listClasspathJsonUrls();
            log.info("Certificados confiáveis configurados via classpath: {} ({} arquivo(s) JSON encontrado(s))",
                    configuredDir, urls.size());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Erro ao acessar diretório de certificados no classpath: " + configuredDir, e);
        }
    }

    private void validateFilesystem() {
        Path dir = Path.of(configuredDir);
        if (!Files.exists(dir)) {
            throw new IllegalStateException(
                    "Diretório de certificados confiáveis não encontrado: " + dir.toAbsolutePath() +
                    ". Configure a propriedade 'truststore.trusted-certs.dir'");
        }
        if (!Files.isDirectory(dir)) {
            throw new IllegalStateException(
                    "O caminho configurado não é um diretório: " + dir.toAbsolutePath());
        }
        log.info("Certificados confiáveis configurados via filesystem: {}", dir.toAbsolutePath());
    }

    @Override
    public List<X509Certificate> getCertificates() {
        log.info("Carregando certificados confiáveis de: {}", configuredDir);

        if (isClasspath()) {
            return loadFromClasspath();
        } else {
            return loadFromFilesystem();
        }
    }

    private List<X509Certificate> loadFromClasspath() {
        List<X509Certificate> certificates = new ArrayList<>();

        try {
            List<URL> urls = listClasspathJsonUrls();
            for (URL url : urls) {
                String fileName = extractFileName(url);
                try (InputStream is = url.openStream()) {
                    byte[] jsonBytes = is.readAllBytes();
                    String jsonContent = new String(jsonBytes, StandardCharsets.UTF_8);
                    X509Certificate cert = parseCertificateFromJson(jsonContent, fileName);
                    if (cert != null) {
                        certificates.add(cert);
                        log.debug("Certificado carregado do classpath: {}", fileName);
                    }
                } catch (Exception e) {
                    log.error("Erro ao carregar certificado do classpath {}: {}", fileName, e.getMessage(), e);
                    throw new RuntimeException("Falha ao carregar certificado: " + fileName, e);
                }
            }
        } catch (IOException e) {
            log.error("Erro ao listar recursos do classpath: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao listar certificados confiáveis no classpath", e);
        }

        log.info("Carregados {} certificados confiáveis do classpath", certificates.size());
        return certificates;
    }

    /**
     * Lista todas as URLs de arquivos .json dentro do diretório de classpath configurado.
     * Suporta tanto recursos em diretórios explodidos quanto dentro de JARs.
     */
    private List<URL> listClasspathJsonUrls() throws IOException {
        String dir = classpathDir();
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = FilesystemCertificateProvider.class.getClassLoader();
        }

        Enumeration<URL> dirUrls = cl.getResources(dir);
        List<URL> jsonUrls = new ArrayList<>();

        while (dirUrls.hasMoreElements()) {
            URL dirUrl = dirUrls.nextElement();
            String protocol = dirUrl.getProtocol();

            if ("file".equals(protocol)) {
                try {
                    Path dirPath = Path.of(dirUrl.toURI());
                    if (Files.isDirectory(dirPath)) {
                        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dirPath, "*.json")) {
                            for (Path p : stream) {
                                jsonUrls.add(p.toUri().toURL());
                            }
                        }
                    }
                } catch (URISyntaxException e) {
                    log.warn("URI inválida para recurso de classpath: {}", dirUrl);
                }
            } else if ("jar".equals(protocol)) {
                String jarUrlStr = dirUrl.toString();
                // jar:file:/path/to.jar!/inner/dir
                String[] parts = jarUrlStr.split("!");
                if (parts.length >= 2) {
                    URI jarUri;
                    try {
                        jarUri = new URI(parts[0].substring(4)); // remove "jar:"
                    } catch (URISyntaxException e) {
                        log.warn("URI de JAR inválida: {}", jarUrlStr);
                        continue;
                    }
                    String innerDir = parts[1].startsWith("/") ? parts[1].substring(1) : parts[1];
                    try (FileSystem fs = FileSystems.newFileSystem(jarUri, Collections.emptyMap())) {
                        Path jarDirPath = fs.getPath(innerDir);
                        if (Files.isDirectory(jarDirPath)) {
                            try (DirectoryStream<Path> stream = Files.newDirectoryStream(jarDirPath, "*.json")) {
                                for (Path p : stream) {
                                    jsonUrls.add(new URL("jar:" + jarUri.toASCIIString() + "!/" + innerDir + "/" + p.getFileName()));
                                }
                            }
                        }
                    } catch (IOException e) {
                        log.warn("Erro ao acessar JAR {}: {}", jarUri, e.getMessage());
                    }
                }
            }
        }

        // Ordena por nome de arquivo para comportamento determinístico
        jsonUrls.sort(Comparator.comparing(this::extractFileName));
        return jsonUrls;
    }

    private String extractFileName(URL url) {
        String path = url.getPath();
        int lastSlash = path.lastIndexOf('/');
        return lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
    }

    private List<X509Certificate> loadFromFilesystem() {
        List<X509Certificate> certificates = new ArrayList<>();
        Path dir = Path.of(configuredDir);

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.json")) {
            for (Path jsonFile : stream) {
                try {
                    String jsonContent = Files.readString(jsonFile, StandardCharsets.UTF_8);
                    X509Certificate cert = parseCertificateFromJson(jsonContent, jsonFile.getFileName().toString());
                    if (cert != null) {
                        certificates.add(cert);
                        log.debug("Certificado carregado: {}", jsonFile.getFileName());
                    }
                } catch (Exception e) {
                    log.error("Erro ao carregar certificado do arquivo {}: {}",
                            jsonFile.getFileName(), e.getMessage(), e);
                    throw new RuntimeException("Falha ao carregar certificado: " + jsonFile.getFileName(), e);
                }
            }
        } catch (IOException e) {
            log.error("Erro ao listar diretório de certificados: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao listar diretório de certificados confiáveis", e);
        }

        log.info("Carregados {} certificados confiáveis do filesystem", certificates.size());
        return certificates;
    }

    private X509Certificate parseCertificateFromJson(String jsonContent, String fileName) {
        try {
            CertificateDTO dto = objectMapper.readValue(jsonContent, CertificateDTO.class);

            if (dto == null || dto.getPem() == null || dto.getPem().isBlank()) {
                log.warn("Arquivo JSON sem conteúdo PEM: {}", fileName);
                return null;
            }

            byte[] pemBytes = dto.getPem().getBytes(StandardCharsets.UTF_8);
            return CertificateParser.parse(pemBytes);
        } catch (IOException e) {
            throw new RuntimeException("Erro ao parsear JSON: " + fileName, e);
        } catch (CertificateParsingException e) {
            throw new RuntimeException("Erro ao parsear certificado PEM: " + fileName, e);
        }
    }
}
