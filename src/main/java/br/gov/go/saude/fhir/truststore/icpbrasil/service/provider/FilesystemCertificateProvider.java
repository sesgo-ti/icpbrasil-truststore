package br.gov.go.saude.fhir.truststore.icpbrasil.service.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateDTO;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
@Component
public class FilesystemCertificateProvider implements CertificateProvider {

    private final ObjectMapper objectMapper;
    private final String configuredDir;
    private final ResourcePatternResolver resourceResolver;

    public FilesystemCertificateProvider(TrustStoreConfig trustStoreConfig) {
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        this.configuredDir = trustStoreConfig.getTrustedCerts().getDir();
        this.resourceResolver = new PathMatchingResourcePatternResolver();
    }

    @PostConstruct
    public void validate() {
        if (!StringUtils.hasText(configuredDir)) {
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
        return configuredDir.startsWith("classpath:");
    }

    private void validateClasspath() {
        try {
            Resource[] resources = resourceResolver.getResources(configuredDir + "/*.json");
            log.info("Certificados confiáveis configurados via classpath: {} ({} arquivo(s) JSON encontrado(s))",
                    configuredDir, resources.length);
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
            Resource[] resources = resourceResolver.getResources(configuredDir + "/*.json");
            for (Resource resource : resources) {
                try (InputStream is = resource.getInputStream()) {
                    byte[] jsonBytes = is.readAllBytes();
                    String jsonContent = new String(jsonBytes, StandardCharsets.UTF_8);
                    X509Certificate cert = parseCertificateFromJson(jsonContent, resource.getFilename());
                    if (cert != null) {
                        certificates.add(cert);
                        log.debug("Certificado carregado do classpath: {}", resource.getFilename());
                    }
                } catch (Exception e) {
                    log.error("Erro ao carregar certificado do classpath {}: {}",
                            resource.getFilename(), e.getMessage(), e);
                    throw new RuntimeException("Falha ao carregar certificado: " + resource.getFilename(), e);
                }
            }
        } catch (IOException e) {
            log.error("Erro ao listar recursos do classpath: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao listar certificados confiáveis no classpath", e);
        }

        log.info("Carregados {} certificados confiáveis do classpath", certificates.size());
        return certificates;
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

            if (dto == null || !StringUtils.hasText(dto.getPem())) {
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
