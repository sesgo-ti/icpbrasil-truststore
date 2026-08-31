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
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Slf4j
public class IcpBrasilCertificateProvider implements CertificateProvider {
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

    @Override
    public List<X509Certificate> getCertificates() {
        log.info("Iniciando obtenção dos certificados ICP-Brasil");

        try {
            byte[] zipData = obterZipData();
            String expectedHash = obterHashEsperado();
            
            validateZipIntegrity(zipData, expectedHash);
            List<X509Certificate> certificates = extractCertificatesFromZip(zipData);

            log.info("Certificados ICP-Brasil carregados com sucesso: {} certificados", certificates.size());
            return certificates;

        } catch (SecurityException e) {
            log.error("Falha na validação de segurança: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Erro ao carregar certificados ICP-Brasil: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao carregar certificados ICP-Brasil", e);
        }
    }

    private byte[] obterZipData() {
        // Tenta primeiro do repositório local
        Optional<byte[]> zipOpt = trustStoreRepository.recuperarZip();
        if (zipOpt.isPresent()) {
            byte[] zipData = zipOpt.get();
            if (zipData.length > 0) {
                log.info("ZIP obtido do repositório local");
                return zipData;
            }
        }

        return baixarZipIcpBrasil();
    }

    private String obterHashEsperado() {
        // Tenta primeiro do repositório local
        try {
            Optional<String> hashOpt = trustStoreRepository.recuperarHash();
            if (hashOpt.filter(s -> s != null && !s.isBlank()).isPresent()) {
                log.info("Hash obtido do repositório local");
                return hashOpt.get();
            }
        } catch (Exception e) {
            log.debug("Erro ao recuperar hash do repositório local: {}", e.getMessage());
        }

        return baixarHashIcpBrasil();
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

    public String baixarHashIcpBrasil() {
        log.info("Baixando hash da URL remota");
        try {
            String hashContent = downloader.downloadText(icpBrasilHashUrl);
            if (hashContent == null || hashContent.isBlank()) {
                throw new IOException("Hash vazio ou inválido");
            }
            return hashContent.split("\\s+")[0].trim();
        } catch (Exception e) {
            throw new RecoveryIcpBrasilResourceException("Falha ao baixar hash: " + icpBrasilHashUrl, e);
        }
    }

    public Instant validateZipIntegrity(byte[] zipData, String expectedHash) {
        try {
            if (!HashValidator.validateSha512(zipData, expectedHash)) {
                throw new SecurityException("Hash do arquivo ZIP não confere com o esperado");
            }
            log.info("Integridade do ZIP validada com sucesso");
            return Instant.now();
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Erro ao validar integridade do ZIP: " + e.getMessage(), e);
        }
    }

    private List<X509Certificate> extractCertificatesFromZip(byte[] zipData) throws IOException {
        List<X509Certificate> certificates = new ArrayList<>();

        try (ByteArrayInputStream bais = new ByteArrayInputStream(zipData);
                ZipInputStream zipInputStream = new ZipInputStream(bais)) {

            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                if (!entry.isDirectory() && isCertificateFile(entry.getName())) {
                    processarCertificado(zipInputStream, entry.getName(), certificates);
                }
            }
        }

        log.info("Extraídos {} certificados do ZIP", certificates.size());
        return certificates;
    }

    private void processarCertificado(ZipInputStream zipInputStream, String fileName, 
            List<X509Certificate> certificates) {
        try {
            byte[] certData = IOUtils.toByteArray(zipInputStream);
            X509Certificate certificate = CertificateParser.parse(certData);
            
            if (certificate != null) {
                certificates.add(certificate);
            }
        } catch (Exception e) {
            log.warn("Erro ao processar certificado {}: {}", fileName, e.getMessage());
        }
    }

    private boolean isCertificateFile(String fileName) {
        String lowerFileName = fileName.toLowerCase();
        return lowerFileName.endsWith(".crt") ||
                lowerFileName.endsWith(".cer") ||
                lowerFileName.endsWith(".pem") ||
                lowerFileName.endsWith(".der");
    }
}
