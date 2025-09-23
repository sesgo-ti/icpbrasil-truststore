package com.github.nogueiralegacy.truststore.model;

import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import com.github.nogueiralegacy.truststore.util.Downloader;
import com.github.nogueiralegacy.truststore.util.HashValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Slf4j
@Component
public class IcpBrasilCertificateProvider implements CertificateProvider {
    private final TrustStoreConfig trustStoreConfig;
    private final Downloader downloader;
    private final String ICP_BRASIL_ZIP_URL;
    private final String ICP_BRASIL_HASH_URL;
    private final int BUFFER_SIZE = 8192;

    public IcpBrasilCertificateProvider(TrustStoreConfig trustStoreConfig, Downloader downloader) {
        this.trustStoreConfig = trustStoreConfig;
        this.downloader = downloader;
        this.ICP_BRASIL_ZIP_URL = trustStoreConfig.getCertificateUrl();
        this.ICP_BRASIL_HASH_URL = trustStoreConfig.getHashUrl();
    }

    @Override
    public List<X509Certificate> getCertificates() {
        try {
            log.info("Iniciando download dos certificados ICP-Brasil");

            // Download do ZIP
            byte[] zipData = downloadZip(ICP_BRASIL_ZIP_URL);
            
            // Download e validação do hash
            String expectedHash = downloadHash(ICP_BRASIL_HASH_URL);
            if (!validateZipHash(zipData, expectedHash)) {
                throw new SecurityException("Hash do arquivo ZIP não confere com o esperado");
            }
            
            // Extração e parsing dos certificados
            List<X509Certificate> certificates = extractCertificatesFromZip(zipData);
            
            log.info("Certificados ICP-Brasil carregados com sucesso: {} certificados", certificates.size());
            return certificates;
            
        } catch (Exception e) {
            log.error("Erro ao carregar certificados ICP-Brasil: {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao carregar certificados ICP-Brasil", e);
        }
    }

    private byte[] downloadZip(String zipUrl) throws IOException {
        log.debug("Fazendo download do ZIP: {}", zipUrl);
        byte[] zipData = downloader.downloadBytes(zipUrl);
        log.debug("Download concluído: {} bytes", zipData.length);
        return zipData;
    }

    private String downloadHash(String hashUrl) throws IOException {
        log.debug("Fazendo download do hash: {}", hashUrl);
        
        String hashContent = downloader.downloadText(hashUrl);
        
        if (!StringUtils.hasText(hashContent)) {
            throw new IOException("Hash vazio ou inválido");
        }
        
        // Remove possível nome do arquivo do hash (formato: hash filename)
        String cleanHash = hashContent.split("\\s+")[0].trim();
        log.debug("Hash obtido: {}", cleanHash);
        return cleanHash;
    }

    private boolean validateZipHash(byte[] zipData, String expectedHash) {
        try {
            log.debug("Validando hash do ZIP");
            boolean isValid = HashValidator.validateSha512(zipData, expectedHash);
            
            if (isValid) {
                log.info("Hash do ZIP validado com sucesso");
            } else {
                log.error("Hash do ZIP não confere com o esperado");
            }
            
            return isValid;
            
        } catch (Exception e) {
            log.error("Erro ao validar hash: {}", e.getMessage(), e);
            return false;
        }
    }

    private List<X509Certificate> extractCertificatesFromZip(byte[] zipData) throws IOException {
        log.debug("Extraindo certificados do ZIP");
        
        List<X509Certificate> certificates = new ArrayList<>();
        
        try (ByteArrayInputStream bais = new ByteArrayInputStream(zipData);
             ZipInputStream zipInputStream = new ZipInputStream(bais)) {
            
            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                // O formato do ACcompactado.zip não tem diretórios
                if (entry.isDirectory()) {
                    continue;
                }
                
                String fileName = entry.getName().toLowerCase();
                if (!isCertificateFile(fileName)) {
                    log.debug("Ignorando arquivo: {}", entry.getName());
                    continue;
                }
                
                try {
                    // Extrai os dados da entrada do ZIP
                    byte[] certData = readZipEntryData(zipInputStream);
                    
                    // Faz o parse do certificado usando os dados extraídos
                    X509Certificate certificate = CertificateParser.parse(certData);
                    
                    if (certificate != null) {
                        certificates.add(certificate);
                        log.debug("Certificado extraído: {}", entry.getName());
                    }
                    
                } catch (Exception e) {
                    log.warn("Erro ao processar certificado {}: {}", entry.getName(), e.getMessage());
                }
            }
        }
        
        log.info("Extraídos {} certificados do ZIP", certificates.size());
        return certificates;
    }

    private boolean isCertificateFile(String fileName) {
        return fileName.endsWith(".crt") || 
               fileName.endsWith(".cer") || 
               fileName.endsWith(".pem") ||
               fileName.endsWith(".der");
    }

    private byte[] readZipEntryData(ZipInputStream zipInputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead;
        
        while ((bytesRead = zipInputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        
        return outputStream.toByteArray();
    }
}
