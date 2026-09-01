package br.gov.go.saude.truststore.icpbrasil.service.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateDTO;
import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Provedor de certificados confiáveis que recebe os documentos JSON já lidos externamente.
 *
 * <p>O core não realiza nenhum I/O de classpath ou sistema de arquivos; a responsabilidade
 * de carregar os bytes brutos (com suporte a fat jar, Spring Resources etc.) pertence ao
 * adaptador/autoconfigure que instancia este provider.</p>
 *
 * <p>Cada elemento de {@code jsonDocuments} deve conter os bytes de um JSON no formato
 * {@link CertificateDTO}.</p>
 */
@Slf4j
public class TrustedCertsProvider implements CertificateProvider {

    private final List<byte[]> jsonDocuments;
    private final ObjectMapper objectMapper;

    public TrustedCertsProvider(List<byte[]> jsonDocuments) {
        this.jsonDocuments = List.copyOf(jsonDocuments);
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Override
    public List<X509Certificate> getCertificates() {
        List<X509Certificate> certificates = new ArrayList<>();

        for (byte[] bytes : jsonDocuments) {
            X509Certificate cert = parseCertificateFromJson(bytes);
            if (cert != null) {
                certificates.add(cert);
            }
        }

        log.info("Carregados {} certificados confiáveis", certificates.size());
        return certificates;
    }

    private X509Certificate parseCertificateFromJson(byte[] bytes) {
        try {
            CertificateDTO dto = objectMapper.readValue(bytes, CertificateDTO.class);

            if (dto == null || dto.getPem() == null || dto.getPem().isBlank()) {
                log.warn("Documento JSON sem campo PEM — ignorando");
                return null;
            }

            byte[] pemBytes = dto.getPem().getBytes(StandardCharsets.UTF_8);
            return CertificateParser.parse(pemBytes);
        } catch (IOException e) {
            throw new RuntimeException("Erro ao parsear JSON do documento", e);
        } catch (CertificateParsingException e) {
            throw new RuntimeException("Erro ao parsear certificado PEM", e);
        }
    }
}
