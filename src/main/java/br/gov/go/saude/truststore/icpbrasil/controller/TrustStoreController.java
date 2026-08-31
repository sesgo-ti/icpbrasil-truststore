package br.gov.go.saude.truststore.icpbrasil.controller;

import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Controller REST para gerenciar e consultar certificados vigentes ICP-Brasil.
 */
@Slf4j
@ConditionalOnProperty(
    prefix = "truststore-icpbrasil.rest",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
@RestController
@RequestMapping("/certificate")
public class TrustStoreController {
    // Constantes para tipos de certificado
    private static final String TYPE_PEM = "pem";
    private static final String TYPE_DER = "der";
    private static final String DEFAULT_TYPE = TYPE_PEM;

    /**
     * Retorna o certificado com base no Subject Key Identifier (SKI).
     * Por padrão retorna em formato PEM, mas pode ser especificado DER através do parâmetro type.
     *
     * @param ski identificador SKI do certificado
     * @param type tipo de formato do certificado (pem ou der). Padrão: pem
     * @return certificado correspondente ao SKI fornecido no formato especificado
     */
    @GetMapping
    public ResponseEntity<?> getCertificate(@RequestParam String ski, 
                                           @RequestParam(defaultValue = DEFAULT_TYPE) String type) {
        try {
            log.info("Buscando certificado para SKI: {}", ski);
            X509Certificate cert = Cache.getCertificateBySki(ski);

            if (cert == null) {
                log.warn("Certificado não encontrado para SKI: {}", ski);
                return ResponseEntity.notFound().build();
            }

            // Validar tipo de formato
            if (!TYPE_PEM.equalsIgnoreCase(type) && !TYPE_DER.equalsIgnoreCase(type)) {
                log.warn("Tipo de formato inválido: {}. Tipos válidos: pem, der", type);
                return ResponseEntity.badRequest()
                    .body("Tipo de formato inválido. Use 'pem' ou 'der'");
            }

            if (TYPE_DER.equalsIgnoreCase(type)) {
                return getCertificateAsDer(cert, ski);
            } else {
                return getCertificateAsPem(cert);
            }

        } catch (Exception e) {
            log.error("Erro ao obter certificado: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Retorna o certificado no formato PEM (texto).
     *
     * @param cert certificado X509
     * @return ResponseEntity com certificado em formato PEM
     */
    private ResponseEntity<String> getCertificateAsPem(X509Certificate cert) {
        try {
            // Converter o certificado para Base64 e adicionar headers PEM
            String base64Cert = Base64.getEncoder().encodeToString(cert.getEncoded());
            
            // Formatar como PEM com quebras de linha a cada 64 caracteres
            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.append("-----BEGIN CERTIFICATE-----\n");
            
            for (int i = 0; i < base64Cert.length(); i += 64) {
                int endIndex = Math.min(i + 64, base64Cert.length());
                pemBuilder.append(base64Cert.substring(i, endIndex)).append("\n");
            }
            
            pemBuilder.append("-----END CERTIFICATE-----");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            
            return new ResponseEntity<>(pemBuilder.toString(), headers, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Erro ao converter certificado para PEM: {}", e.getMessage(), e);
            throw new RuntimeException("Erro na conversão para PEM", e);
        }
    }

    /**
     * Retorna o certificado no formato DER (binário).
     *
     * @param cert certificado X509
     * @param ski identificador SKI para nome do arquivo
     * @return ResponseEntity com certificado em formato DER
     */
    private ResponseEntity<byte[]> getCertificateAsDer(X509Certificate cert, String ski) {
        try {
            // Converte o certificado em formato DER (binário)
            byte[] derBytes = cert.getEncoded();

            // Cria cabeçalhos para forçar o download do arquivo
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/x-x509-ca-cert"));
            headers.setContentDisposition(
                    ContentDisposition.attachment()
                            .filename(ski + ".der")
                            .build()
            );

            return new ResponseEntity<>(derBytes, headers, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Erro ao converter certificado para DER: {}", e.getMessage(), e);
            throw new RuntimeException("Erro na conversão para DER", e);
        }
    }
}