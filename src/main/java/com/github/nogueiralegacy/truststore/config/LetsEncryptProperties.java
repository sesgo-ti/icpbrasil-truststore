package com.github.nogueiralegacy.truststore.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

/**
 * Propriedades de configuração para certificados Let's Encrypt.
 * Esta classe carrega as URLs dos certificados Let's Encrypt a partir do arquivo de configuração
 * e fornece métodos para acessá-las de forma segura.
 */
@Getter
@Setter
@Slf4j
@Validated
@Configuration
@ConfigurationProperties(prefix = "truststore.letsencrypt")
public class LetsEncryptProperties {
    
    /**
     * Mapa contendo os nomes dos certificados e suas respectivas URLs.
     * Exemplo:
     * - isrg-root-x1: https://letsencrypt.org/certs/isrgrootx1.pem
     * - lets-encrypt-r3: https://letsencrypt.org/certs/lets-encrypt-r3.pem
     */
    @NotEmpty(message =
            """
            Pelo menos um certificado Let's Encrypt deve ser configurado em\s
            'truststore.letsencrypt.certificates'
           """)
    private Map<
            @NotBlank(message = "Nome do certificado é obrigatório") String,
            @NotBlank(message = "URL de acesso ao certificado é obrigatória") String
            > certificates;
    
    /**
     * Retorna todas as URLs dos certificados Let's Encrypt como um array.
     * 
     * @return Array contendo todas as URLs configuradas, ou array vazio se nenhuma estiver configurada
     */
    public String[] getCertificateUrls() {
        return certificates.values().toArray(new String[0]);
    }
    
    /**
     * Retorna uma URL específica de certificado pelo nome.
     * 
     * @param name Nome do certificado conforme configurado no arquivo de propriedades
     * @return URL do certificado ou null se não encontrado
     * @throws IllegalArgumentException se o nome for null ou vazio
     */
    public String getCertificateUrl(String name) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Nome do certificado não pode ser null ou vazio");
        }
        
        if (CollectionUtils.isEmpty(certificates)) {
            log.warn("Tentativa de buscar certificado '{}' mas nenhum certificado está configurado", name);
            return null;
        }
        
        String url = certificates.get(name.trim());
        if (url == null) {
            log.warn("Certificado '{}' não encontrado. Certificados disponíveis: {}", name, certificates.keySet());
        }
        
        return url;
    }
    
    /**
     * Verifica se existe um certificado com o nome especificado.
     * 
     * @param name Nome do certificado
     * @return true se o certificado existir, false caso contrário
     */
    public boolean hasCertificate(String name) {
        if (!StringUtils.hasText(name)) {
            return false;
        }
        return !CollectionUtils.isEmpty(certificates) && certificates.containsKey(name.trim());
    }
}