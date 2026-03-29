package br.gov.go.saude.fhir.truststore.icpbrasil.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.InputStream;

@Slf4j
@Component
public class Util {

    public InputStream getResource(String resourceName) throws NullPointerException {
        if (!StringUtils.hasText(resourceName)) {
           log.error("resourceName não pode ser null ou vazio");
           throw new IllegalArgumentException("resourceName não pode ser null ou vazio");
        }
        
        InputStream is = this.getClass().getClassLoader().getResourceAsStream(resourceName);
        if (is == null) {
            String errorMsg = "Recurso não encontrado: " + resourceName;
            log.error(errorMsg);
            throw new RuntimeException(errorMsg);
        }

        return is;
    }
}
