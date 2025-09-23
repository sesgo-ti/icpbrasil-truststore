package com.github.nogueiralegacy.truststore.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.InputStream;

@Slf4j
@Component
public class Util {

    public InputStream getResource(String resourceName) throws NullPointerException {
        if (resourceName == null) {
           log.error("resourceName não pode ser null");
        }
        InputStream is = this.getClass().getClassLoader().getResourceAsStream(resourceName);
        if (is == null) {
            log.warn("Recurso {} não encontrado", resourceName);
        }

        return is;
    }


}
