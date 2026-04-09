package br.gov.go.saude.fhir.truststore.icpbrasil.support;

import java.io.InputStream;

/**
 * Carregador estático de resources de teste.
 * Substitui a classe Util que existia em src/main como @Component.
 */
public final class TestResourceLoader {

    private TestResourceLoader() {}

    public static InputStream getResource(String resourceName) {
        if (resourceName == null || resourceName.isBlank()) {
            throw new IllegalArgumentException("resourceName não pode ser null ou vazio");
        }
        InputStream is = TestResourceLoader.class.getClassLoader().getResourceAsStream(resourceName);
        if (is == null) {
            throw new RuntimeException("Recurso não encontrado: " + resourceName);
        }
        return is;
    }
}
