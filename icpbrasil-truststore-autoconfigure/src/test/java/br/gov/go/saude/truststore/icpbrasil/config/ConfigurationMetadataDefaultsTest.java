package br.gov.go.saude.truststore.icpbrasil.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A metadata de configuração gerada ({@code META-INF/spring-configuration-metadata.json}) é o que
 * a IDE mostra ao completar uma propriedade. O processador não vê os inicializadores de
 * {@link TrustStoreConfig} (classe compilada em outro módulo), então os defaults são declarados à
 * mão em {@code additional-spring-configuration-metadata.json}. Este teste impede que essa cópia
 * divirja do POJO: o que a metadata declara como default tem de ser exatamente o que a biblioteca
 * usa quando a propriedade não é informada.
 */
class ConfigurationMetadataDefaultsTest {

    private static final String PREFIX = "icpbrasil-truststore.";

    /** Propriedades sob o prefixo que legitimamente não têm default. */
    private static final Set<String> WITHOUT_DEFAULT = Set.of("icpbrasil-truststore.filesystem.base-dir");

    /** Propriedades fora de {@link TrustStoreConfig}: S3 tem POJO próprio; scheduling é só uma condição. */
    private static final Set<String> OUTSIDE_POJO = Set.of("icpbrasil-truststore.scheduling.enabled");

    static Map<String, JsonNode> properties;

    @BeforeAll
    @SneakyThrows
    static void loadMetadata() {
        properties = new LinkedHashMap<>();
        try (InputStream in = ConfigurationMetadataDefaultsTest.class
                .getResourceAsStream("/META-INF/spring-configuration-metadata.json")) {
            assertNotNull(in, "metadata gerada pelo spring-boot-configuration-processor ausente");
            for (JsonNode property : new ObjectMapper().readTree(in).path("properties")) {
                String name = property.path("name").asText();
                if (name.startsWith(PREFIX) && !name.startsWith(PREFIX + "s3.")) {
                    properties.put(name, property);
                }
            }
        }
    }

    @Test
    void testMetadata_TodaPropriedadeDoPojoDeclaraDefault_ExcetoAsObrigatorias() {
        List<String> semDefault = new ArrayList<>();
        for (Map.Entry<String, JsonNode> entry : properties.entrySet()) {
            if (!entry.getValue().has("defaultValue") && !WITHOUT_DEFAULT.contains(entry.getKey())) {
                semDefault.add(entry.getKey());
            }
        }
        assertEquals(List.of(), semDefault,
                "propriedades sem defaultValue na metadata; declare em additional-spring-configuration-metadata.json");
        for (String name : WITHOUT_DEFAULT) {
            assertTrue(properties.containsKey(name), name + " deveria constar da metadata");
            assertFalse(properties.get(name).has("defaultValue"), name + " é obrigatória e não pode ter default");
        }
    }

    @Test
    void testMetadata_DefaultsDeclaradosCoincidemComOsDoPojo() {
        Map<String, Object> declared = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> entry : properties.entrySet()) {
            JsonNode defaultValue = entry.getValue().get("defaultValue");
            if (defaultValue != null && !OUTSIDE_POJO.contains(entry.getKey())) {
                declared.put(entry.getKey(), asBindable(defaultValue));
            }
        }
        assertFalse(declared.isEmpty());

        // Ligar só os defaults declarados a um POJO novo: se algum valor da metadata for diferente do
        // inicializador correspondente, o objeto ligado deixa de ser igual a um POJO intocado.
        TrustStoreConfig bound = new Binder(new MapConfigurationPropertySource(declared))
                .bind("icpbrasil-truststore", Bindable.of(TrustStoreConfig.class))
                .get();

        assertEquals(new TrustStoreConfig(), bound);
    }

    @Test
    void testMetadata_SchedulingEnabled_DeclaradoComDefaultTrue() {
        JsonNode scheduling = properties.get("icpbrasil-truststore.scheduling.enabled");

        assertNotNull(scheduling, "scheduling.enabled só existe na metadata adicional (é uma @ConditionalOnProperty)");
        assertTrue(scheduling.path("defaultValue").asBoolean());
        assertEquals("java.lang.Boolean", scheduling.path("type").asText());
    }

    @Test
    void testMetadata_TodaPropriedadeTemDescricao() {
        List<String> semDescricao = new ArrayList<>();
        for (Map.Entry<String, JsonNode> entry : properties.entrySet()) {
            if (entry.getValue().path("description").asText().isBlank()) {
                semDescricao.add(entry.getKey());
            }
        }
        assertEquals(List.of(), semDescricao, "propriedades sem description na metadata");
    }

    /** Listas viram o formato com vírgulas que o Binder aceita; escalares entram como estão. */
    private static Object asBindable(JsonNode node) {
        if (node.isArray()) {
            List<String> items = new ArrayList<>();
            node.forEach(item -> items.add(item.asText()));
            return String.join(",", items);
        }
        if (node.isBoolean()) {
            return node.asBoolean();
        }
        if (node.isNumber()) {
            return node.numberValue();
        }
        return node.asText();
    }
}
