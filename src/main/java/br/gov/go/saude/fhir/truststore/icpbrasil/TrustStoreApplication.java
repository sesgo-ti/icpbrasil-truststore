package br.gov.go.saude.fhir.truststore.icpbrasil;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties({
    TrustStoreConfig.class
})
@SpringBootApplication
public class TrustStoreApplication {
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(TrustStoreApplication.class);
        
        // Ajusta o tipo de aplicação web (Standalone) com base na propriedade rest.enabled
        app.addListeners((ApplicationEnvironmentPreparedEvent event) -> {
            Boolean restEnabled = event.getEnvironment()
                .getProperty("truststore-icpbrasil.rest.enabled", Boolean.class, true);
            
            if (!Boolean.TRUE.equals(restEnabled)) {
                app.setWebApplicationType(WebApplicationType.NONE);
            }
        });
        
        app.run(args);
    }
}
