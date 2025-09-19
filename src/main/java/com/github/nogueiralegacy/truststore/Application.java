package com.github.nogueiralegacy.truststore;

import com.github.nogueiralegacy.truststore.config.TrustStoreConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@EnableConfigurationProperties({
    com.github.nogueiralegacy.truststore.config.TrustStoreConfig.class,
    TrustStoreConfig.class
})
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
