package com.github.nogueiralegacy.truststore.config;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@Configuration
@ConfigurationProperties(prefix = "truststore.vault")
public class VaultProperties {
    @NotBlank(message = "Vault certificates path must be provided")
    private String certificatePath;
}
