package com.github.nogueiralegacy.truststore.config;

import com.github.nogueiralegacy.truststore.http.VaultCertificateManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Primary;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.HttpURLConnection;

/**
 * Configuração customizada do cliente Vault que usa o certificado SSL específico
 * carregado pelo VaultCertificateManager ao invés do truststore padrão da JVM.
 * 
 * Esta configuração cria um ClientHttpRequestFactory customizado que será usado
 * pelo VaultTemplate auto-configurado do Spring Boot.
 * 
 * IMPORTANTE: Depende explicitamente do VaultCertificateManager estar inicializado
 * pois precisa do SSLContext configurado com o certificado SSL do Vault.
 */
@Slf4j
@Configuration
@DependsOn("vaultCertificateManager")
@RequiredArgsConstructor
public class VaultClientConfiguration {
    
    private final VaultCertificateManager vaultCertificateManager;
    
    @Value("${spring.cloud.vault.connection-timeout:5000}")
    private int connectionTimeout;
    
    @Value("${spring.cloud.vault.read-timeout:15000}")
    private int readTimeout;
    
    /**
     * Cria um ClientHttpRequestFactory customizado que usa o SSLContext
     * do VaultCertificateManager com o certificado SSL específico do Vault.
     * 
     * Este factory SOBRESCREVE o comportamento padrão do Spring que usa
     * o truststore padrão da JVM.
     * 
     * O Spring Boot auto-detecta este bean e o usa para configurar o VaultTemplate.
     */
    @Bean
    @Primary
    public ClientHttpRequestFactory vaultClientHttpRequestFactory() {
        log.info("Criando ClientHttpRequestFactory customizado para Vault com certificado SSL específico");
        
        // Obtém o SSLContext configurado com o certificado SSL do Vault
        SSLContext vaultSSLContext = vaultCertificateManager.getVaultSSLContext();
        
        // Cria factory customizado que aplica o SSLContext em cada conexão
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                super.prepareConnection(connection, httpMethod);
                
                // Configura SSL Context customizado para conexões HTTPS
                if (connection instanceof HttpsURLConnection httpsConnection) {
                    httpsConnection.setSSLSocketFactory(vaultSSLContext.getSocketFactory());
                    log.debug("SSLContext customizado aplicado à conexão HTTPS com o Vault");
                }
            }
        };
        
        // Configura timeouts
        factory.setConnectTimeout(connectionTimeout);
        factory.setReadTimeout(readTimeout);
        
        log.info("ClientHttpRequestFactory configurado com sucesso com certificado SSL específico do Vault");
        
        return factory;
    }
}

