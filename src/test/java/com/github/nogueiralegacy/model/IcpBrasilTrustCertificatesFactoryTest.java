package com.github.nogueiralegacy.model;

import java.io.InputStream;

import com.github.nogueiralegacy.truststore.Application;
import com.github.nogueiralegacy.truststore.model.IcpBrasilTrustCertificatesFactory;
import com.github.nogueiralegacy.truststore.util.Util;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = Application.class)
@TestPropertySource(locations = "classpath:application-test.yaml")
public class IcpBrasilTrustCertificatesFactoryTest {
    
    private IcpBrasilTrustCertificatesFactory factory;

    @Autowired
    private Util util;
    
    // Hash SHA-512 real do arquivo ACcompactado.zip de teste
    private static final String VALID_TEST_HASH = "bbc9703e33df4be5b23e900177a3672191ca2f9c5dc68eaf129562ea43f90b89a6525b61b427212dce0b8026ec26ef2ca06ffe491ab911d0bac9722faefdfde2";
    
    @BeforeEach
    public void setUp() {
        InputStream testZipStream = util.getResource("ACcompactado.zip");
        this.factory = new IcpBrasilTrustCertificatesFactory(testZipStream, VALID_TEST_HASH);
    }
    
    @Test
    public void testFactoryCreation() {
        assertNotNull(factory, "Factory deve ser criada com sucesso");
        assertNotNull(factory.getZipInputStream(), "ZipInputStream deve estar disponível");
        assertEquals(VALID_TEST_HASH, factory.getExpectedHash(), "Hash esperado deve corresponder");
    }
    
    @Test
    public void testConstructorWithNullInputStream() {
        assertThrows(IllegalArgumentException.class, () -> {
            new IcpBrasilTrustCertificatesFactory(null, VALID_TEST_HASH);
        }, "Deve lançar exceção para InputStream nulo");
    }
    
    @Test
    public void testConstructorWithNullHash() {
        InputStream testZipStream = util.getResource("ACcompactado.zip");
        assertThrows(IllegalArgumentException.class, () -> {
            new IcpBrasilTrustCertificatesFactory(testZipStream, null);
        }, "Deve lançar exceção para hash nulo");
    }
    
    @Test
    public void testConstructorWithEmptyHash() {
        InputStream testZipStream = util.getResource("ACcompactado.zip");
        assertThrows(IllegalArgumentException.class, () -> {
            new IcpBrasilTrustCertificatesFactory(testZipStream, "");
        }, "Deve lançar exceção para hash vazio");
    }
    
    @Test
    public void testConstructorWithInvalidHashFormat() {
        InputStream testZipStream = util.getResource("ACcompactado.zip");
        assertThrows(IllegalArgumentException.class, () -> {
            new IcpBrasilTrustCertificatesFactory(testZipStream, "invalid-hash");
        }, "Deve lançar exceção para formato de hash inválido");
    }
}
