package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.http.TrustStoreManager.TrustStoreCreationException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

class TrustStoreManagerTest {

    @Test
    void testConstrutor_SemCertificados_LancaTrustStoreCreationException() {
        assertThrows(TrustStoreCreationException.class, () -> new TrustStoreManager(List::of));
    }
}
