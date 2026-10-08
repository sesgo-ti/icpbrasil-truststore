package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.http.tls.ItiTlsAnchors;
import br.gov.go.saude.truststore.icpbrasil.http.tls.TlsTrust;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class TrustStoreManagerTest {

    @Test
    void testConstrutor_ConfiancaDedicada_ExpoeSslContextEAncoras() {
        TrustStoreManager manager = new TrustStoreManager(TlsTrust.dedicatedCa(ItiTlsAnchors.load()));

        assertNotNull(manager.getSslContext());
        assertEquals(2, manager.getAcceptedIssuers().length);
    }
}
