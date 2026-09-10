package br.gov.go.saude.truststore.icpbrasil.model;

import org.junit.jupiter.api.Test;

import java.security.cert.X509CRL;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class RevocationLookupTest {

    @Test
    void testConstrutor_StatusConclusivoComEvidencia_Aceito() {
        RevocationLookup lookup = new RevocationLookup(new RevocationStatus.Revoked("CRL"),
                new RevocationEvidence.Crl(mock(X509CRL.class)));

        assertTrue(lookup.isConclusive());
        assertNotNull(lookup.evidence());
    }

    @Test
    void testConstrutor_StatusConclusivoSemEvidencia_Rejeitado() {
        assertThrows(IllegalArgumentException.class,
                () -> new RevocationLookup(new RevocationStatus.Good("OCSP", new byte[0]), null));
    }

    @Test
    void testConstrutor_StatusInconclusivoComEvidencia_Rejeitado() {
        assertThrows(IllegalArgumentException.class,
                () -> new RevocationLookup(new RevocationStatus.OcspUnavailable(),
                        new RevocationEvidence.OcspResponse(new byte[0])));
    }

    @Test
    void testInconclusive_SemEvidencia() {
        RevocationLookup lookup = RevocationLookup.inconclusive(new RevocationStatus.Malformed("CRL"));

        assertFalse(lookup.isConclusive());
        assertNull(lookup.evidence());
    }
}
