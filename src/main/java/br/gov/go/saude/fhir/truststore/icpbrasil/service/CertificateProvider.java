package br.gov.go.saude.fhir.truststore.icpbrasil.service;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateProvider {
    List<X509Certificate> getCertificates();
}
