package br.gov.go.saude.truststore.icpbrasil.service.provider;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateProvider {
    List<X509Certificate> getCertificates();
}
