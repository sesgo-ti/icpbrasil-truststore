package com.github.nogueiralegacy.truststore.service;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateProvider {
    List<X509Certificate> getCertificates();
}
