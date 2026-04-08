package br.gov.go.saude.fhir.truststore.icpbrasil.http;

import lombok.Data;

import java.util.List;

@Data
public class DownloadPolicyConfig {
    private long maxOcspResponseBytes = 1_048_576L;
    private long maxCrlResponseBytes = 52_428_800L;
    private long maxAiaResponseBytes = 10_485_760L;
    private boolean blockPrivateHostnames = true;
    private List<String> allowedDomains = List.of();
}
