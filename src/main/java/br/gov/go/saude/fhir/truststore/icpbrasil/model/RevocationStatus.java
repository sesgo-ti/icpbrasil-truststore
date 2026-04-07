package br.gov.go.saude.fhir.truststore.icpbrasil.model;

public sealed interface RevocationStatus permits
        RevocationStatus.Good, RevocationStatus.Revoked,
        RevocationStatus.NoDistributionPoints, RevocationStatus.OcspUnavailable,
        RevocationStatus.CrlUnavailable, RevocationStatus.NoConnectivity,
        RevocationStatus.Malformed {

    record Good(String source, byte[] responseDer) implements RevocationStatus {}
    record Revoked(String source) implements RevocationStatus {}
    record NoDistributionPoints() implements RevocationStatus {}
    record OcspUnavailable() implements RevocationStatus {}
    record CrlUnavailable() implements RevocationStatus {}
    record NoConnectivity() implements RevocationStatus {}
    record Malformed(String source) implements RevocationStatus {}
}
