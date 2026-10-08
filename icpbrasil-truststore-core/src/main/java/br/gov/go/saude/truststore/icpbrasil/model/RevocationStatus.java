package br.gov.go.saude.truststore.icpbrasil.model;

public sealed interface RevocationStatus permits
        RevocationStatus.Good, RevocationStatus.Revoked,
        RevocationStatus.NoDistributionPoints, RevocationStatus.OcspUnavailable,
        RevocationStatus.CrlUnavailable, RevocationStatus.NoConnectivity,
        RevocationStatus.Malformed {

    /**
     * Não revogado no instante da consulta; {@code responseDer} é a evidência (resposta OCSP ou
     * CRL em DER). Se a resposta OCSP foi assinada por responder delegado sem
     * {@code ocsp-nocheck}, a evidência do status desse responder não é incluída.
     */
    record Good(String source, byte[] responseDer) implements RevocationStatus {}
    record Revoked(String source) implements RevocationStatus {}
    record NoDistributionPoints() implements RevocationStatus {}
    record OcspUnavailable() implements RevocationStatus {}
    record CrlUnavailable() implements RevocationStatus {}
    record NoConnectivity() implements RevocationStatus {}
    record Malformed(String source) implements RevocationStatus {}

    /**
     * Apenas {@link Good} e {@link Revoked} são veredictos sobre o certificado; os demais
     * status descrevem por que nenhum veredicto foi obtido e nunca equivalem a "não revogado".
     */
    default boolean isConclusive() {
        return this instanceof Good || this instanceof Revoked;
    }
}
