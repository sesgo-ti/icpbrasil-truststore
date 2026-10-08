package br.gov.go.saude.truststore.icpbrasil.model;

public sealed interface RevocationStatus permits
        RevocationStatus.Good, RevocationStatus.Revoked,
        RevocationStatus.NoDistributionPoints, RevocationStatus.OcspUnavailable,
        RevocationStatus.CrlUnavailable, RevocationStatus.NoConnectivity,
        RevocationStatus.Malformed {

    /**
     * Não revogado no instante da consulta; {@code responseDer} é a evidência (resposta OCSP ou
     * CRL em DER). A evidência pode declarar a revogação do certificado com data posterior ao
     * instante da consulta, e por isso não serve como prova de que ele nunca foi revogado. Se a
     * resposta OCSP foi assinada por responder delegado sem {@code ocsp-nocheck}, a evidência do
     * status desse responder não é incluída.
     */
    record Good(String source, byte[] responseDer) implements RevocationStatus {}
    /**
     * Revogado no instante da consulta: a evidência declara a revogação com data igual ou
     * anterior a esse instante. Com data posterior o certificado ainda não está revogado, e o
     * status é {@link Good}.
     */
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
