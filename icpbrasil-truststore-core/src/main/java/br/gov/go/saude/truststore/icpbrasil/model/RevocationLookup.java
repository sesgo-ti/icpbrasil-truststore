package br.gov.go.saude.truststore.icpbrasil.model;

import java.util.Objects;

/**
 * Resultado de uma consulta de revogação: o {@link RevocationStatus} e, quando ele é conclusivo,
 * a {@link RevocationEvidence} que o fundamenta.
 *
 * @param status   veredicto ou motivo da inconclusão
 * @param evidence artefato verificado; presente se, e somente se, {@code status} é conclusivo
 */
public record RevocationLookup(RevocationStatus status, RevocationEvidence evidence) {

    public RevocationLookup {
        Objects.requireNonNull(status, "status");
        if (status.isConclusive() != (evidence != null)) {
            throw new IllegalArgumentException(
                    "Evidência deve acompanhar exatamente os status conclusivos; status=" + status);
        }
    }

    public static RevocationLookup inconclusive(RevocationStatus status) {
        return new RevocationLookup(status, null);
    }

    public boolean isConclusive() {
        return status.isConclusive();
    }
}
