package br.gov.go.saude.truststore.icpbrasil.service.pkix;

import java.util.Optional;

/** Fornece o material de confiança vigente; vazio quando nenhuma validação deve ocorrer. */
public interface TrustMaterialSource {

    Optional<TrustMaterial> current();
}
