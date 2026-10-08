package br.gov.go.saude.truststore.icpbrasil.service.revocation;

import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;

import java.security.cert.X509Certificate;

/**
 * Verificação de revogação do certificado de um responder OCSP delegado, usada por
 * {@link OcspClient#lookup(X509Certificate, X509Certificate, String, ResponderRevocationCheck)}.
 *
 * <p>A evidência deve ser independente da resposta OCSP em análise: consultar o próprio responder
 * sobre si mesmo não prova nada, pois uma chave vazada também assinaria essa resposta. A
 * implementação também não pode depender de nova consulta OCSP, sob pena de recursão.</p>
 */
@FunctionalInterface
public interface ResponderRevocationCheck {

    /**
     * Informa o status de revogação do responder delegado no instante da chamada.
     *
     * <p>É chamada a cada uso de uma resposta de delegado sem {@code ocsp-nocheck}, inclusive
     * quando a resposta vem do cache, e no máximo duas vezes por resposta. Roda na thread de quem
     * consulta o {@link OcspClient}, de forma bloqueante e possivelmente concorrente com outras
     * consultas, por isso a implementação precisa ser thread-safe. Qualquer retorno diferente de
     * {@code Good}, inclusive {@code null}, e qualquer exceção recusam a resposta.</p>
     *
     * @param responder certificado do responder delegado que assinou a resposta
     * @param issuer    AC emissora do responder (a mesma do certificado consultado)
     * @return status de revogação do responder; só {@code Good} permite aceitar a resposta
     */
    RevocationStatus check(X509Certificate responder, X509Certificate issuer);
}
