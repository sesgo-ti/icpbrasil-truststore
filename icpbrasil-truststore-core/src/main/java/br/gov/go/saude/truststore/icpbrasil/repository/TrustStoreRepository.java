package br.gov.go.saude.truststore.icpbrasil.repository;

import java.time.Instant;
import java.util.Optional;

/**
 * Persistência do acervo ICP-Brasil por geração: o ZIP, seu hash SHA-512 e o instante da última
 * confirmação junto ao ITI formam uma unidade.
 *
 * <p>Contrato de consistência: {@link #armazenarGeracao} grava a geração inteira antes de torná-la
 * vigente, e {@link #recuperarGeracao} devolve uma geração completa ou vazio — nunca o ZIP de uma
 * geração com o hash ou a confirmação de outra. Uma interrupção no meio da escrita deixa vigente a
 * geração anterior.</p>
 */
public interface TrustStoreRepository {

    /**
     * Geração persistida, lida de uma única referência vigente.
     *
     * @param zip               conteúdo do ZIP de certificados
     * @param hash              SHA-512 (hex) anunciado pelo ITI para esse ZIP
     * @param ultimaConfirmacao instante em que a geração foi confirmada vigente junto ao ITI
     */
    record Geracao(byte[] zip, String hash, Instant ultimaConfirmacao) {
    }

    /** Geração vigente completa, ou vazio se não há geração ou se ela está incompleta. */
    Optional<Geracao> recuperarGeracao();

    /**
     * Hash da geração vigente, sem ler o ZIP.
     */
    Optional<String> recuperarHash();

    /**
     * Grava ZIP e confirmação da geração e só então a torna vigente.
     *
     * @throws IllegalArgumentException se {@code hash} não for hexadecimal
     */
    void armazenarGeracao(byte[] zip, String hash, Instant confirmacao);

    /**
     * Renova a confirmação da geração vigente.
     *
     * @throws IllegalStateException se não há geração vigente
     */
    void armazenarUltimaConfirmacao(Instant instant);

    default Optional<byte[]> recuperarZip() {
        return recuperarGeracao().map(Geracao::zip);
    }

    default Optional<Instant> recuperarUltimaConfirmacao() {
        return recuperarGeracao().map(Geracao::ultimaConfirmacao);
    }
}
