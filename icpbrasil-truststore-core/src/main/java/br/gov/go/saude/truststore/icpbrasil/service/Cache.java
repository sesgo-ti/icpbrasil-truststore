package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Índice em memória do acervo ICP-Brasil (SKI → certificado), servido aos consumidores.
 *
 * <p><strong>Modelo de segurança:</strong> a leitura é pública; a <em>escrita</em> é
 * restrita ao pipeline legítimo de carga ({@link TrustStoreService}, mesmo pacote), que só
 * publica um acervo depois de validar o hash SHA-512 e parsear todos os certificados.
 * Código fora do pipeline não consegue substituir nem revalidar o acervo.</p>
 *
 * <p><strong>Validade:</strong> cada publicação é um snapshot imutável com o instante em que
 * a geração foi confirmada junto ao ITI e o instante em que expira. A expiração é verificada
 * a cada leitura, com o relógio injetado: um acervo cuja confirmação não foi renovada deixa
 * de ser servido no prazo, mesmo que nenhuma atualização volte a executar.</p>
 *
 * <p><strong>Concorrência:</strong> o snapshot é trocado por atribuição atômica de uma única
 * referência {@code volatile}; leitores nunca observam índice e validade de gerações
 * diferentes. As escritas são serializadas entre si para que {@code renew} nunca republique
 * um índice descartado por {@code invalidate} concorrente.</p>
 *
 * <p>Uma instância por aplicação: a auto-configuração expõe o bean compartilhado.</p>
 */
@Slf4j
public class Cache {

    /**
     * Estado observável do acervo publicado, sem I/O.
     *
     * @param hash        SHA-512 (hex) do ZIP de origem
     * @param confirmedAt instante em que a geração foi confirmada como vigente junto ao ITI
     * @param expiresAt   instante a partir do qual o acervo deixa de ser servido
     * @param valid       {@code true} se o acervo ainda é servido no instante da consulta
     */
    public record State(String hash, Instant confirmedAt, Instant expiresAt, boolean valid) {
    }

    /**
     * Resposta de {@link #lookupCertificate} obtida de um único snapshot.
     *
     * @param available   {@code true} se havia acervo vigente no instante da consulta
     * @param certificate certificado com o SKI consultado; {@code null} se ele não está no
     *                    acervo vigente ou se não há acervo vigente ({@code available == false})
     */
    public record Lookup(boolean available, X509Certificate certificate) {
    }

    private record Snapshot(Map<String, X509Certificate> index, String hash,
                            Instant confirmedAt, Instant expiresAt) {
    }

    private final Clock clock;
    private volatile Snapshot snapshot;

    public Cache() {
        this(Clock.systemUTC());
    }

    public Cache(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Monta o índice SKI → certificado a partir dos certificados já parseados.
     * Falha se algum certificado não tiver SKI, para que o pipeline detecte o problema antes
     * de persistir ou publicar qualquer coisa.
     *
     * @throws IllegalArgumentException se algum certificado não possuir a extensão SKI
     */
    static Map<String, X509Certificate> indexBySki(List<X509Certificate> certificates) {
        Map<String, X509Certificate> index = new HashMap<>();
        for (X509Certificate certificate : certificates) {
            String ski;
            try {
                ski = CertificateParser.getSubjectKeyIdentifier(certificate);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("Certificado sem Subject Key Identifier: "
                        + certificate.getSubjectX500Principal(), e);
            }
            X509Certificate anterior = index.put(ski, certificate);
            if (anterior != null) {
                log.warn("SKI {} duplicado no acervo; mantido o último certificado ({})",
                        ski, certificate.getSubjectX500Principal());
            }
        }
        return Map.copyOf(index);
    }

    /**
     * Publica um novo snapshot, substituindo o anterior de forma atômica.
     * Pré-condição (garantida pelo pipeline): o índice foi montado a partir de um ZIP cujo
     * hash foi validado e cujos certificados foram todos parseados.
     */
    synchronized void publish(Map<String, X509Certificate> index, String hash,
                              Instant confirmedAt, Instant expiresAt) {
        snapshot = new Snapshot(Map.copyOf(index), Objects.requireNonNull(hash, "hash"),
                Objects.requireNonNull(confirmedAt, "confirmedAt"),
                Objects.requireNonNull(expiresAt, "expiresAt"));
        log.info("Cache de certificados atualizado com {} entradas (hash {}, expira em {}).",
                index.size(), hash, expiresAt);
    }

    /**
     * Renova a validade do snapshot atual, mantendo o mesmo índice, somente se ele
     * corresponder ao {@code hash} reconfirmado junto ao ITI. Um snapshot já expirado pode
     * ser renovado: seu conteúdo foi validado neste processo e acabou de ser reconfirmado.
     *
     * @return {@code false} se não há snapshot ou se o hash não corresponde; nesse caso nada
     *         muda e o chamador deve obter e validar o acervo por completo
     */
    synchronized boolean renew(String hash, Instant confirmedAt, Instant expiresAt) {
        Snapshot atual = snapshot;
        if (atual == null || !atual.hash().equals(hash)) {
            return false;
        }
        snapshot = new Snapshot(atual.index(), hash, Objects.requireNonNull(confirmedAt, "confirmedAt"),
                Objects.requireNonNull(expiresAt, "expiresAt"));
        log.info("Validade do cache renovada até {} (hash {}).", expiresAt, hash);
        return true;
    }

    /**
     * Descarta o snapshot; até a próxima publicação as leituras retornam vazio (fail-closed).
     */
    synchronized void invalidate() {
        snapshot = null;
        log.warn("Cache de certificados invalidado.");
    }

    /**
     * @return o snapshot vigente, ou {@code null} se não há snapshot ou se ele já expirou
     *         segundo o relógio — a expiração é decidida no instante da leitura, não no refresh
     */
    private Snapshot vigente() {
        Snapshot atual = snapshot;
        if (atual == null || !clock.instant().isBefore(atual.expiresAt())) {
            return null;
        }
        return atual;
    }

    /**
     * @return o certificado com o SKI informado, ou {@code null} se não existe no acervo ou se
     *         não há acervo vigente
     */
    public X509Certificate getCertificateBySki(String ski) {
        Snapshot atual = vigente();
        return atual == null ? null : atual.index().get(ski);
    }

    /**
     * Consulta um SKI informando, na mesma leitura, se havia acervo vigente. Permite distinguir
     * "acervo indisponível" de "SKI inexistente" sem uma segunda leitura, que poderia observar
     * outro snapshot ou a expiração ocorrida entre as duas chamadas.
     */
    public Lookup lookupCertificate(String ski) {
        Snapshot atual = vigente();
        if (atual == null) {
            return new Lookup(false, null);
        }
        return new Lookup(true, atual.index().get(ski));
    }

    /**
     * Retorna uma cópia do mapa de certificados indexados por SKI.
     *
     * @return Mapa SKI → X509Certificate (cópia defensiva); vazio se não há acervo vigente
     */
    public Map<String, X509Certificate> getAllCertificates() {
        Snapshot atual = vigente();
        return atual == null ? new HashMap<>() : new HashMap<>(atual.index());
    }

    /**
     * Retorna os certificados raiz (auto-assinados) indexados por SKI.
     * Um certificado é considerado raiz quando subject e issuer são iguais
     * e a assinatura é verificável com a própria chave pública.
     *
     * @return Mapa SKI → X509Certificate contendo apenas certificados raiz; vazio se não há
     *         acervo vigente
     */
    public Map<String, X509Certificate> getRootCertificates() {
        Map<String, X509Certificate> roots = new HashMap<>();
        Snapshot atual = vigente();
        if (atual == null) {
            return roots;
        }
        for (Map.Entry<String, X509Certificate> entry : atual.index().entrySet()) {
            if (CertificateParser.isSelfSigned(entry.getValue())) {
                roots.put(entry.getKey(), entry.getValue());
            }
        }
        return roots;
    }

    /**
     * @return {@code true} se há um snapshot publicado e ainda não expirado
     */
    public boolean isCacheValid() {
        return vigente() != null;
    }

    /**
     * Estado do último snapshot publicado, inclusive quando já expirado (com
     * {@code valid = false}), para diagnóstico sem tocar no repositório.
     *
     * @return vazio se nenhum snapshot foi publicado ou se o cache foi invalidado
     */
    public Optional<State> getState() {
        Snapshot atual = snapshot;
        if (atual == null) {
            return Optional.empty();
        }
        boolean valid = clock.instant().isBefore(atual.expiresAt());
        return Optional.of(new State(atual.hash(), atual.confirmedAt(), atual.expiresAt(), valid));
    }
}
