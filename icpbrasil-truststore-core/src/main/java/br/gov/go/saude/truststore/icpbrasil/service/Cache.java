package br.gov.go.saude.truststore.icpbrasil.service;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RaizDescartada;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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
     * @param raizesNaoFixadas raízes descartadas por não constarem da lista fixada; imutável e
     *                    vazia quando nenhuma foi descartada
     */
    public record State(String hash, Instant confirmedAt, Instant expiresAt, boolean valid,
                        List<RaizDescartada> raizesNaoFixadas) {
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

    /**
     * @param index        SKI → candidato preferido (ver {@link #PREFERENCE})
     * @param candidates   SKI → todos os certificados com esse SKI, o preferido primeiro
     * @param certificates todos os certificados distintos da geração, na ordem recebida
     * @param raizesNaoFixadas raízes descartadas na geração, fora de {@code index} e {@code certificates}
     */
    private record Snapshot(Map<String, X509Certificate> index, Map<String, List<X509Certificate>> candidates,
                            List<X509Certificate> certificates, List<RaizDescartada> raizesNaoFixadas,
                            String hash, Instant confirmedAt, Instant expiresAt) {
    }

    /**
     * Ordem entre certificados que compartilham o SKI (mesma chave, reemitida ou cross-signed):
     * autoassinado primeiro, por encerrar a cadeia; depois o de maior {@code notAfter}; por fim,
     * o menor fingerprint SHA-256, só para que a escolha não dependa da ordem recebida.
     */
    static final Comparator<X509Certificate> PREFERENCE =
            Comparator.comparing((X509Certificate certificate) -> !CertificateParser.isSelfSignedRoot(certificate))
                    .thenComparing(X509Certificate::getNotAfter, Comparator.reverseOrder())
                    .thenComparing(CertificateParser::getFingerprintSha256);

    private final Clock clock;
    private volatile Snapshot snapshot;

    public Cache() {
        this(Clock.systemUTC());
    }

    public Cache(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Índice com uma entrada por SKI: o candidato preferido segundo {@link #PREFERENCE}. Os
     * demais certificados com o mesmo SKI ficam fora do índice; no acervo publicado, continuam
     * acessíveis por {@link #getCertificatesBySki} e {@link #currentCertificates}.
     *
     * @throws IllegalArgumentException se algum certificado não possuir a extensão SKI
     */
    public static Map<String, X509Certificate> indexBySki(List<X509Certificate> certificates) {
        Map<String, X509Certificate> index = new HashMap<>();
        candidatesBySki(distinct(certificates)).forEach((ski, candidates) -> index.put(ski, candidates.getFirst()));
        return Map.copyOf(index);
    }

    private static List<X509Certificate> distinct(List<X509Certificate> certificates) {
        return List.copyOf(new LinkedHashSet<>(certificates));
    }

    private static Map<String, List<X509Certificate>> candidatesBySki(List<X509Certificate> certificates) {
        Map<String, List<X509Certificate>> grouped = new LinkedHashMap<>();
        for (X509Certificate certificate : certificates) {
            String ski;
            try {
                ski = CertificateParser.getSubjectKeyIdentifier(certificate);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("Certificado sem Subject Key Identifier: "
                        + certificate.getSubjectX500Principal(), e);
            }
            grouped.computeIfAbsent(ski, k -> new ArrayList<>()).add(certificate);
        }
        Map<String, List<X509Certificate>> candidates = new HashMap<>();
        grouped.forEach((ski, list) -> {
            if (list.size() > 1) {
                log.info("SKI {} compartilhado por {} certificados no acervo; todos mantidos", ski, list.size());
            }
            candidates.put(ski, list.stream().sorted(PREFERENCE).toList());
        });
        return Map.copyOf(candidates);
    }

    /**
     * Publica um novo snapshot, substituindo o anterior de forma atômica. Certificados idênticos
     * contam uma vez; os que compartilham SKI são todos mantidos.
     *
     * @throws IllegalArgumentException se algum certificado não possuir a extensão SKI; nesse
     *                                  caso o snapshot anterior é mantido
     */
    synchronized void publish(List<X509Certificate> certificates, String hash,
                              Instant confirmedAt, Instant expiresAt) {
        publish(certificates, List.of(), hash, confirmedAt, expiresAt);
    }

    /**
     * Como {@link #publish(List, String, Instant, Instant)}, registrando no snapshot as raízes
     * descartadas informadas, que não entram no índice e aparecem em {@link State#raizesNaoFixadas}.
     */
    synchronized void publish(List<X509Certificate> certificates, List<RaizDescartada> raizesNaoFixadas,
                              String hash, Instant confirmedAt, Instant expiresAt) {
        List<X509Certificate> distinct = distinct(certificates);
        Map<String, List<X509Certificate>> candidates = candidatesBySki(distinct);
        Map<String, X509Certificate> index = new HashMap<>();
        candidates.forEach((ski, list) -> index.put(ski, list.getFirst()));
        snapshot = new Snapshot(Map.copyOf(index), candidates, distinct,
                List.copyOf(raizesNaoFixadas), Objects.requireNonNull(hash, "hash"),
                Objects.requireNonNull(confirmedAt, "confirmedAt"),
                Objects.requireNonNull(expiresAt, "expiresAt"));
        log.info("Cache de certificados atualizado com {} certificados e {} SKIs (hash {}, expira em {}).",
                distinct.size(), index.size(), hash, expiresAt);
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
        snapshot = new Snapshot(atual.index(), atual.candidates(), atual.certificates(),
                atual.raizesNaoFixadas(), hash, Objects.requireNonNull(confirmedAt, "confirmedAt"),
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
     * Todos os certificados do acervo vigente com o SKI informado, o preferido primeiro (ver
     * {@link #PREFERENCE}). Mais de um candidato ocorre quando uma AC foi reemitida ou
     * cross-signed com a mesma chave; quem monta cadeias deve considerar todos.
     *
     * @return lista imutável; vazia se o SKI não existe ou se não há acervo vigente
     */
    public List<X509Certificate> getCertificatesBySki(String ski) {
        Snapshot atual = vigente();
        return atual == null ? List.of() : atual.candidates().getOrDefault(ski, List.of());
    }

    /**
     * Todos os certificados distintos do acervo vigente, inclusive os que compartilham SKI.
     * Como {@link #currentIndex()}, a referência é a da geração publicada e se mantém em
     * {@code renew}, permitindo memoização por geração.
     *
     * @return lista imutável; vazia se não há acervo vigente
     */
    public List<X509Certificate> currentCertificates() {
        Snapshot atual = vigente();
        return atual == null ? List.of() : atual.certificates();
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
     * Índice do acervo vigente, imutável e sem cópia. A identidade da referência é a da geração
     * publicada: muda a cada {@code publish} e se mantém em {@code renew}, o que permite a quem
     * deriva estruturas do acervo (ex.: âncoras PKIX) memoizá-las por geração sem copiar o índice
     * a cada consulta.
     *
     * @return o índice vigente, ou mapa vazio se não há acervo vigente
     */
    public Map<String, X509Certificate> currentIndex() {
        Snapshot atual = vigente();
        return atual == null ? Map.of() : atual.index();
    }

    /**
     * Retorna os certificados raiz indexados por SKI. O critério é o de
     * {@link CertificateParser#isSelfSignedRoot}: autoemitido, com AKI ausente ou igual ao SKI,
     * e autoassinatura válida ou de algoritmo que a JVM não verifica.
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
            if (CertificateParser.isSelfSignedRoot(entry.getValue())) {
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
        return Optional.of(new State(atual.hash(), atual.confirmedAt(), atual.expiresAt(), valid,
                atual.raizesNaoFixadas()));
    }
}
