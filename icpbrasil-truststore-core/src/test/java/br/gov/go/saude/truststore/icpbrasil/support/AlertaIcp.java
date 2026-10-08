package br.gov.go.saude.truststore.icpbrasil.support;

import br.gov.go.saude.truststore.icpbrasil.model.CertificateParser;
import br.gov.go.saude.truststore.icpbrasil.model.RaizDescartada;
import lombok.SneakyThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Grava {@code target/alerta-icp.md} quando o acervo real do ITI diverge da lista de raízes
 * fixadas. O arquivo é o corpo da issue aberta pelo pipeline; só existe se houve divergência.
 *
 * <p>Deve ser chamado antes da asserção que falha, senão o relatório se perde.
 */
public final class AlertaIcp {

    static final Path ARQUIVO = Path.of("target", "alerta-icp.md");

    private static final String ACAO = """
            Ação esperada: confirmar no DOU/ITI se houve mudança oficial na hierarquia da ICP-Brasil. \
            Se houve, atualizar as raízes fixadas e publicar nova versão; se não, investigar a \
            origem do certificado divergente (acervo adulterado ou falha do ITI).
            """;

    private AlertaIcp() {}

    /** Remove o relatório de uma execução anterior, para que o arquivo reflita só a execução atual. */
    @SneakyThrows
    public static void limpar() {
        Files.deleteIfExists(ARQUIVO);
    }

    /** Registra raízes que {@code RaizesFixadas} descartou do acervo. */
    public static void registrarRaizesDescartadas(List<RaizDescartada> descartadas) {
        List<Divergencia> itens = descartadas.stream()
                .map(d -> new Divergencia(d.subject(), d.fingerprintSha256()))
                .toList();
        registrar("Raízes do acervo fora da lista fixada", itens);
    }

    /** Registra certificados do acervo que o filtro ou o critério de raiz não reconhece como esperado. */
    public static void registrarCertificados(String titulo, List<X509Certificate> certificados) {
        List<Divergencia> itens = certificados.stream()
                .map(c -> new Divergencia(c.getSubjectX500Principal().getName(),
                        CertificateParser.getFingerprintSha256(c)))
                .toList();
        registrar(titulo, itens);
    }

    @SneakyThrows
    private static void registrar(String titulo, List<Divergencia> itens) {
        if (itens.isEmpty()) {
            return;
        }
        StringBuilder md = new StringBuilder();
        if (!Files.exists(ARQUIVO)) {
            md.append("# Divergência no acervo ICP-Brasil\n\n").append(ACAO).append('\n');
        }
        md.append("## ").append(titulo).append("\n\n");
        for (Divergencia item : itens) {
            md.append("- subject: `").append(item.subject()).append("`\n")
                    .append("  - fingerprint SHA-256: `").append(item.fingerprintSha256()).append("`\n");
        }
        md.append('\n');
        Files.createDirectories(ARQUIVO.getParent());
        Files.writeString(ARQUIVO, md, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    private record Divergencia(String subject, String fingerprintSha256) {}
}
