package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Aplica regras de segurança a downloads iniciados por URLs extraídas de certificados.
 *
 * <p>Protege contra SSRF bloqueando esquemas não-HTTP(S), hostnames reservados e endereços
 * não públicos, tanto em literais quanto nos endereços resolvidos via DNS. Expõe os limites de
 * tamanho por tipo de artefato, aplicados pelo {@link CertificateHttpTransport} durante o
 * recebimento da resposta.</p>
 */
@Slf4j
public class DownloadPolicy {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    private static final Set<String> BLOCKED_HOSTNAMES =
            Set.of("localhost", "ip6-localhost", "ip6-loopback");

    // Um host só de dígitos e pontos nunca é um nome DNS válido (TLD não pode ser numérico);
    // tratá-lo como literal cobre formas abreviadas como "1234", que a JVM expande para IPv4.
    private static final Pattern IPV4_LITERAL = Pattern.compile("[0-9.]+");

    private final TrustStoreConfig.DownloadPolicyConfig config;

    public DownloadPolicy(TrustStoreConfig trustStoreConfig) {
        this.config = trustStoreConfig.getDownloadPolicy();
    }

    public DownloadPolicy(TrustStoreConfig.DownloadPolicyConfig config) {
        this.config = config;
    }

    /**
     * Valida se a URL pode ser acessada pela política de download.
     * Lança {@link DownloadPolicyException} se a URL for bloqueada.
     */
    public void validateUrl(String rawUrl) {
        URI uri;
        try {
            uri = URI.create(rawUrl);
        } catch (IllegalArgumentException e) {
            throw new DownloadPolicyException("URL inválida: " + rawUrl);
        }

        validateScheme(uri, rawUrl);
        validateHost(uri, rawUrl);
    }

    /**
     * Limite em bytes para respostas OCSP, aplicado durante o recebimento.
     */
    public long getMaxOcspResponseBytes() {
        return config.getMaxOcspResponseBytes();
    }

    /**
     * Limite em bytes para CRLs, aplicado durante o recebimento.
     */
    public long getMaxCrlResponseBytes() {
        return config.getMaxCrlResponseBytes();
    }

    /**
     * Limite em bytes para respostas AIA CA Issuers, aplicado durante o recebimento.
     */
    public long getMaxAiaResponseBytes() {
        return config.getMaxAiaResponseBytes();
    }

    private void validateScheme(URI uri, String rawUrl) {
        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            throw new DownloadPolicyException(
                    "Esquema não permitido '" + scheme + "' em: " + rawUrl
                    + ". Apenas http e https são aceitos.");
        }
    }

    private void validateHost(URI uri, String rawUrl) {
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new DownloadPolicyException("Host ausente na URL: " + rawUrl);
        }

        if (BLOCKED_HOSTNAMES.contains(host.toLowerCase())) {
            throw new DownloadPolicyException("Host reservado bloqueado: " + host);
        }

        if (isIpLiteral(host)) {
            InetAddress address = parseIpLiteral(host, rawUrl);
            if (isNonPublicAddress(address)) {
                throw new DownloadPolicyException(
                        "Endereço IP não público bloqueado: " + host + " em: " + rawUrl);
            }
        } else if (config.isBlockPrivateHostnames()) {
            checkResolvedAddresses(host, rawUrl);
        }

        List<String> allowlist = config.getAllowedDomains();
        if (allowlist != null && !allowlist.isEmpty() && !isAllowed(host, allowlist)) {
            throw new DownloadPolicyException(
                    "Domínio '" + host + "' não está na lista de domínios permitidos");
        }
    }

    private boolean isIpLiteral(String host) {
        return host.startsWith("[") || IPV4_LITERAL.matcher(host).matches();
    }

    private InetAddress parseIpLiteral(String host, String rawUrl) {
        String literal = (host.startsWith("[") && host.endsWith("]"))
                ? host.substring(1, host.length() - 1)
                : host;
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException | SecurityException e) {
            throw new DownloadPolicyException("Endereço IP inválido '" + host + "' em: " + rawUrl);
        }
    }

    /**
     * Falha de resolução bloqueia: sem o endereço não há como garantir que o destino é público.
     */
    private void checkResolvedAddresses(String host, String rawUrl) {
        InetAddress[] addresses;
        try {
            addresses = resolve(host);
        } catch (UnknownHostException | SecurityException e) {
            log.debug("Falha ao resolver '{}' para verificação SSRF: {}", host, e.getMessage());
            throw new DownloadPolicyException(
                    "Host '" + host + "' não pôde ser resolvido; download bloqueado em: " + rawUrl);
        }
        for (InetAddress address : addresses) {
            if (isNonPublicAddress(address)) {
                throw new DownloadPolicyException(
                        "Host '" + host + "' resolve para endereço não público "
                        + address.getHostAddress() + " em: " + rawUrl);
            }
        }
    }

    /**
     * Resolução DNS do host; ponto de substituição em testes, que não devem depender de rede.
     */
    InetAddress[] resolve(String host) throws UnknownHostException {
        return InetAddress.getAllByName(host);
    }

    /**
     * Classifica endereços que nunca devem ser destino de download disparado por certificado:
     * não especificado, loopback, link-local, site-local (RFC 1918 e fec0::/10), multicast,
     * "esta rede" (0.0.0.0/8), CGNAT (100.64.0.0/10), IETF protocol assignments (192.0.0.0/24),
     * benchmarking (198.18.0.0/15) e ULA (fc00::/7). Endereços IPv4 mapeados em IPv6 chegam
     * aqui já convertidos pela JVM em {@code Inet4Address}.
     */
    private static boolean isNonPublicAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] octets = address.getAddress();
        if (octets.length == 4) {
            int first = octets[0] & 0xFF;
            int second = octets[1] & 0xFF;
            return first == 0
                    || (first == 100 && (second & 0xC0) == 64)
                    || (first == 192 && second == 0 && octets[2] == 0)
                    || (first == 198 && (second & 0xFE) == 18);
        }
        return (octets[0] & 0xFE) == 0xFC;
    }

    private boolean isAllowed(String host, List<String> allowedDomains) {
        String lowerHost = host.toLowerCase();
        for (String allowed : allowedDomains) {
            String lowerAllowed = allowed.toLowerCase();
            if (lowerHost.equals(lowerAllowed) || lowerHost.endsWith("." + lowerAllowed)) {
                return true;
            }
        }
        return false;
    }
}
