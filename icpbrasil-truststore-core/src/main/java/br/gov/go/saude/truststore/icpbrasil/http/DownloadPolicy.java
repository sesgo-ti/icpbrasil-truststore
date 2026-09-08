package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Aplica regras de segurança a downloads iniciados por URLs extraídas de certificados.
 *
 * <p>Protege contra SSRF bloqueando esquemas não-HTTP(S), IPs privados e hostnames
 * reservados. Aplica limites de tamanho de resposta por tipo de artefato.</p>
 *
 * <p>A resolução DNS falha fechada por padrão, mas não fixa o IP da conexão HTTP.
 * DNS rebinding exige proteção adicional de egress na rede de execução.</p>
 */
public class DownloadPolicy {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    private static final Set<String> BLOCKED_HOSTNAMES =
            Set.of("localhost", "ip6-localhost", "ip6-loopback");

    private final TrustStoreConfig.DownloadPolicyConfig config;

    /** Cria a política a partir das configurações do acervo. */
    public DownloadPolicy(TrustStoreConfig trustStoreConfig) {
        this.config = trustStoreConfig.getDownloadPolicy();
    }

    /** Cria a política com limites e restrições explícitos. */
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
     * Valida o tamanho da resposta OCSP.
     */
    public void validateOcspResponseSize(byte[] response, String url) {
        validateSize(response, url, config.getMaxOcspResponseBytes(), "OCSP");
    }

    /**
     * Valida o tamanho da resposta CRL.
     */
    public void validateCrlResponseSize(byte[] response, String url) {
        validateSize(response, url, config.getMaxCrlResponseBytes(), "CRL");
    }

    /**
     * Valida o tamanho da resposta AIA CA Issuers.
     */
    public void validateAiaResponseSize(byte[] response, String url) {
        validateSize(response, url, config.getMaxAiaResponseBytes(), "AIA");
    }

    /** @return limite de bytes aplicado durante o recebimento OCSP */
    public long getMaxOcspResponseBytes() {
        return config.getMaxOcspResponseBytes();
    }

    /** @return limite de bytes aplicado durante o recebimento CRL */
    public long getMaxCrlResponseBytes() {
        return config.getMaxCrlResponseBytes();
    }

    /** @return limite de bytes aplicado durante o recebimento AIA */
    public long getMaxAiaResponseBytes() {
        return config.getMaxAiaResponseBytes();
    }

    private void validateScheme(URI uri, String rawUrl) {
        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
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

        if (uri.getRawUserInfo() != null || host.contains("%")) {
            throw new DownloadPolicyException("Credenciais ou escopo IPv6 não permitidos na URL: " + rawUrl);
        }
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (BLOCKED_HOSTNAMES.contains(host.toLowerCase(Locale.ROOT))) {
            throw new DownloadPolicyException("Host reservado bloqueado: " + host);
        }

        if (isPrivateIpLiteral(host)) {
            throw new DownloadPolicyException(
                    "Endereço IP privado ou de loopback bloqueado: " + host + " em: " + rawUrl);
        }

        if (config.isBlockPrivateHostnames()) {
            checkResolvedAddress(host, rawUrl);
        }

        List<String> allowlist = config.getAllowedDomains();
        if (allowlist != null && !allowlist.isEmpty() && !isAllowed(host, allowlist)) {
            throw new DownloadPolicyException(
                    "Domínio '" + host + "' não está na lista de domínios permitidos");
        }
    }

    private void validateSize(byte[] response, String url, long maxBytes, String type) {
        if (response.length > maxBytes) {
            throw new DownloadPolicyException(
                    "Resposta " + type + " muito grande: " + response.length
                    + " bytes de " + url + " (máximo: " + maxBytes + " bytes)");
        }
    }

    private boolean isPrivateIpLiteral(String host) {
        String cleanHost = (host.startsWith("[") && host.endsWith("]"))
                ? host.substring(1, host.length() - 1)
                : host;

        if (!looksLikeIpLiteral(cleanHost)) {
            return false;
        }

        try {
            InetAddress addr = InetAddress.getByName(cleanHost);
            return isNonPublicAddress(addr);
        } catch (UnknownHostException e) {
            throw new DownloadPolicyException("Endereço IP inválido: " + host);
        }
    }

    private boolean looksLikeIpLiteral(String host) {
        return host.matches("[0-9.]+") || host.contains(":");
    }

    private boolean isNonPublicAddress(InetAddress addr) {
        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()
                || addr.isAnyLocalAddress() || addr.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = addr.getAddress();
        int first = bytes[0] & 0xff;
        int second = bytes[1] & 0xff;
        int third = bytes[2] & 0xff;
        if (bytes.length == 4) {
            return first == 0 || first >= 240
                    || (first == 100 && (second & 0xc0) == 64) // CGNAT: 100.64.0.0/10.
                    || (first == 192 && second == 0 && (third == 0 || third == 2))
                    || (first == 192 && second == 88 && third == 99)
                    || (first == 198 && (second == 18 || second == 19))
                    || (first == 198 && second == 51 && third == 100)
                    || (first == 203 && second == 0 && third == 113);
        }
        // Apenas unicast global 2000::/3; exclui ULA, NAT64 e formatos de transição.
        return (first & 0xe0) != 0x20
                || (first == 0x20 && second == 0x01 && third < 2)
                || (first == 0x20 && second == 0x01 && third == 0x0d && (bytes[3] & 0xff) == 0xb8)
                || (first == 0x20 && second == 0x02) // 6to4 pode encapsular um IPv4 privado.
                || (first == 0x3f && second == 0xff && (third & 0xf0) == 0);
    }

    private void checkResolvedAddress(String host, String url) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (isNonPublicAddress(addr)) {
                    throw new DownloadPolicyException(
                            "Host '" + host + "' resolve para endereço não público "
                            + addr.getHostAddress() + " em: " + url);
                }
            }
        } catch (UnknownHostException e) {
            throw new DownloadPolicyException("Não foi possível resolver hostname para verificação SSRF: " + host);
        }
    }

    private boolean isAllowed(String host, List<String> allowedDomains) {
        String lowerHost = host.toLowerCase(Locale.ROOT);
        for (String allowed : allowedDomains) {
            String lowerAllowed = allowed.toLowerCase(Locale.ROOT);
            if (lowerHost.equals(lowerAllowed) || lowerHost.endsWith("." + lowerAllowed)) {
                return true;
            }
        }
        return false;
    }
}
