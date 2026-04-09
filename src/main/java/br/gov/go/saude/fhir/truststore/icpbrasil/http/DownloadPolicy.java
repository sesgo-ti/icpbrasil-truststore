package br.gov.go.saude.fhir.truststore.icpbrasil.http;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.Set;

/**
 * Aplica regras de segurança a downloads iniciados por URLs extraídas de certificados.
 *
 * <p>Protege contra SSRF bloqueando esquemas não-HTTP(S), IPs privados e hostnames
 * reservados. Aplica limites de tamanho de resposta por tipo de artefato.</p>
 */
@Slf4j
@Component
public class DownloadPolicy {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    private static final Set<String> BLOCKED_HOSTNAMES =
            Set.of("localhost", "ip6-localhost", "ip6-loopback");

    private final TrustStoreConfig.DownloadPolicyConfig config;

    @Autowired
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
            return addr.isLoopbackAddress()
                    || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress()
                    || addr.isAnyLocalAddress()
                    || addr.isMulticastAddress();
        } catch (Exception e) {
            return false;
        }
    }

    private boolean looksLikeIpLiteral(String host) {
        return host.matches("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+") || host.contains(":");
    }

    private void checkResolvedAddress(String host, String url) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
                        || addr.isLinkLocalAddress() || addr.isAnyLocalAddress()) {
                    throw new DownloadPolicyException(
                            "Host '" + host + "' resolve para endereço privado "
                            + addr.getHostAddress() + " em: " + url);
                }
            }
        } catch (DownloadPolicyException e) {
            throw e;
        } catch (Exception e) {
            log.debug("Não foi possível resolver hostname '{}' para verificação SSRF: {}",
                    host, e.getMessage());
        }
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
