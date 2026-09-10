package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class DownloadPolicyTest {

    private DownloadPolicy policy;

    @BeforeEach
    void setUp() {
        TrustStoreConfig.DownloadPolicyConfig config = new TrustStoreConfig.DownloadPolicyConfig();
        config.setBlockPrivateHostnames(false); // desativa resolução DNS nos testes unitários
        config.setAllowedDomains(List.of());
        policy = new DownloadPolicy(config);
    }

    // --- validateUrl: esquemas ---

    @ParameterizedTest
    @ValueSource(strings = {
        "http://example.com/crl.crl",
        "https://ocsp.icpbrasil.gov.br/status",
        "http://ca.serpro.gov.br/lcr/sub.crl"
    })
    void validateUrl_esquemasPermitidos_naoLancaExcecao(String url) {
        assertDoesNotThrow(() -> policy.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "file:///etc/passwd",
        "ftp://example.com/crl.crl",
        "ldap://example.com/cn=crl",
        "gopher://example.com/crl"
    })
    void validateUrl_esquemasProibidos_lancaExcecao(String url) {
        assertThrows(DownloadPolicyException.class, () -> policy.validateUrl(url));
    }

    // --- validateUrl: IPs literais privados ---

    @ParameterizedTest
    @ValueSource(strings = {
        "http://127.0.0.1/crl",
        "http://127.1.2.3/crl",
        "http://10.0.0.1/crl",
        "http://10.255.255.255/crl",
        "http://172.16.0.1/crl",
        "http://172.31.255.255/crl",
        "http://192.168.0.1/crl",
        "http://192.168.1.100/crl",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/crl",
        "http://0.0.0.0/crl"
    })
    void validateUrl_ipPrivadoLiteral_lancaExcecao(String url) {
        assertThrows(DownloadPolicyException.class, () -> policy.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://8.8.8.8/crl",
        "http://1.1.1.1/crl",
        "https://200.0.0.1/ocsp"
    })
    void validateUrl_ipPublicoLiteral_naoLancaExcecao(String url) {
        assertDoesNotThrow(() -> policy.validateUrl(url));
    }

    // --- validateUrl: hostnames reservados ---

    @ParameterizedTest
    @ValueSource(strings = {
        "http://localhost/crl",
        "http://LOCALHOST/crl",
        "http://ip6-localhost/crl",
        "http://ip6-loopback/crl"
    })
    void validateUrl_hostnameReservado_lancaExcecao(String url) {
        assertThrows(DownloadPolicyException.class, () -> policy.validateUrl(url));
    }

    // --- validateUrl: allowlist ---

    @Test
    void validateUrl_allowlistAtiva_dominioPermitido_naoLancaExcecao() {
        TrustStoreConfig.DownloadPolicyConfig config = new TrustStoreConfig.DownloadPolicyConfig();
        config.setBlockPrivateHostnames(false);
        config.setAllowedDomains(List.of("icpbrasil.gov.br", "serpro.gov.br"));
        DownloadPolicy policyWithAllowlist = new DownloadPolicy(config);

        assertDoesNotThrow(() -> policyWithAllowlist.validateUrl("https://ocsp.icpbrasil.gov.br/status"));
        assertDoesNotThrow(() -> policyWithAllowlist.validateUrl("http://ca.serpro.gov.br/lcr.crl"));
        assertDoesNotThrow(() -> policyWithAllowlist.validateUrl("https://icpbrasil.gov.br/crl"));
    }

    @Test
    void validateUrl_allowlistAtiva_dominioNaoPermitido_lancaExcecao() {
        TrustStoreConfig.DownloadPolicyConfig config = new TrustStoreConfig.DownloadPolicyConfig();
        config.setBlockPrivateHostnames(false);
        config.setAllowedDomains(List.of("icpbrasil.gov.br"));
        DownloadPolicy policyWithAllowlist = new DownloadPolicy(config);

        assertThrows(DownloadPolicyException.class,
                () -> policyWithAllowlist.validateUrl("https://evil.attacker.com/crl"));
    }

    // --- limites de tamanho ---

    @Test
    void testGetMaxResponseBytes_RefletemConfiguracao() {
        TrustStoreConfig.DownloadPolicyConfig config = new TrustStoreConfig.DownloadPolicyConfig();
        config.setMaxOcspResponseBytes(2_048);
        config.setMaxCrlResponseBytes(4_096);
        config.setMaxAiaResponseBytes(8_192);
        DownloadPolicy configured = new DownloadPolicy(config);

        assertEquals(2_048, configured.getMaxOcspResponseBytes());
        assertEquals(4_096, configured.getMaxCrlResponseBytes());
        assertEquals(8_192, configured.getMaxAiaResponseBytes());
    }

    // --- validateUrl: faixas não públicas além das privadas RFC 1918 ---

    @ParameterizedTest
    @ValueSource(strings = {
        "http://[fd00::1]/crl",
        "http://[fc00::1]/crl",
        "http://[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/crl",
        "http://[::ffff:10.0.0.1]/crl",
        "http://[fe80::1]/crl",
        "http://[::]/crl",
        "http://100.64.0.1/crl",
        "http://100.127.255.255/crl",
        "http://192.0.0.1/crl",
        "http://192.0.0.255/crl",
        "http://198.18.0.1/crl",
        "http://198.19.255.255/crl",
        "http://0.1.2.3/crl",
        "http://1234/crl",
        "http://224.0.0.1/crl"
    })
    void testValidateUrl_FaixaNaoPublicaLiteral_LancaExcecao(String url) {
        assertThrows(DownloadPolicyException.class, () -> policy.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://100.63.255.255/crl",
        "http://100.128.0.1/crl",
        "http://192.0.1.1/crl",
        "http://198.17.255.255/crl",
        "http://198.20.0.1/crl",
        "http://[2606:4700:4700::1111]/crl",
        "http://[fb00::1]/crl",
        "http://[fe00::1]/crl"
    })
    void testValidateUrl_LiteralPublicoAdjacenteAsFaixasBloqueadas_NaoLancaExcecao(String url) {
        assertDoesNotThrow(() -> policy.validateUrl(url));
    }

    @Test
    void testValidateUrl_LiteralNumericoInvalido_LancaExcecao() {
        assertThrows(DownloadPolicyException.class, () -> policy.validateUrl("http://1.2.3.4.5/crl"));
    }

    // --- validateUrl: resolução DNS (block-private-hostnames) ---

    @Test
    void testValidateUrl_FalhaDns_BloqueiaQuandoBlockPrivateHostnamesAtivo() {
        DownloadPolicy resolving = policyResolvingTo(true, null);

        DownloadPolicyException ex = assertThrows(DownloadPolicyException.class,
                () -> resolving.validateUrl("http://ocsp.example.com/status"));

        assertTrue(ex.getMessage().contains("não pôde ser resolvido"), ex.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"fd00::1", "100.64.1.1", "10.0.0.5", "127.0.0.1", "169.254.169.254", "0.0.0.0"})
    @SneakyThrows
    void testValidateUrl_HostResolveParaEnderecoNaoPublico_LancaExcecao(String resolved) {
        DownloadPolicy resolving = policyResolvingTo(true, InetAddress.getByName(resolved));

        assertThrows(DownloadPolicyException.class,
                () -> resolving.validateUrl("http://ocsp.example.com/status"));
    }

    @Test
    @SneakyThrows
    void testValidateUrl_HostResolveParaEnderecoPublico_NaoLancaExcecao() {
        DownloadPolicy resolving = policyResolvingTo(true, InetAddress.getByName("8.8.8.8"));

        assertDoesNotThrow(() -> resolving.validateUrl("http://ocsp.example.com/status"));
    }

    @Test
    void testValidateUrl_BlockPrivateHostnamesDesativado_NaoResolveDns() {
        AtomicBoolean resolved = new AtomicBoolean();
        TrustStoreConfig.DownloadPolicyConfig config = new TrustStoreConfig.DownloadPolicyConfig();
        config.setBlockPrivateHostnames(false);
        DownloadPolicy nonResolving = new DownloadPolicy(config) {
            @Override
            InetAddress[] resolve(String host) throws UnknownHostException {
                resolved.set(true);
                throw new UnknownHostException(host);
            }
        };

        assertDoesNotThrow(() -> nonResolving.validateUrl("http://ocsp.example.com/status"));
        assertFalse(resolved.get());
    }

    /**
     * Política com resolução DNS substituída: devolve o endereço informado ou, se nulo,
     * simula falha de resolução. Evita dependência de rede nos testes.
     */
    private static DownloadPolicy policyResolvingTo(boolean blockPrivateHostnames, InetAddress address) {
        TrustStoreConfig.DownloadPolicyConfig config = new TrustStoreConfig.DownloadPolicyConfig();
        config.setBlockPrivateHostnames(blockPrivateHostnames);
        return new DownloadPolicy(config) {
            @Override
            InetAddress[] resolve(String host) throws UnknownHostException {
                if (address == null) {
                    throw new UnknownHostException(host);
                }
                return new InetAddress[]{address};
            }
        };
    }
}
