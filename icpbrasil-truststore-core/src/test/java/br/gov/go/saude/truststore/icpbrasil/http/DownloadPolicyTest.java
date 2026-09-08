package br.gov.go.saude.truststore.icpbrasil.http;

import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockStatic;

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
    void testValidateUrl_esquemasPermitidos_naoLancaExcecao(String url) {
        assertDoesNotThrow(() -> policy.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "file:///etc/passwd",
        "ftp://example.com/crl.crl",
        "ldap://example.com/cn=crl",
        "gopher://example.com/crl"
    })
    void testValidateUrl_esquemasProibidos_lancaExcecao(String url) {
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
        "http://0.0.0.0/crl",
        "http://0.1.2.3/crl",
        "http://127.1/crl",
        "http://2130706433/crl",
        "http://100.64.0.1/crl",
        "http://100.127.255.255/crl",
        "http://192.0.0.8/crl",
        "http://192.0.2.1/crl",
        "http://192.88.99.1/crl",
        "http://198.18.0.1/crl",
        "http://198.19.255.255/crl",
        "http://198.51.100.1/crl",
        "http://203.0.113.1/crl",
        "http://224.0.0.1/crl",
        "http://240.0.0.1/crl",
        "http://255.255.255.255/crl",
        "http://[fc00::1]/crl",
        "http://[fd12:3456::1]/crl",
        "http://[fe80::1]/crl",
        "http://[ff02::1]/crl",
        "http://[::ffff:127.0.0.1]/crl",
        "http://[::ffff:100.64.0.1]/crl",
        "http://[64:ff9b::7f00:1]/crl",
        "http://[2001:db8::1]/crl",
        "http://[2001::1]/crl",
        "http://[2002:7f00:1::1]/crl",
        "http://[3fff::1]/crl"
    })
    void testValidateUrl_ipPrivadoLiteral_lancaExcecao(String url) {
        assertThrows(DownloadPolicyException.class, () -> policy.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://8.8.8.8/crl",
        "http://1.1.1.1/crl",
        "https://200.0.0.1/ocsp",
        "http://100.63.255.255/crl",
        "http://100.128.0.1/crl",
        "http://[2606:4700:4700::1111]/crl",
        "http://[2001:4860:4860::8888]/crl"
    })
    void testValidateUrl_ipPublicoLiteral_naoLancaExcecao(String url) {
        assertDoesNotThrow(() -> policy.validateUrl(url));
    }

    // --- validateUrl: hostnames reservados ---

    @ParameterizedTest
    @ValueSource(strings = {
        "http://localhost/crl",
        "http://LOCALHOST/crl",
        "http://ip6-localhost/crl",
        "http://ip6-loopback/crl",
        "http://localhost./crl"
    })
    void testValidateUrl_hostnameReservado_lancaExcecao(String url) {
        assertThrows(DownloadPolicyException.class, () -> policy.validateUrl(url));
    }

    // --- validateUrl: allowlist ---

    @Test
    void testValidateUrl_allowlistAtiva_dominioPermitido_naoLancaExcecao() {
        TrustStoreConfig.DownloadPolicyConfig config = new TrustStoreConfig.DownloadPolicyConfig();
        config.setBlockPrivateHostnames(false);
        config.setAllowedDomains(List.of("icpbrasil.gov.br", "serpro.gov.br"));
        DownloadPolicy policyWithAllowlist = new DownloadPolicy(config);

        assertDoesNotThrow(() -> policyWithAllowlist.validateUrl("https://ocsp.icpbrasil.gov.br/status"));
        assertDoesNotThrow(() -> policyWithAllowlist.validateUrl("http://ca.serpro.gov.br/lcr.crl"));
        assertDoesNotThrow(() -> policyWithAllowlist.validateUrl("https://icpbrasil.gov.br/crl"));
    }

    @Test
    void testValidateUrl_allowlistAtiva_dominioNaoPermitido_lancaExcecao() {
        TrustStoreConfig.DownloadPolicyConfig config = new TrustStoreConfig.DownloadPolicyConfig();
        config.setBlockPrivateHostnames(false);
        config.setAllowedDomains(List.of("icpbrasil.gov.br"));
        DownloadPolicy policyWithAllowlist = new DownloadPolicy(config);

        assertThrows(DownloadPolicyException.class,
                () -> policyWithAllowlist.validateUrl("https://evil.attacker.com/crl"));
    }

    // --- limites de tamanho ---

    @Test
    void testValidateOcspResponseSize_dentroDolimite_naoLancaExcecao() {
        byte[] response = new byte[1024];
        assertDoesNotThrow(() -> policy.validateOcspResponseSize(response, "https://ocsp.example.com"));
    }

    @Test
    void testValidateOcspResponseSize_acimaDoLimite_lancaExcecao() {
        byte[] response = new byte[(int) (1_048_576L + 1)];
        assertThrows(DownloadPolicyException.class,
                () -> policy.validateOcspResponseSize(response, "https://ocsp.example.com"));
    }

    @Test
    void testValidateCrlResponseSize_dentroDolimite_naoLancaExcecao() {
        byte[] response = new byte[5_000_000];
        assertDoesNotThrow(() -> policy.validateCrlResponseSize(response, "http://ca.example.com/crl"));
    }

    @Test
    void testValidateCrlResponseSize_acimaDoLimite_lancaExcecao() {
        byte[] response = new byte[(int) (52_428_800L + 1)];
        assertThrows(DownloadPolicyException.class,
                () -> policy.validateCrlResponseSize(response, "http://ca.example.com/crl"));
    }

    @Test
    void testValidateAiaResponseSize_dentroDolimite_naoLancaExcecao() {
        byte[] response = new byte[500_000];
        assertDoesNotThrow(() -> policy.validateAiaResponseSize(response, "http://ca.example.com/chain.p7b"));
    }

    @Test
    void testValidateAiaResponseSize_acimaDoLimite_lancaExcecao() {
        byte[] response = new byte[(int) (10_485_760L + 1)];
        assertThrows(DownloadPolicyException.class,
                () -> policy.validateAiaResponseSize(response, "http://ca.example.com/chain.p7b"));
    }

    @Test
    @SneakyThrows
    void testValidateUrl_falhaDnsBloqueadaPorPadrao() {
        DownloadPolicy defaultPolicy = new DownloadPolicy(new TrustStoreConfig.DownloadPolicyConfig());
        try (MockedStatic<InetAddress> dns = mockStatic(InetAddress.class)) {
            dns.when(() -> InetAddress.getAllByName("ca.example.test"))
                    .thenThrow(new UnknownHostException("DNS indisponivel"));
            assertThrows(DownloadPolicyException.class,
                    () -> defaultPolicy.validateUrl("http://ca.example.test/crl"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.0.0.1", "100.64.0.1", "fc00::1", "224.0.0.1", "198.18.0.1"})
    @SneakyThrows
    void testValidateUrl_dnsMistoComEnderecoNaoPublicoBloqueado(String address) {
        DownloadPolicy defaultPolicy = new DownloadPolicy(new TrustStoreConfig.DownloadPolicyConfig());
        InetAddress publicAddress = InetAddress.getByName("8.8.8.8");
        InetAddress blockedAddress = InetAddress.getByName(address);
        try (MockedStatic<InetAddress> dns = mockStatic(InetAddress.class)) {
            dns.when(() -> InetAddress.getAllByName("ca.example.test"))
                    .thenReturn(new InetAddress[]{publicAddress, blockedAddress});
            assertThrows(DownloadPolicyException.class,
                    () -> defaultPolicy.validateUrl("http://ca.example.test/crl"));
        }
    }

    @Test
    @SneakyThrows
    void testValidateUrl_dnsPublicoPermitido() {
        DownloadPolicy defaultPolicy = new DownloadPolicy(new TrustStoreConfig.DownloadPolicyConfig());
        InetAddress address = InetAddress.getByName("8.8.8.8");
        try (MockedStatic<InetAddress> dns = mockStatic(InetAddress.class)) {
            dns.when(() -> InetAddress.getAllByName("ca.example.test"))
                    .thenReturn(new InetAddress[]{address});
            assertDoesNotThrow(() -> defaultPolicy.validateUrl("http://ca.example.test/crl"));
        }
    }
}
