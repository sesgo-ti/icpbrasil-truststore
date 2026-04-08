package br.gov.go.saude.fhir.truststore.icpbrasil.http;

import br.gov.go.saude.fhir.truststore.icpbrasil.config.TrustStoreConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

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
    void validateOcspResponseSize_dentroDolimite_naoLancaExcecao() {
        byte[] response = new byte[1024];
        assertDoesNotThrow(() -> policy.validateOcspResponseSize(response, "https://ocsp.example.com"));
    }

    @Test
    void validateOcspResponseSize_acimaDoLimite_lancaExcecao() {
        byte[] response = new byte[(int) (1_048_576L + 1)];
        assertThrows(DownloadPolicyException.class,
                () -> policy.validateOcspResponseSize(response, "https://ocsp.example.com"));
    }

    @Test
    void validateCrlResponseSize_dentroDolimite_naoLancaExcecao() {
        byte[] response = new byte[5_000_000];
        assertDoesNotThrow(() -> policy.validateCrlResponseSize(response, "http://ca.example.com/crl"));
    }

    @Test
    void validateCrlResponseSize_acimaDoLimite_lancaExcecao() {
        byte[] response = new byte[(int) (52_428_800L + 1)];
        assertThrows(DownloadPolicyException.class,
                () -> policy.validateCrlResponseSize(response, "http://ca.example.com/crl"));
    }

    @Test
    void validateAiaResponseSize_dentroDolimite_naoLancaExcecao() {
        byte[] response = new byte[500_000];
        assertDoesNotThrow(() -> policy.validateAiaResponseSize(response, "http://ca.example.com/chain.p7b"));
    }

    @Test
    void validateAiaResponseSize_acimaDoLimite_lancaExcecao() {
        byte[] response = new byte[(int) (10_485_760L + 1)];
        assertThrows(DownloadPolicyException.class,
                () -> policy.validateAiaResponseSize(response, "http://ca.example.com/chain.p7b"));
    }
}
