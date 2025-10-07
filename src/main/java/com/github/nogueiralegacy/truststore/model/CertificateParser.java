package com.github.nogueiralegacy.truststore.model;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.*;
import org.springframework.stereotype.Component;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.HexFormat;
import java.util.Optional;
import java.util.function.Function;

@Slf4j
@Component
public class CertificateParser {
    public static X509Certificate parse(InputStream inputStream) throws CertificateParsingException {
        if (inputStream == null) {
            log.error("Erro ao carregar certificado: InputStream é nulo");
            throw new IllegalArgumentException("InputStream não pode ser nulo");
        }

        try (InputStream is = inputStream) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            Certificate cert = cf.generateCertificate(is);
            if (cert instanceof X509Certificate x509) {
                return x509;
            } else {
                String error = "Erro ao carregar certificado como x509Certificate";
                log.error(error);
                throw new CertificateParsingException(error);
            }

        } catch (CertificateException e) {
            log.error("Erro ao carregar certificado: {}", e.getMessage());
            throw new CertificateParsingException("Erro ao carregar certificado", e);
        } catch (IOException e) {
            log.error("Erro ao fechar InputStream: {}", e.getMessage());
            throw new CertificateParsingException("Erro ao fechar InputStream", e);
        }
    }

    /**
     * Faz o parse de um certificado X.509 a partir de um array de bytes.
     *
     * @param certData Array de bytes contendo os dados do certificado
     * @return Certificado X509 parseado
     * @throws CertificateParsingException Se houver erro no parsing do certificado
     */
    public static X509Certificate parse(byte[] certData) throws CertificateParsingException {
        if (certData == null || certData.length == 0) {
            log.error("Erro ao carregar certificado: dados do certificado são nulos ou vazios");
            throw new IllegalArgumentException("Dados do certificado não podem ser nulos ou vazios");
        }

        try (InputStream inputStream = new ByteArrayInputStream(certData)) {
            return parse(inputStream);
        } catch (IOException e) {
            log.error("Erro ao criar InputStream a partir dos dados do certificado: {}", e.getMessage());
            throw new CertificateParsingException("Erro ao processar dados do certificado", e);
        }
    }

    /**
     * Retorna o Common Name (CN) so subject do certificado.
     */
    public static String getSubjectCommonName(X509Certificate certificate) {
        return getCommonName(certificate, true).orElseThrow(
                () -> {
                    log.error("CN do subject do certificado não encontrado");
                    return new IllegalArgumentException("CN do subject do certificado não encontrado");
                }
        );
    }

    /**
     * Retorna o Common Name (CN) so issuer do certificado.
     */
    public static String getIssuerCommonName(X509Certificate certificate) {
        // Se não é "subject", logo é "issuer"
        return getCommonName(certificate, false).orElseThrow(
                () -> {
                    log.error("CN do issuer do certificado não encontrado");
                    return new IllegalArgumentException("CN do issuer do certificado não encontrado");
                }
        );
    }

    /**
     * Retorna o Organization (O) do subject do certificado.
     */
    public static String getSubjectOrganization(X509Certificate certificate) {
        return getOrganization(certificate, true).orElseThrow(
                () -> {
                    log.error("Organization (O) do subject do certificado não encontrado");
                    return new IllegalArgumentException("Organization (O) do subject do certificado não encontrado");
                }
        );
    }

    /**
     * Retorna o Organization (O) do issuer do certificado.
     */
    public static String getIssuerOrganization(X509Certificate certificate) {
        return getOrganization(certificate, false).orElseThrow(
                () -> {
                    log.error("Organization (O) do issuer do certificado não encontrado");
                    return new IllegalArgumentException("Organization (O) do issuer do certificado não encontrado");
                }
        );
    }

    /**
     * Retorna o valor de um atributo (ex: CN, O) do DN do Subject ou Issuer do certificado.
     */
    private static Optional<String> getDnAttribute(X509Certificate certificate, String attribute, boolean isSubject) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        String dn = isSubject ?
                certificate.getSubjectX500Principal().getName() :
                certificate.getIssuerX500Principal().getName();
        try {
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                if (attribute.equalsIgnoreCase(rdn.getType())) {
                    return Optional.of(rdn.getValue().toString().trim());
                }
            }
        } catch (InvalidNameException e) {
            log.error("Erro ao processar DN {}: {}", dn, e.getMessage(), e);
            throw new RuntimeException("Erro ao extrair atributo '" + attribute + "' do certificado", e);
        }
        return Optional.empty();
    }

    /**
     * Retorna o Common Name (CN) do certificado.
     */
    private static Optional<String> getCommonName(X509Certificate certificate, boolean isSubject) {
        return getDnAttribute(certificate, "CN", isSubject);
    }

    /**
     * Retorna o Organization (O) do certificado. Te
     */
    private static Optional<String> getOrganization(X509Certificate certificate, boolean isSubject) {
        return getDnAttribute(certificate, "O", isSubject);
    }

    /**
     * Retorna os Subject Alternative Names (SAN) do certificado.
     */
    public static GeneralNames getSubjectAlternativeNames(X509Certificate certificate) {
        return X509ExtensionUtils.getExtensionValue(
                        certificate,
                        "2.5.29.17",
                        GeneralNames::getInstance
                )
                .orElseThrow(() -> {
                    log.error("Extensão Subject Alternative Name não encontrada no certificado");
                    return new IllegalArgumentException("Extensão SAN (2.5.29.17) não encontrada no certificado");
                });
    }

    /**
     * Retorna o Certificate Authority Information Access ( 1.3.6.1.5.5.7.1.1 ) do certificado
     *
     */
    public static AccessDescription[] getCertificateAuthorityInformationAccess(X509Certificate certificate) {
        return X509ExtensionUtils.getExtensionValue(
                        certificate,
                        "1.3.6.1.5.5.7.1.1",
                        octets -> {
                            AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(octets);
                            return authorityInformationAccess.getAccessDescriptions();
                        })
                .orElseThrow(() -> {
                    log.error("Extensão CRL Distribution Points (2.5.29.31) não encontrada no certificado");
                    return new IllegalArgumentException("Extensão CRL Distribution Points (2.5.29.31) não encontrada no certificado");
                });
    }

    /**
     * Retorna o CRL Distribution Points ( 2.5.29.31 ) do certificado.
     */
    public static DistributionPoint[] getCrlDistributionPoints(X509Certificate certificate) {
        return X509ExtensionUtils.getExtensionValue(
                        certificate,
                        "2.5.29.31",
                        octets -> {
                            CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(octets);
                            return crlDistPoint.getDistributionPoints();
                        })
                .orElseThrow(() -> {
                    log.error("Extensão CRL Distribution Points (2.5.29.31) não encontrada no certificado");
                    return new IllegalArgumentException("Extensão CRL Distribution Points (2.5.29.31) não encontrada no certificado");
                });
    }

    /**
     * Retorna o Subject Key Identifier (SKI) do certificado em formato hexadecimal.
     */
    public static String getSubjectKeyIdentifier(X509Certificate certificate) {
        return X509ExtensionUtils.getExtensionValue(
                        certificate,
                        "2.5.29.14",
                        octets -> {
                            SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(octets);
                            return ski.getKeyIdentifier(); // byte[]
                        })
                .map(value -> HexFormat.of().formatHex(value)) // converte byte[] -> String hex
                .orElseThrow(() -> {
                    log.error("Extensão SKI não encontrada no certificado");
                    return new IllegalArgumentException("Extensão AKI (2.5.29.14) não encontrada no certificado");
                });
    }

    /**
     * Retorna o Authority Key Identifier (AKI) do certificado em formato hexadecimal.
     */
    public static String getAuthorityKeyIdentifier(X509Certificate certificate) {
        return X509ExtensionUtils.getExtensionValue(
                        certificate,
                        "2.5.29.35",
                        octets -> {
                            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(octets);
                            return aki.getKeyIdentifier(); // byte[]
                        })
                .map(value -> HexFormat.of().formatHex(value)) // converte byte[] -> String hex
                .orElseThrow(() -> {
                    log.error("Extensão AKI não encontrada no certificado");
                    return new IllegalArgumentException("Extensão AKI (2.5.29.35) não encontrada no certificado");
                });
    }


    private static class X509ExtensionUtils {

        private static <T> Optional<T> getExtensionValue(
                X509Certificate certificate,
                String oid,
                Function<byte[], T> parser) {

            byte[] extensionValue = certificate.getExtensionValue(oid);
            if (extensionValue == null) {
                return Optional.empty();
            }

            try {
                ASN1OctetString octetString = ASN1OctetString.getInstance(extensionValue);
                T result = parser.apply(octetString.getOctets());
                return Optional.ofNullable(result);
            } catch (Exception e) {
                return Optional.empty();
            }
        }
    }
}
