package com.github.nogueiralegacy.truststore.model;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.springframework.stereotype.Component;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.Base64;
import java.util.Optional;

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
            if (cert instanceof X509Certificate x509 ) {
                return x509;
            } else {
                String error = "Erro ao carregar certificado como x509Certificate";
                log.error(error);
                throw new CertificateParsingException(error);
            }

        } catch (CertificateException e){
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
     * Retorna o Common Name (CN) do certificado.
     */
    public static Optional<String> getCommonName(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        String dn = certificate.getSubjectX500Principal().getName();

        try {
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return Optional.of(rdn.getValue().toString().trim());
                }
            }
        } catch (InvalidNameException e) {
            log.error("Erro ao processar DN {}: {}", dn, e.getMessage(), e);
            throw new RuntimeException("Erro ao extrair CN do certificado", e);
        }

        return Optional.empty();
    }


    public static Optional<String> getSimpleExtensionValue(X509Certificate certificate, String oid) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        try {
            byte[] extensionValue = certificate.getExtensionValue(oid);
            if (extensionValue == null) {
                return Optional.empty();
            }

            // Decodifica corretamente o OCTET STRING usando BouncyCastle
            ASN1Primitive asn1 = ASN1Primitive.fromByteArray(extensionValue);
            ASN1OctetString octetString = ASN1OctetString.getInstance(asn1);
            byte[] ski = octetString.getOctets();

            String skiBase64 = Base64.getEncoder().encodeToString(ski);
            return Optional.of(skiBase64);

        } catch (Exception e) {
            log.error("Erro ao extrair Subject Key Identifier do certificado: {}", e.getMessage(), e);
            throw new RuntimeException("Erro ao extrair Subject Key Identifier", e);
        }
    }

    /**
     * Retorna o Subject Key Identifier (SKI) do certificado em Base64.
     */
    public static Optional<String> getSubjectKeyIdentifier(X509Certificate certificate) {
        final String SKI_OID = "2.5.29.14";

        return getSimpleExtensionValue(certificate, SKI_OID);
    }

    /**
     * Retorna o Authority Key Identifier (AKI) do certificado em Base64.
     */
    public static Optional<String> getAuthorityKeyIdentifier(X509Certificate certificate) {
        String AKI_OID = "2.5.29.35";

        return getSimpleExtensionValue(certificate, AKI_OID);
    }
}
