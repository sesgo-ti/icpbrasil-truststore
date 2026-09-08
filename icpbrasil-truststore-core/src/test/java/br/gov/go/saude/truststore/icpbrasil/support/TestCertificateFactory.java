package br.gov.go.saude.truststore.icpbrasil.support;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Fábrica de certificados X.509 para testes unitários.
 *
 * <p>Fornece building blocks reutilizáveis para gerar certificados de teste
 * (root CA, leaf, intermediários) sem duplicação entre classes de teste.</p>
 */
public final class TestCertificateFactory {

    private static final JcaX509ExtensionUtils EXT_UTILS = createExtUtils();
    private static final JcaX509CertificateConverter CERT_CONVERTER = new JcaX509CertificateConverter();

    private TestCertificateFactory() {}

    @SneakyThrows
    public static X509Certificate generateRootCert(KeyPair keyPair) {
        X500Name subject = new X500Name("CN=Test Root CA, O=Test, C=BR");
        X509v3CertificateBuilder builder = createBuilder(subject, subject, 1, keyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        addSki(builder, keyPair);
        return sign(builder, keyPair);
    }

    @SneakyThrows
    public static X509Certificate generateLeafCert(KeyPair subjectKeyPair, KeyPair issuerKeyPair,
                                                    X509Certificate issuerCert) {
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=Test Leaf, O=Test, C=BR");
        X509v3CertificateBuilder builder = createBuilder(issuerName, subject, 3, subjectKeyPair);
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        addSki(builder, subjectKeyPair);
        addAki(builder, issuerKeyPair);
        return sign(builder, issuerKeyPair);
    }

    public static X509v3CertificateBuilder createBuilder(X500Name issuer, X500Name subject,
                                                          long serial, KeyPair subjectKeyPair) {
        Instant now = Instant.now();
        return new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(serial),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject, subjectKeyPair.getPublic());
    }

    @SneakyThrows
    public static void addSki(X509v3CertificateBuilder builder, KeyPair keyPair) {
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                EXT_UTILS.createSubjectKeyIdentifier(keyPair.getPublic()));
    }

    @SneakyThrows
    public static void addAki(X509v3CertificateBuilder builder, KeyPair issuerKeyPair) {
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                EXT_UTILS.createAuthorityKeyIdentifier(issuerKeyPair.getPublic()));
    }

    @SneakyThrows
    public static void addAia(X509v3CertificateBuilder builder, String url) {
        AccessDescription ad = new AccessDescription(
                AccessDescription.id_ad_caIssuers,
                new GeneralName(GeneralName.uniformResourceIdentifier, url));
        builder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(ad));
    }

    @SneakyThrows
    public static X509Certificate sign(X509v3CertificateBuilder builder, KeyPair signerKeyPair) {
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(signerKeyPair.getPrivate());
        return CERT_CONVERTER.getCertificate(builder.build(signer));
    }

    @SneakyThrows
    private static JcaX509ExtensionUtils createExtUtils() {
        return new JcaX509ExtensionUtils();
    }
}
