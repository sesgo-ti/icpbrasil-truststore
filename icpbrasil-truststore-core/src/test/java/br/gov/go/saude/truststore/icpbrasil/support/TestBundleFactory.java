package br.gov.go.saude.truststore.icpbrasil.support;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Monta bundles ZIP sintéticos no formato do acervo do ITI (um certificado DER por entrada
 * {@code .crt}) e certificados de AC para popular esses bundles.
 */
public final class TestBundleFactory {

    private static final KeyPairGenerator KPG = createKpg();
    private static long serial = 1000;

    private TestBundleFactory() {}

    public static KeyPair newKeyPair() {
        return KPG.generateKeyPair();
    }

    /** AC raiz autoassinada com CN próprio, basicConstraints CA e SKI. */
    @SneakyThrows
    public static X509Certificate caCert(String cn, KeyPair keyPair) {
        X500Name subject = new X500Name("CN=" + cn + ", O=Test, C=BR");
        X509v3CertificateBuilder builder = TestCertificateFactory.createBuilder(subject, subject, ++serial, keyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        TestCertificateFactory.addSki(builder, keyPair);
        return TestCertificateFactory.sign(builder, keyPair);
    }

    /** AC intermediária emitida por {@code issuer}, com basicConstraints CA, SKI e AKI. */
    @SneakyThrows
    public static X509Certificate intermediateCaCert(String cn, KeyPair keyPair,
                                                     X509Certificate issuer, KeyPair issuerKeyPair) {
        X500Name issuerName = X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
        X500Name subject = new X500Name("CN=" + cn + ", O=Test, C=BR");
        X509v3CertificateBuilder builder = TestCertificateFactory.createBuilder(issuerName, subject, ++serial, keyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        TestCertificateFactory.addSki(builder, keyPair);
        TestCertificateFactory.addAki(builder, issuerKeyPair);
        return TestCertificateFactory.sign(builder, issuerKeyPair);
    }

    /** AC autoassinada sem a extensão SKI. */
    @SneakyThrows
    public static X509Certificate caCertWithoutSki(String cn, KeyPair keyPair) {
        X500Name subject = new X500Name("CN=" + cn + ", O=Test, C=BR");
        X509v3CertificateBuilder builder = TestCertificateFactory.createBuilder(subject, subject, ++serial, keyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return TestCertificateFactory.sign(builder, keyPair);
    }

    /** Bundle com os certificados em DER, nomeados {@code ac-N.crt}. */
    @SneakyThrows
    public static byte[] bundleOf(X509Certificate... certificates) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        for (int i = 0; i < certificates.length; i++) {
            entries.put("ac-" + i + ".crt", certificates[i].getEncoded());
        }
        return zipOf(entries);
    }

    @SneakyThrows
    public static byte[] zipOf(Map<String, byte[]> entries) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }

    @SneakyThrows
    private static KeyPairGenerator createKpg() {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg;
    }
}
