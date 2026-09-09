package br.gov.go.saude.truststore.icpbrasil.support;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Monta bundles ZIP sintéticos no formato do acervo do ITI (um certificado DER por entrada
 * {@code .crt}) e ACs raiz para populá-los. Versão mínima da fábrica homônima dos testes do
 * core, que não é visível para este módulo.
 */
public final class TestBundleFactory {

    private static final KeyPairGenerator KPG = createKpg();
    private static final JcaX509ExtensionUtils EXT_UTILS = createExtUtils();
    private static long serial = 1000;

    private TestBundleFactory() {}

    public static KeyPair newKeyPair() {
        return KPG.generateKeyPair();
    }

    /** AC raiz autoassinada com CN próprio, basicConstraints CA e SKI. */
    @SneakyThrows
    public static X509Certificate caCert(String cn, KeyPair keyPair) {
        X500Name subject = new X500Name("CN=" + cn + ", O=Test, C=BR");
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(++serial),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                EXT_UTILS.createSubjectKeyIdentifier(keyPair.getPublic()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    /** Bundle com os certificados em DER, nomeados {@code ac-N.crt}. */
    @SneakyThrows
    public static byte[] bundleOf(X509Certificate... certificates) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (int i = 0; i < certificates.length; i++) {
                zip.putNextEntry(new ZipEntry("ac-" + i + ".crt"));
                zip.write(certificates[i].getEncoded());
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

    @SneakyThrows
    private static JcaX509ExtensionUtils createExtUtils() {
        return new JcaX509ExtensionUtils();
    }
}
