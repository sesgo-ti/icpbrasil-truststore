package br.gov.go.saude.truststore.icpbrasil.support;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
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

    /** CPF fictício usado nos certificados de teste. */
    public static final String CPF_TESTE = "00000000191";
    /** Data de nascimento fictícia (ddMMyyyy) usada nos certificados de teste. */
    public static final String NASCIMENTO_TESTE = "01011990";
    /** CN do titular fictício no padrão ICP-Brasil ("NOME:CPF"). */
    public static final String CN_TITULAR_TESTE = "USUARIO DE TESTE:" + CPF_TESTE;
    /** CN da AC fictícia emissora. */
    public static final String CN_AC_TESTE = "AC Teste ICP-Brasil";

    /**
     * Gera uma AC fictícia com os atributos de nome no padrão ICP-Brasil
     * (O=ICP-Brasil, C=BR), para emitir certificados de pessoa física de teste.
     */
    @SneakyThrows
    public static X509Certificate generateIcpBrasilTestCa(KeyPair keyPair) {
        X500Name subject = new X500Name("CN=" + CN_AC_TESTE + ", OU=Teste, O=ICP-Brasil, C=BR");
        X509v3CertificateBuilder builder = createBuilder(subject, subject, 10, keyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        addSki(builder, keyPair);
        return sign(builder, keyPair);
    }

    /**
     * Gera um certificado de pessoa física (e-CPF) sintético, reproduzindo a
     * estrutura definida pela Resolução CG ICP-Brasil nº 211/2024:
     * CN no formato {@code NOME:CPF}, SAN com 4 entradas (incluindo o otherName
     * {@code 2.16.76.1.3.1} com data de nascimento + CPF fictícios), 2 pontos de distribuição
     * de CRL, 1 entrada AIA (caIssuers, sem OCSP), política {@code 2.16.76.1.*} e
     * keyUsage digitalSignature + nonRepudiation.
     */
    @SneakyThrows
    public static X509Certificate generateIcpBrasilPersonCert(KeyPair subjectKeyPair,
                                                              KeyPair issuerKeyPair,
                                                              X509Certificate issuerCert) {
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + CN_TITULAR_TESTE + ", OU=Teste, O=ICP-Brasil, C=BR");
        X509v3CertificateBuilder builder = createBuilder(issuerName, subject, 11, subjectKeyPair);

        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        addSki(builder, subjectKeyPair);
        addAki(builder, issuerKeyPair);

        // keyUsage: digitalSignature + nonRepudiation (como nos e-CPF reais)
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

        // SAN com 4 entradas, como nos certificados ICP-Brasil de pessoa física:
        // e-mail + otherName 2.16.76.1.3.1 (nascimento+CPF+...) + 2.16.76.1.3.5 + 2.16.76.1.3.6
        String dadosPf = NASCIMENTO_TESTE + CPF_TESTE + "0".repeat(11) + "0".repeat(15);
        GeneralName[] sanEntries = {
                new GeneralName(GeneralName.rfc822Name, "usuario.teste@example.com"),
                icpOtherName("2.16.76.1.3.1", dadosPf),
                icpOtherName("2.16.76.1.3.5", "0".repeat(12)),
                icpOtherName("2.16.76.1.3.6", "0".repeat(12)),
        };
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sanEntries));

        // 2 pontos de distribuição de CRL (URLs fictícias)
        DistributionPoint[] dps = {
                crlDistributionPoint("http://crl.teste.example/ac-teste-1.crl"),
                crlDistributionPoint("http://crl2.teste.example/ac-teste-2.crl"),
        };
        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(dps));

        // AIA com uma única entrada caIssuers (certificados Soluti não têm OCSP na AIA)
        addAia(builder, "http://cert.teste.example/ac-teste.p7b");

        // Política de certificado no ramo ICP-Brasil (2.16.76.1.*)
        builder.addExtension(Extension.certificatePolicies, false,
                new CertificatePolicies(new PolicyInformation(
                        new ASN1ObjectIdentifier("2.16.76.1.2.1.133"))));

        return sign(builder, issuerKeyPair);
    }

    /**
     * Monta um otherName no formato usado pela ICP-Brasil: sequência com o OID e o
     * valor como PrintableString em tag explícita — a mesma estrutura que o
     * {@code IcpBrasilCertificateParser} espera ao extrair CPF/nascimento.
     */
    private static GeneralName icpOtherName(String oid, String valor) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1ObjectIdentifier(oid));
        vector.add(new DERTaggedObject(true, 0, new DERPrintableString(valor)));
        return new GeneralName(GeneralName.otherName, new DERSequence(vector));
    }

    private static DistributionPoint crlDistributionPoint(String url) {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, url);
        DistributionPointName dpn = new DistributionPointName(new GeneralNames(gn));
        return new DistributionPoint(dpn, null, null);
    }

    @SneakyThrows
    private static JcaX509ExtensionUtils createExtUtils() {
        return new JcaX509ExtensionUtils();
    }
}
