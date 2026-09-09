package br.gov.go.saude.truststore.icpbrasil.support;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static br.gov.go.saude.truststore.icpbrasil.support.TestCertificateFactory.*;

/**
 * Hierarquia sintética de três níveis (raiz → intermediária → folha), com os endpoints de
 * revogação de cada nível embutidos nos certificados e atalhos para produzir as evidências
 * (CRLs e respostas OCSP) que esses endpoints publicariam.
 */
public record TestChain(KeyPair rootKeyPair, X509Certificate root,
                        KeyPair intermediateKeyPair, X509Certificate intermediate,
                        KeyPair leafKeyPair, X509Certificate leaf) {

    /** URLs de revogação a embutir em um certificado; {@code null} omite a extensão correspondente. */
    public record Endpoints(String crlUrl, String ocspUrl) {
        public static Endpoints none() {
            return new Endpoints(null, null);
        }
    }

    public static final String ROOT_CRL_URL = "http://crl.root.example/root.crl";
    public static final String ROOT_OCSP_URL = "http://ocsp.root.example/";
    public static final String INTERMEDIATE_CRL_URL = "http://crl.intermediate.example/intermediate.crl";
    public static final String INTERMEDIATE_OCSP_URL = "http://ocsp.intermediate.example/";

    private static final AtomicLong SERIALS = new AtomicLong(5000);
    private static final KeyPairGenerator KPG = createKpg();

    /** Intermediária (emitida pela raiz) e folha publicam CRL e OCSP nas URLs padrão. */
    public static TestChain create() {
        return create(new Endpoints(ROOT_CRL_URL, ROOT_OCSP_URL),
                new Endpoints(INTERMEDIATE_CRL_URL, INTERMEDIATE_OCSP_URL));
    }

    /**
     * @param intermediateEndpoints URLs publicadas no certificado da intermediária (servidas pela raiz)
     * @param leafEndpoints         URLs publicadas no certificado da folha (servidas pela intermediária)
     */
    public static TestChain create(Endpoints intermediateEndpoints, Endpoints leafEndpoints) {
        return create(intermediateEndpoints, leafEndpoints,
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(365)));
    }

    /** Variante com período de validade explícito para a folha. */
    public static TestChain create(Endpoints intermediateEndpoints, Endpoints leafEndpoints,
                                   Instant leafNotBefore, Instant leafNotAfter) {
        KeyPair rootKeyPair = KPG.generateKeyPair();
        KeyPair intermediateKeyPair = KPG.generateKeyPair();
        KeyPair leafKeyPair = KPG.generateKeyPair();
        X509Certificate root = generateRootCert(rootKeyPair);
        X509Certificate intermediate = intermediateCert(intermediateKeyPair, rootKeyPair, root, intermediateEndpoints);
        X509Certificate leaf = leafCert(leafKeyPair, intermediateKeyPair, intermediate, leafEndpoints,
                leafNotBefore, leafNotAfter);
        return new TestChain(rootKeyPair, root, intermediateKeyPair, intermediate, leafKeyPair, leaf);
    }

    /** Raiz e intermediária, como constariam no acervo. */
    public List<X509Certificate> authorities() {
        return List.of(root, intermediate);
    }

    /** Outra folha emitida pela mesma intermediária, com as extensões informadas. */
    @SneakyThrows
    public X509Certificate anotherLeaf(Endpoints endpoints, Extension... extra) {
        X509v3CertificateBuilder builder = leafBuilder(KPG.generateKeyPair(), intermediateKeyPair, intermediate,
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(365)));
        addEndpoints(builder, endpoints);
        for (Extension extension : extra) {
            builder.addExtension(extension);
        }
        return sign(builder, intermediateKeyPair);
    }

    /** CRL da raiz (cobre a intermediária), vigente em {@code now}, em DER. */
    public byte[] rootCrl(Instant now, Map<BigInteger, Instant> revoked) {
        return crl(rootKeyPair, root, now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(1)), revoked);
    }

    /** CRL da intermediária (cobre a folha), vigente em {@code now}, em DER. */
    public byte[] intermediateCrl(Instant now, Map<BigInteger, Instant> revoked) {
        return intermediateCrl(now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(1)), revoked);
    }

    public byte[] intermediateCrl(Instant thisUpdate, Instant nextUpdate, Map<BigInteger, Instant> revoked) {
        return crl(intermediateKeyPair, intermediate, thisUpdate, nextUpdate, revoked);
    }

    /** Resposta OCSP da raiz sobre a intermediária, vigente em {@code now}. */
    public byte[] rootOcsp(Instant now, CertificateStatus status) {
        return ocsp(intermediate, root, rootKeyPair, root, status,
                now.minus(Duration.ofMinutes(1)), now.plus(Duration.ofHours(1)));
    }

    /** Resposta OCSP da intermediária sobre a folha, vigente em {@code now}. */
    public byte[] intermediateOcsp(Instant now, CertificateStatus status) {
        return intermediateOcsp(status, now.minus(Duration.ofMinutes(1)), now.plus(Duration.ofHours(1)));
    }

    public byte[] intermediateOcsp(CertificateStatus status, Instant thisUpdate, Instant nextUpdate) {
        return ocsp(leaf, intermediate, intermediateKeyPair, intermediate, status, thisUpdate, nextUpdate);
    }

    // --- Geradores ---

    /** AC intermediária (CA, pathLen ilimitado) com keyUsage keyCertSign|cRLSign, SKI/AKI e endpoints. */
    @SneakyThrows
    private static X509Certificate intermediateCert(KeyPair subjectKeyPair, KeyPair issuerKeyPair,
                                                    X509Certificate issuerCert, Endpoints endpoints) {
        X509v3CertificateBuilder builder = createBuilder(issuerNameOf(issuerCert),
                new X500Name("CN=Test Intermediate CA, O=Test, C=BR"), SERIALS.incrementAndGet(), subjectKeyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        addSki(builder, subjectKeyPair);
        addAki(builder, issuerKeyPair);
        addEndpoints(builder, endpoints);
        return sign(builder, issuerKeyPair);
    }

    @SneakyThrows
    private static X509Certificate leafCert(KeyPair subjectKeyPair, KeyPair issuerKeyPair, X509Certificate issuerCert,
                                            Endpoints endpoints, Instant notBefore, Instant notAfter) {
        X509v3CertificateBuilder builder = leafBuilder(subjectKeyPair, issuerKeyPair, issuerCert, notBefore, notAfter);
        addEndpoints(builder, endpoints);
        return sign(builder, issuerKeyPair);
    }

    @SneakyThrows
    private static X509v3CertificateBuilder leafBuilder(KeyPair subjectKeyPair, KeyPair issuerKeyPair,
                                                        X509Certificate issuerCert, Instant notBefore, Instant notAfter) {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerNameOf(issuerCert),
                BigInteger.valueOf(SERIALS.incrementAndGet()), Date.from(notBefore), Date.from(notAfter),
                new X500Name("CN=Test Leaf, O=Test, C=BR"), subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        addSki(builder, subjectKeyPair);
        addAki(builder, issuerKeyPair);
        return builder;
    }

    @SneakyThrows
    private static void addEndpoints(X509v3CertificateBuilder builder, Endpoints endpoints) {
        if (endpoints.crlUrl() != null) {
            builder.addExtension(Extension.cRLDistributionPoints, false,
                    new CRLDistPoint(new DistributionPoint[]{crlDistributionPoint(endpoints.crlUrl())}));
        }
        if (endpoints.ocspUrl() != null) {
            builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                    new AccessDescription(AccessDescription.id_ad_ocsp,
                            new GeneralName(GeneralName.uniformResourceIdentifier, endpoints.ocspUrl()))));
        }
    }

    /** CRL completa e direta assinada pelo emissor, com AKI e CRL Number; motivo keyCompromise. */
    @SneakyThrows
    private static byte[] crl(KeyPair issuerKeyPair, X509Certificate issuerCert,
                              Instant thisUpdate, Instant nextUpdate, Map<BigInteger, Instant> revoked) {
        X509v2CRLBuilder builder = new JcaX509v2CRLBuilder(issuerCert.getSubjectX500Principal(), Date.from(thisUpdate));
        builder.setNextUpdate(Date.from(nextUpdate));
        revoked.forEach((serial, at) -> builder.addCRLEntry(serial, Date.from(at), CRLReason.keyCompromise));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerKeyPair.getPublic()));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        return builder.build(signer(issuerKeyPair)).getEncoded();
    }

    /**
     * Resposta OCSP {@code successful} com um único SingleResponse para o alvo, assinada por
     * {@code signerKeyPair} (ResponderID byKey) e carregando o certificado do assinante.
     */
    @SneakyThrows
    private static byte[] ocsp(X509Certificate target, X509Certificate issuer, KeyPair signerKeyPair,
                               X509Certificate signerCert, CertificateStatus status,
                               Instant thisUpdate, Instant nextUpdate) {
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID certId = new CertificateID(digests.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuer), target.getSerialNumber());
        BasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(signerCert.getPublicKey(),
                digests.get(CertificateID.HASH_SHA1));
        builder.addResponse(certId, status, Date.from(thisUpdate),
                nextUpdate == null ? null : Date.from(nextUpdate), null);
        BasicOCSPResp basic = builder.build(signer(signerKeyPair),
                new X509CertificateHolder[]{new JcaX509CertificateHolder(signerCert)}, Date.from(thisUpdate));
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    @SneakyThrows
    private static ContentSigner signer(KeyPair keyPair) {
        return new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
    }

    @SneakyThrows
    private static KeyPairGenerator createKpg() {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg;
    }
}
