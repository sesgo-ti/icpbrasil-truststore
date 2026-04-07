package br.gov.go.saude.fhir.truststore.icpbrasil.model;

import br.gov.go.saude.fhir.truststore.icpbrasil.model.CertificateParser;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class IcpBrasilCertificateParser {

    /**
     * Seguindo o formato descrito no documento:
     * @see <a href="https://www.in.gov.br/en/web/dou/-/resolucao-cg-icp-brasil-n-211-de-31-de-outubro-de-2024-593690315">
     *      Resolução CG ICP-Brasil nº 211/2024</a>
     * A Data de nascimento em um certificado ICP-Brasil é armazenada na extensão Subject Alternative Name.
     * O Subject Alternative Name é uma lista. O elemento contendo essa informação é identificado pelo
     * OID com valor "2.16.76.1.3.1"
     * Retorna a data de nascimento do titular do certificado.
     *
     * @param certificate Certificado ICP-Brasil
     * @return Data de nascimento do titular do certificado
     */
    public static LocalDate getDataNascimento(X509Certificate certificate) {
        if (!isIcpBrasilOrganization(certificate)) {
            throw new IllegalArgumentException("Certificado não pertence à ICP-Brasil");
        }
        String value = extractOidValueFromSAN(certificate, "2.16.76.1.3.1");
        String dataNascimento = value.substring(0, 8); // Ex: "24122002"
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("ddMMyyyy");
        return LocalDate.parse(dataNascimento, formatter);
    }

    /**
     * Extrai o CPF do titular do certificado ICP-Brasil.
     *
     * @param certificate Certificado ICP-Brasil
     * @return CPF do titular do certificado
     */
    public static String getCpf(X509Certificate certificate) {
        if (!isIcpBrasilOrganization(certificate)) {
            throw new IllegalArgumentException("Certificado não pertence à ICP-Brasil");
        }
        String value = extractOidValueFromSAN(certificate, "2.16.76.1.3.1");
        return value.substring(8, 19); // Extrai os 11 dígitos do CPF
    }

    /**
     * Extrai o valor de um OID específico do Subject Alternative Name do certificado.
     *
     * @param certificate Certificado X.509
     * @param targetOid OID a ser buscado (ex: "2.16.76.1.3.1")
     * @return Valor associado ao OID
     * @throws IllegalArgumentException se o OID não for encontrado ou estrutura for inválida
     */
    private static String extractOidValueFromSAN(X509Certificate certificate, String targetOid) {
        GeneralNames gns = CertificateParser.getSubjectAlternativeNames(certificate);

        for (GeneralName gn : gns.getNames()) {
            ASN1Primitive primitive = gn.getName().toASN1Primitive();

            if (primitive instanceof DERIA5String) {
                continue;
            }

            if (!(primitive instanceof ASN1Sequence)) {
                throw new IllegalArgumentException("GeneralName não é uma sequência ASN.1");
            }

            ASN1Sequence seq = ASN1Sequence.getInstance(primitive);
            String oid = seq.getObjectAt(0).toString();

            if (oid.equals(targetOid)) {
                return ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getBaseObject().toString();
            }
        }

        throw new IllegalArgumentException("OID " + targetOid + " não encontrado - certificado não segue a estrutura ICP-Brasil");
    }

    public static boolean isIcpBrasilOrganization(X509Certificate certificate) {
        boolean validSubject = "ICP-Brasil".equals(
                CertificateParser.getSubjectOrganization(certificate)
        );

        boolean validIssuer = "ICP-Brasil".equals(
                CertificateParser.getIssuerOrganization(certificate)
        );

        return validSubject && validIssuer;
    }
}
