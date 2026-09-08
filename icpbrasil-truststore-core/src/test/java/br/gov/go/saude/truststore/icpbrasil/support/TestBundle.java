package br.gov.go.saude.truststore.icpbrasil.support;

import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Bundles sinteticos pequenos para exercitar o pipeline real sem rede. */
public final class TestBundle {
    private TestBundle() {}

    @SneakyThrows
    public static byte[] zip(X509Certificate certificate) {
        return zip(Map.of("ca.crt", certificate.getEncoded()));
    }

    @SneakyThrows
    public static byte[] zip(Map<String, byte[]> entries) {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for (var entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return bytes.toByteArray();
    }

    @SneakyThrows
    public static String hash(byte[] bytes) {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-512").digest(bytes));
    }
}
