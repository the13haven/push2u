/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * The TLS identity of the in-process {@link MockPushReceiver}: one self-signed P-256 certificate for {@code 127.0.0.1},
 * generated lazily once per test JVM — nothing is checked into the repository, because a committed private key in a
 * public security library is its own problem and a committed certificate expires.
 *
 * <p>{@link #serverContext()} presents the certificate; {@link #clientContext()} trusts exactly that certificate and
 * nothing else, through an ordinary {@link TrustManagerFactory} over a one-entry trust store — no trust-all
 * {@code TrustManager}, no disabled hostname verification. The tests exercise the same https-only contract
 * ({@link Endpoints#requireSecure}) and the same TLS handshake the production path uses; there is no plaintext mode
 * anywhere, in shipped code or in the tests.
 *
 * <p><b>Invariant: keep this class provider-free.</b> Like the rest of the shared test plumbing it is loaded on two
 * deliberately disjoint classpaths — {@code test} carries only bcprov, {@code fipsTest} carries only bc-fips — so it
 * uses platform primitives only and never names a provider. That is also why the certificate's DER is built by hand
 * below: bcpkix is not a dependency of this project, and {@code sun.security.*} internals would need
 * {@code --add-exports} and have already moved packages once across JDK releases. The hand-built encoding is not
 * self-certified — it is parsed back through the JDK's {@link CertificateFactory}, so the platform validates it.
 */
final class LoopbackTls {

    private LoopbackTls() {}

    /** An {@link SSLContext} that presents the per-JVM loopback certificate — the receiver's server side. */
    static SSLContext serverContext() {
        return Holder.SERVER_CONTEXT;
    }

    /** An {@link SSLContext} that trusts exactly the per-JVM loopback certificate — the test client side. */
    static SSLContext clientContext() {
        return Holder.CLIENT_CONTEXT;
    }

    /** Lazy holder: key pair, certificate and both contexts are created once, on first use. */
    private static final class Holder {

        private static final char[] KEY_PASSWORD = new char[0];
        private static final SSLContext SERVER_CONTEXT;
        private static final SSLContext CLIENT_CONTEXT;

        static {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair keyPair = generator.generateKeyPair();
                X509Certificate certificate = selfSignedLoopbackCertificate(keyPair);

                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, null);
                keyStore.setKeyEntry(
                        "push2u-test", keyPair.getPrivate(), KEY_PASSWORD, new X509Certificate[] {certificate});
                KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagers.init(keyStore, KEY_PASSWORD);
                SSLContext serverContext = SSLContext.getInstance("TLS");
                serverContext.init(keyManagers.getKeyManagers(), null, null);
                SERVER_CONTEXT = serverContext;

                KeyStore trustStore = KeyStore.getInstance("PKCS12");
                trustStore.load(null, null);
                trustStore.setCertificateEntry("push2u-test", certificate);
                TrustManagerFactory trustManagers =
                        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagers.init(trustStore);
                SSLContext clientContext = SSLContext.getInstance("TLS");
                clientContext.init(null, trustManagers.getTrustManagers(), null);
                CLIENT_CONTEXT = clientContext;
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("failed to build the loopback TLS test identity", e);
            }
        }

        private Holder() {}
    }

    /**
     * Builds a fresh self-signed X.509 v3 certificate for the loopback receiver: subject/issuer {@code CN=push2u test
     * receiver}, an ECDSA-with-SHA256 signature by its own P-256 key, {@code basicConstraints} CA:false, and —
     * load-bearing — a {@code subjectAltName} carrying <em>iPAddress</em> {@code 127.0.0.1}: the JDK verifies an
     * IP-literal URL such as {@code https://127.0.0.1:port/…} against the iPAddress SAN, and a DNS-only certificate
     * would fail hostname verification.
     *
     * <p>The DER is assembled by hand (see the class Javadoc for why), then handed to the JDK's
     * {@link CertificateFactory} so the platform parses and validates the encoding rather than this class asserting its
     * own correctness. {@code publicKey.getEncoded()} already <em>is</em> the DER SubjectPublicKeyInfo, so the hardest
     * subtree comes from the JDK for free.
     */
    private static X509Certificate selfSignedLoopbackCertificate(KeyPair keyPair) throws GeneralSecurityException {
        // ecdsa-with-SHA256, OID 1.2.840.10045.4.3.2. RFC 5758 §3.2: the parameters field MUST be omitted.
        byte[] signatureAlgorithm =
                der(0x30, der(0x06, new byte[] {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02}));

        // [0] EXPLICIT Version ::= INTEGER 2 — v3, required for the extensions below (RFC 5280 §4.1.2.1).
        byte[] version = der(0xA0, der(0x02, new byte[] {2}));

        // Serial number: 8 random bytes with the first forced into [0x40, 0x7F] — positive and minimally
        // encoded per DER, unique enough per JVM (RFC 5280 §4.1.2.2).
        byte[] serialBytes = new byte[8];
        new SecureRandom().nextBytes(serialBytes);
        serialBytes[0] = (byte) ((serialBytes[0] & 0x3F) | 0x40);
        byte[] serial = der(0x02, serialBytes);

        // Name ::= RDNSequence of one RDN: CN=push2u test receiver (CN is OID 2.5.4.3). Issuer == subject.
        byte[] name = der(
                0x30,
                der(
                        0x31,
                        der(
                                0x30,
                                concat(
                                        der(0x06, new byte[] {0x55, 0x04, 0x03}),
                                        der(0x0C, "push2u test receiver".getBytes(StandardCharsets.UTF_8))))));

        // Validity: notBefore 2026-01-01 (UTCTime — the year this fixture was written; RFC 5280 §4.1.2.5
        // requires UTCTime for dates through 2049), notAfter 9999-12-31T23:59:59Z (GeneralizedTime). The far
        // end date is deliberate: RFC 5280 §4.1.2.5 defines 99991231235959Z as "no well-defined expiration
        // date", and a per-JVM throwaway certificate that expired mid-life would fail this suite for no
        // security gain — the private key never leaves this JVM.
        byte[] validity = der(
                0x30,
                concat(
                        der(0x17, "260101000000Z".getBytes(StandardCharsets.US_ASCII)),
                        der(0x18, "99991231235959Z".getBytes(StandardCharsets.US_ASCII))));

        // basicConstraints (OID 2.5.29.19): CA:false — cA defaults to FALSE, so DER forbids writing it and the
        // extension value is an empty SEQUENCE.
        byte[] basicConstraints =
                der(0x30, concat(der(0x06, new byte[] {0x55, 0x1D, 0x13}), der(0x04, der(0x30, new byte[0]))));

        // subjectAltName (OID 2.5.29.17): GeneralName iPAddress [7] 127.0.0.1 — the receiver's endpoint is an
        // IP-literal URL, and the JDK matches those against the iPAddress SAN only, never against CN.
        byte[] subjectAltName =
                der(0x30, concat(der(0x06, new byte[] {0x55, 0x1D, 0x11}), der(0x04, der(0x30, der(0x87, new byte[] {
                    127, 0, 0, 1
                })))));

        // [3] EXPLICIT Extensions ::= SEQUENCE OF Extension.
        byte[] extensions = der(0xA3, der(0x30, concat(basicConstraints, subjectAltName)));

        byte[] tbsCertificate = der(
                0x30,
                concat(
                        version,
                        serial,
                        signatureAlgorithm,
                        name,
                        validity,
                        name,
                        keyPair.getPublic().getEncoded(),
                        extensions));

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(tbsCertificate);
        // SHA256withECDSA produces the DER-encoded ECDSA-Sig-Value that X.509 wants in the BIT STRING verbatim.
        byte[] signature = signer.sign();

        byte[] certificate =
                der(0x30, concat(tbsCertificate, signatureAlgorithm, der(0x03, concat(new byte[] {0}, signature))));

        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate));
    }

    /** One DER TLV: tag byte, definite length, content. */
    private static byte[] der(int tag, byte[] content) {
        byte[] length;
        if (content.length < 0x80) {
            length = new byte[] {(byte) content.length};
        } else if (content.length <= 0xFF) {
            length = new byte[] {(byte) 0x81, (byte) content.length};
        } else {
            // Nothing this class encodes exceeds 65535 bytes.
            length = new byte[] {(byte) 0x82, (byte) (content.length >>> 8), (byte) content.length};
        }
        byte[] encoded = new byte[1 + length.length + content.length];
        encoded[0] = (byte) tag;
        System.arraycopy(length, 0, encoded, 1, length.length);
        System.arraycopy(content, 0, encoded, 1 + length.length, content.length);
        return encoded;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] joined = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, joined, offset, part.length);
            offset += part.length;
        }
        return joined;
    }
}
