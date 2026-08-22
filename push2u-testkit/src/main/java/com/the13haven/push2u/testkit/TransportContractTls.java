/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

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
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * The TLS identity of the transport contract's harness: one self-signed P-256 certificate for {@code 127.0.0.1},
 * generated lazily once per test JVM. Nothing is committed to a repository and nothing ships in the artifact — a
 * private key inside a published jar would be a credential everyone holds, and a committed certificate expires.
 *
 * <p>{@link #serverContext()} presents the certificate from the harness's listeners. {@link #clientContext()} and
 * {@link #clientTrustManager()} are the two standard objects the contract hands an implementor: they trust exactly this
 * certificate and nothing else, built through an ordinary {@link TrustManagerFactory} over a one-entry trust store — no
 * trust-all manager and no relaxed hostname verification anywhere, so the transport under test performs the same
 * handshake and the same hostname check a production endpoint demands. Both halves are handed over because the common
 * HTTP stacks want different ones: the JDK's client and Apache HttpClient 5 take an {@code SSLContext}, while OkHttp's
 * supported configuration call takes the socket factory <em>and</em> the {@link X509TrustManager} beside it.
 *
 * <p><b>Invariant: this class names no JCE provider.</b> The kit is loaded on test classpaths whose providers differ —
 * including two that can never coexist — so it uses the standard algorithm names and takes whatever the environment
 * offers, exactly as the code under test does. That is also why the certificate's DER is assembled by hand below: a
 * certificate-building library is not a dependency of this artifact, and JDK-internal builders live in packages that
 * need {@code --add-exports} and have moved before. The hand-built encoding is not self-certified — it is parsed back
 * through the platform's {@link CertificateFactory}, so the JDK validates it.
 */
final class TransportContractTls {

    /** Serial-number randomness for the throwaway certificate; held so the generator is created once. */
    private static final SecureRandom RANDOM = new SecureRandom();

    private TransportContractTls() {}

    /** An {@link SSLContext} that presents the per-JVM loopback certificate — the harness's server side. */
    static SSLContext serverContext() {
        return Holder.SERVER_CONTEXT;
    }

    /** An {@link SSLContext} that trusts exactly the per-JVM loopback certificate — handed to the implementor. */
    static SSLContext clientContext() {
        return Holder.CLIENT_CONTEXT;
    }

    /** The {@link X509TrustManager} behind {@link #clientContext()} — handed to the implementor beside it. */
    static X509TrustManager clientTrustManager() {
        return Holder.CLIENT_TRUST_MANAGER;
    }

    /** Lazy holder: key pair, certificate, both contexts and the trust manager are created once, on first use. */
    private static final class Holder {

        private static final char[] KEY_PASSWORD = new char[0];
        private static final SSLContext SERVER_CONTEXT;
        private static final SSLContext CLIENT_CONTEXT;
        private static final X509TrustManager CLIENT_TRUST_MANAGER;

        static {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair keyPair = generator.generateKeyPair();
                X509Certificate certificate = selfSignedLoopbackCertificate(keyPair);

                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, null);
                keyStore.setKeyEntry(
                        "push2u-transport-contract", keyPair.getPrivate(), KEY_PASSWORD, new X509Certificate[] {
                            certificate
                        });
                KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagers.init(keyStore, KEY_PASSWORD);
                SSLContext serverContext = SSLContext.getInstance("TLS");
                serverContext.init(keyManagers.getKeyManagers(), null, null);
                SERVER_CONTEXT = serverContext;

                KeyStore trustStore = KeyStore.getInstance("PKCS12");
                trustStore.load(null, null);
                trustStore.setCertificateEntry("push2u-transport-contract", certificate);
                TrustManagerFactory trustManagers =
                        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagers.init(trustStore);
                CLIENT_TRUST_MANAGER = onlyX509TrustManager(trustManagers.getTrustManagers());
                SSLContext clientContext = SSLContext.getInstance("TLS");
                clientContext.init(null, new TrustManager[] {CLIENT_TRUST_MANAGER}, null);
                CLIENT_CONTEXT = clientContext;
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("failed to build the transport contract's TLS identity", e);
            }
        }

        private Holder() {}

        /**
         * The one {@link X509TrustManager} the factory built over the one-entry store. The client context is
         * initialised with exactly this instance, so the context and the handed-over manager cannot disagree about what
         * they trust.
         */
        private static X509TrustManager onlyX509TrustManager(TrustManager... trustManagers) {
            for (TrustManager candidate : trustManagers) {
                if (candidate instanceof X509TrustManager x509) {
                    return x509;
                }
            }
            throw new IllegalStateException("the platform's TrustManagerFactory produced no X509TrustManager");
        }
    }

    /**
     * Builds a fresh self-signed X.509 v3 certificate for the harness's loopback listeners: subject/issuer
     * {@code CN=push2u transport contract}, an ECDSA-with-SHA256 signature by its own P-256 key,
     * {@code basicConstraints} CA:false, and — load-bearing — a {@code subjectAltName} carrying <em>iPAddress</em>
     * {@code 127.0.0.1}: the endpoints the contract hands out are IP-literal URLs, the JDK verifies those against the
     * iPAddress SAN and never against CN, and a certificate without it would fail hostname verification — which the
     * contract wants performed, not skipped. One certificate serves every listener, the redirect target included, so a
     * transport that wrongly follows the redirect arrives there with no trust error to stop it and its absence means
     * what the redirect check needs it to mean.
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
        RANDOM.nextBytes(serialBytes);
        serialBytes[0] = (byte) ((serialBytes[0] & 0x3F) | 0x40);
        byte[] serial = der(0x02, serialBytes);

        // Name ::= RDNSequence of one RDN: CN=push2u transport contract (CN is OID 2.5.4.3). Issuer == subject.
        byte[] name = der(
                0x30,
                der(
                        0x31,
                        der(
                                0x30,
                                concat(
                                        der(0x06, new byte[] {0x55, 0x04, 0x03}),
                                        der(0x0C, "push2u transport contract".getBytes(StandardCharsets.UTF_8))))));

        // Validity: notBefore 2026-01-01 (UTCTime — the year this harness was written; RFC 5280 §4.1.2.5
        // requires UTCTime for dates through 2049), notAfter 9999-12-31T23:59:59Z (GeneralizedTime). The far
        // end date is deliberate: RFC 5280 §4.1.2.5 defines 99991231235959Z as "no well-defined expiration
        // date", and a per-JVM throwaway certificate that expired mid-life would fail a consumer's suite for
        // no security gain — the private key never leaves the test JVM.
        byte[] validity = der(
                0x30,
                concat(
                        der(0x17, "260101000000Z".getBytes(StandardCharsets.US_ASCII)),
                        der(0x18, "99991231235959Z".getBytes(StandardCharsets.US_ASCII))));

        // basicConstraints (OID 2.5.29.19): CA:false — cA defaults to FALSE, so DER forbids writing it and the
        // extension value is an empty SEQUENCE.
        byte[] basicConstraints =
                der(0x30, concat(der(0x06, new byte[] {0x55, 0x1D, 0x13}), der(0x04, der(0x30, new byte[0]))));

        // subjectAltName (OID 2.5.29.17): GeneralName iPAddress [7] 127.0.0.1 — see the method Javadoc.
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
            // Only the two-byte long form is implemented, which is enough for everything this
            // class encodes. Refusing anything larger rather than writing a truncated length: a
            // silently mis-encoded TLV would produce a certificate that parses into the wrong
            // shape, and this helper is exactly the kind of thing that gets copied elsewhere.
            if (content.length > 0xFFFF) {
                throw new IllegalArgumentException(
                        "DER content of " + content.length + " bytes exceeds the 65535 this helper can encode");
            }
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
