/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Provider;
import java.security.Security;
import java.security.Signature;

import org.junit.jupiter.api.Test;

/**
 * {@code Jca.using(provider)} exists so a deployment can keep every primitive inside one compliance boundary. The two
 * things worth pinning are that an explicitly bound provider is actually the one used — not merely accepted and then
 * ignored in favour of the platform search order — and that the ES256 fallback stays inside that boundary.
 *
 * <p>The FIPS half of this is covered for real in the {@code fipsTest} source set, which runs against BouncyCastle FIPS
 * on a separate classpath. What is added here is the same reasoning with stock providers, so the binding is checked on
 * every build rather than only in the FIPS matrix.
 */
class JcaProviderBindingTest {

    /**
     * Every primitive is asked of the bound provider. Asserted through a provider that records its own lookups rather
     * than by comparing {@code getProvider()} against a stock provider: the stock providers are also what the platform
     * search order returns first, so {@code assertThat(...getProvider()).isSameAs(SunEC)} would stay green even if the
     * binding were dropped entirely and the lookup fell through to the platform.
     *
     * <p>The sentinel delegates the actual service to the stock providers, so the primitives really work — what is
     * being proved is only that the request passed through the provider that was handed in.
     */
    @Test
    void everyPrimitiveIsRequestedFromTheBoundProviderRatherThanTheSearchOrder() {
        assertThat(lookupsFor(Jca::hmacSha256)).containsExactly("Mac/HmacSHA256");
        assertThat(lookupsFor(Jca::aesGcm)).containsExactly("Cipher/" + Algorithms.AES_GCM_NO_PADDING);
        assertThat(lookupsFor(Jca::ecdh)).containsExactly("KeyAgreement/ECDH");
        assertThat(lookupsFor(Jca::ecKeyFactory)).containsExactly("KeyFactory/EC");
        assertThat(lookupsFor(Jca::ecKeyPairGenerator)).containsExactly("KeyPairGenerator/EC");
        assertThat(lookupsFor(Jca::p256Parameters)).containsExactly("AlgorithmParameters/EC");
        assertThat(lookupsFor(Jca::es256)).containsExactly("Signature/" + Algorithms.ES256_P1363);
    }

    /**
     * The negative half of the same statement: the platform instance must NOT consult a provider it was never given.
     * Together with the test above this pins the binding in both directions — one instance uses the provider, the other
     * cannot reach it.
     */
    @Test
    void thePlatformInstanceDoesNotConsultAnUninstalledProvider() {
        SentinelProvider sentinel = new SentinelProvider();

        Jca.platform().hmacSha256();
        Jca.platform().ecdh();
        Jca.platform().p256Parameters();

        assertThat(sentinel.lookups()).isEmpty();
    }

    /** Runs one primitive against a recording provider and returns the service lookups it made. */
    private static java.util.Set<String> lookupsFor(java.util.function.Consumer<Jca> primitive) {
        SentinelProvider sentinel = new SentinelProvider();
        primitive.accept(Jca.using(sentinel));
        return sentinel.lookups();
    }

    /**
     * Records every {@code type/algorithm} it is asked for and delegates the work to the stock providers. Not installed
     * in {@link Security}, so nothing can reach it except through an explicit {@code Jca.using(...)}.
     */
    private static final class SentinelProvider extends Provider {

        @java.io.Serial
        private static final long serialVersionUID = 1L;

        private final transient java.util.Set<String> lookups = java.util.concurrent.ConcurrentHashMap.newKeySet();

        SentinelProvider() {
            super("push2u-sentinel", "1.0", "records lookups, delegates the work");
        }

        @Override
        public Service getService(String type, String algorithm) {
            lookups.add(type + "/" + algorithm);
            Provider source = "Mac".equals(type) || "Cipher".equals(type)
                    ? Security.getProvider("SunJCE")
                    : Security.getProvider("SunEC");
            return source.getService(type, algorithm);
        }

        java.util.Set<String> lookups() {
            return java.util.Set.copyOf(lookups);
        }
    }

    /**
     * A provider registering only the DER spelling of ES256 — the shape BouncyCastle FIPS has — must resolve to the DER
     * encoding rather than failing. The signature is then converted by {@link EcdsaDer}; picking the wrong branch here
     * would produce a JWT signed with a DER blob where RFC 7518 §3.4 requires raw {@code r || s}, which every push
     * service would reject as an invalid signature.
     */
    @Test
    void aProviderWithoutTheP1363SpellingFallsBackToDerWithinTheSameProvider() {
        Provider derOnly = new DerOnlyProvider();

        Jca.EcdsaSignature resolved = Jca.using(derOnly).es256();

        assertThat(resolved.encoding()).isEqualTo(Jca.EcdsaSignature.Encoding.DER);
        assertThat(resolved.delegate().getProvider())
                .as("the fallback must not widen the search to another installed provider")
                .isSameAs(derOnly);
    }

    @Test
    void theResolutionIsCachedSoTheFallbackIsNotRepaidOnEverySignature() {
        DerOnlyProvider derOnly = new DerOnlyProvider();
        Jca jca = Jca.using(derOnly);

        jca.es256();
        int afterFirst = derOnly.p1363Lookups();
        jca.es256();
        jca.es256();

        assertThat(derOnly.p1363Lookups())
                .as("the missing P1363 name is looked up once, not once per signature")
                .isEqualTo(afterFirst);
    }

    /** Registers {@code SHA256withECDSA} (delegating to SunEC) and nothing else. */
    private static final class DerOnlyProvider extends Provider {

        @java.io.Serial
        private static final long serialVersionUID = 1L;

        private transient int p1363Lookups;

        DerOnlyProvider() {
            super("push2u-der-only", "1.0", "ES256 in DER form only");
            Provider sunEc = Security.getProvider("SunEC");
            Service source = sunEc.getService("Signature", Algorithms.ES256_DER);
            putService(new Service(this, "Signature", Algorithms.ES256_DER, source.getClassName(), null, null) {
                @Override
                public Object newInstance(Object constructorParameter) throws java.security.NoSuchAlgorithmException {
                    return Signature.getInstance(Algorithms.ES256_DER, sunEc);
                }
            });
        }

        @Override
        public synchronized Service getService(String type, String algorithm) {
            if (Algorithms.ES256_P1363.equals(algorithm)) {
                p1363Lookups++;
            }
            return super.getService(type, algorithm);
        }

        synchronized int p1363Lookups() {
            return p1363Lookups;
        }
    }
}
