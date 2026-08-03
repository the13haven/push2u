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

    @Test
    void anExplicitProviderIsTheOneThatServesEveryPrimitive() {
        Provider sunJce = Security.getProvider("SunJCE");
        Provider sunEc = Security.getProvider("SunEC");
        assertThat(sunJce).as("stock JRE provider").isNotNull();
        assertThat(sunEc).as("stock JRE provider").isNotNull();

        assertThat(Jca.using(sunJce).hmacSha256().getProvider()).isSameAs(sunJce);
        assertThat(Jca.using(sunJce).aesGcm().getProvider()).isSameAs(sunJce);
        assertThat(Jca.using(sunEc).ecdh().getProvider()).isSameAs(sunEc);
        assertThat(Jca.using(sunEc).ecKeyFactory().getProvider()).isSameAs(sunEc);
        assertThat(Jca.using(sunEc).ecKeyPairGenerator().getProvider()).isSameAs(sunEc);
        assertThat(Jca.using(sunEc).es256().delegate().getProvider()).isSameAs(sunEc);
    }

    @Test
    void theP256ParametersComeFromTheBoundProviderToo() {
        assertThat(Jca.using(Security.getProvider("SunEC")).p256Parameters().getCurve())
                .isEqualTo(Jca.platform().p256Parameters().getCurve());
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
