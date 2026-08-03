package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.Provider;

import org.junit.jupiter.api.Test;

/**
 * What the library does when the provider it was pointed at does not carry the primitive being asked for.
 *
 * <p>Not a hypothetical: {@code Jca.using(...)} exists so a deployment can bind every primitive to one provider (a FIPS
 * module, a smartcard bridge, a hardened JRE profile), and those register a deliberately narrow set of algorithms. The
 * contract under test is that such a provider produces a {@link PushCryptoException} naming both the algorithm and the
 * provider it was missing from — the two facts an operator needs — rather than a {@code NoSuchAlgorithmException}
 * surfacing from somewhere deep in a send.
 */
class JcaUnavailableAlgorithmTest {

    private static final String PROVIDER_NAME = "push2u-empty";

    /** A syntactically valid provider that registers nothing, so every lookup against it fails. */
    private static final Provider EMPTY = new Provider(PROVIDER_NAME, "1.0", "registers no algorithms") {};

    private final Jca jca = Jca.using(EMPTY);

    @Test
    void hmacReportsTheAlgorithmAndTheProvider() {
        assertThatThrownBy(jca::hmacSha256)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining(Algorithms.HMAC_SHA256)
                .hasMessageContaining(PROVIDER_NAME)
                .hasCauseInstanceOf(java.security.GeneralSecurityException.class);
    }

    @Test
    void aesGcmReportsTheAlgorithmAndTheProvider() {
        assertThatThrownBy(jca::aesGcm)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining(Algorithms.AES_GCM_NO_PADDING)
                .hasMessageContaining(PROVIDER_NAME);
    }

    @Test
    void ecdhReportsTheAlgorithmAndTheProvider() {
        assertThatThrownBy(jca::ecdh)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining(Algorithms.ECDH)
                .hasMessageContaining(PROVIDER_NAME);
    }

    @Test
    void keyFactoryAndKeyPairGeneratorAreDistinguishableInTheMessage() {
        assertThatThrownBy(jca::ecKeyFactory)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("KeyFactory");

        assertThatThrownBy(jca::ecKeyPairGenerator)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining("KeyPairGenerator");
    }

    @Test
    void p256ParametersReportsTheCurveItCouldNotBuild() {
        assertThatThrownBy(jca::p256Parameters)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining(Algorithms.SECP256R1)
                .hasMessageContaining(PROVIDER_NAME);
    }

    /**
     * ES256 is the one primitive with a fallback: P1363 first, DER second, both bound to the same provider. When
     * neither is registered the failure has to name both attempts, otherwise an operator reading it would go looking
     * for the wrong algorithm name in their provider's documentation.
     */
    @Test
    void es256NamesBothTheP1363AndDerAttemptsAndKeepsTheFirstFailureAttached() {
        assertThatThrownBy(jca::es256)
                .isInstanceOf(PushCryptoException.class)
                .hasMessageContaining(Algorithms.ES256_P1363)
                .hasMessageContaining(Algorithms.ES256_DER)
                .hasMessageContaining(PROVIDER_NAME)
                .satisfies(thrown -> org.assertj.core.api.Assertions.assertThat(
                                thrown.getCause().getSuppressed())
                        .as("the P1363 lookup failure is kept as suppressed evidence")
                        .hasSize(1));
    }

    /**
     * The platform instance describes itself differently — there is no provider name to report, and a message reading
     * "unavailable from provider null" would send an operator hunting for a provider that was never configured.
     */
    @Test
    void thePlatformInstanceDescribesItselfWithoutAProviderName() {
        Jca platform = Jca.platform();

        // Every algorithm this library needs is present on a stock JRE, so the description is only observable
        // through an algorithm nothing registers.
        assertThatThrownBy(() -> Jca.using(EMPTY).hmacSha256()).hasMessageContaining("provider " + PROVIDER_NAME);
        org.assertj.core.api.Assertions.assertThat(platform.hmacSha256())
                .as("the platform providers do carry HMAC-SHA-256")
                .isNotNull();
    }
}
