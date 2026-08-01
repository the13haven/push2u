package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import java.security.Provider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

/**
 * The ES256 algorithm/format selection: native P1363 output is preferred, and a provider
 * offering no ECDSA form at all is rejected loudly. The BouncyCastle provider is not registered
 * with {@code java.security.Security} — it stays scoped to the {@link Jca} under test, which is
 * exactly the {@code .cryptoProvider(...)} contract. The DER-fallback side of the matrix
 * (BC-FIPS) lives in {@code BcFipsJcaEs256SelectionTest} in the fipsTest source set — bc-fips
 * cannot share a classpath with the stock bcprov used here.
 */
class JcaEs256SelectionTest {

    @Test
    void platformProviderYieldsNativeP1363() {
        Jca.EcdsaSignature es256 = Jca.platform().es256();

        assertThat(es256.encoding()).isEqualTo(Jca.EcdsaSignature.Encoding.P1363);
        assertThat(es256.delegate().getAlgorithm()).isEqualTo("SHA256withECDSAinP1363Format");
    }

    @Test
    void stockBouncyCastleRegistersP1363SoTheFallbackStaysInactive() {
        Provider bc = new BouncyCastleProvider();

        Jca.EcdsaSignature es256 = Jca.using(bc).es256();

        assertThat(es256.encoding())
            .as("stock bcprov registers SHA256withECDSAinP1363Format — the direct r||s path")
            .isEqualTo(Jca.EcdsaSignature.Encoding.P1363);
        assertThat(es256.delegate().getProvider()).isSameAs(bc);
    }

    @Test
    void providerWithNoEcdsaFormIsRejectedNamingBothAlgorithms() {
        Provider empty = new Provider("no-ecdsa", "1.0", "test provider registering nothing") {
        };

        assertThatThrownBy(() -> Jca.using(empty).es256())
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no-ecdsa")
            .hasMessageContaining("SHA256withECDSAinP1363Format")
            .hasMessageContaining("SHA256withECDSA");
    }

    @Test
    void failedResolutionIsNotCachedAndFailsTheSameWayOnEveryCall() {
        Provider empty = new Provider("no-ecdsa", "1.0", "test provider registering nothing") {
        };
        Jca jca = Jca.using(empty);

        PushCryptoException first = catchThrowableOfType(PushCryptoException.class, jca::es256);
        PushCryptoException second = catchThrowableOfType(PushCryptoException.class, jca::es256);

        assertThat(first).as("first call rejects the provider").isNotNull();
        assertThat(second)
            .as("a failed resolution must not be cached — the second call re-resolves and "
                + "rejects identically instead of serving stale state")
            .isNotNull()
            .hasMessage(first.getMessage());
        assertThat(second.getMessage())
            .contains("no-ecdsa", "SHA256withECDSAinP1363Format", "SHA256withECDSA");
    }
}
