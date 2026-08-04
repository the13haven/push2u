package com.the13haven.push2u;

import static com.the13haven.push2u.TestVectors.b64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * {@link Subscription} is the library's only mutable-carrying value type: two byte arrays it copies on the way in and
 * on the way out. Equality therefore has to be by content — an application storing subscriptions in a {@code Set} or
 * keying a map by them would otherwise get duplicates that look identical in a log and behave as distinct entries.
 */
class SubscriptionValueTest {

    private static final String ENDPOINT = "https://push.example.net/wpush/v1/token";

    private static byte[] key() {
        return b64(TestVectors.UA_PUBLIC);
    }

    private static byte[] auth() {
        return b64(TestVectors.AUTH_SECRET);
    }

    @Test
    void equalityAndHashingAreByContentNotByArrayIdentity() {
        Subscription first = new Subscription(ENDPOINT, key(), auth());
        Subscription second = new Subscription(ENDPOINT, key(), auth());

        assertThat(first.equals(first)).as("equals is reflexive").isTrue();
        assertThat(first)
                .isEqualTo(second)
                .hasSameHashCodeAs(second)
                .isNotEqualTo(null)
                .isNotEqualTo("not a subscription");
    }

    @Test
    void eachComponentParticipatesInEquality() {
        Subscription base = new Subscription(ENDPOINT, key(), auth());

        assertThat(base).isNotEqualTo(new Subscription(ENDPOINT + "2", key(), auth()));

        byte[] otherKey = key();
        otherKey[64] ^= 0x01;
        assertThat(base).isNotEqualTo(new Subscription(ENDPOINT, otherKey, auth()));

        byte[] otherAuth = auth();
        otherAuth[0] ^= 0x01;
        assertThat(base).isNotEqualTo(new Subscription(ENDPOINT, key(), otherAuth));
    }

    @Test
    void theKeyMaterialIsCopiedInBothDirections() {
        byte[] mutableKey = key();
        byte[] mutableAuth = auth();
        Subscription subscription = new Subscription(ENDPOINT, mutableKey, mutableAuth);

        mutableKey[1] ^= 0xFF;
        mutableAuth[1] ^= 0xFF;
        assertThat(subscription.p256dh()).isEqualTo(key());
        assertThat(subscription.auth()).isEqualTo(auth());

        subscription.p256dh()[1] ^= 0xFF;
        subscription.auth()[1] ^= 0xFF;
        assertThat(subscription.p256dh()).isEqualTo(key());
        assertThat(subscription.auth()).isEqualTo(auth());
    }

    /**
     * A 65-byte key with the wrong first octet is the interesting rejection: the length check alone would pass it, and
     * what arrives is then a compressed point or a raw coordinate pair that ECDH would interpret as something else
     * entirely.
     */
    @Test
    void aKeyOfTheRightLengthWithTheWrongPrefixIsRejected() {
        byte[] wrongPrefix = key();
        wrongPrefix[0] = 0x03;

        assertThatThrownBy(() -> new Subscription(ENDPOINT, wrongPrefix, auth()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("0x04");
    }

    @Test
    void theAuthSecretMustBeExactlyTheSixteenBytesRfc8291Requires() {
        for (int length : new int[] {0, 15, 17, 32}) {
            assertThatThrownBy(() -> new Subscription(ENDPOINT, key(), new byte[length]))
                    .as("auth of %d bytes", length)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("16 bytes");
        }
    }

    @Test
    void aPlaintextEndpointIsRejected() {
        assertThatThrownBy(() -> new Subscription("http://push.example.net/x", key(), auth()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toStringDoesNotLeakTheSubscriptionToken() {
        String rendered = new Subscription(ENDPOINT, key(), auth()).toString();

        assertThat(rendered).doesNotContain("token");
        assertThat(rendered).doesNotContain(Arrays.toString(auth()));
    }
}
