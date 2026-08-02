package io.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;

class DomainTypesTest {

    @Test
    void subscriptionDefensivelyCopiesInputsAndAccessors() {
        byte[] p256dh = new byte[65];
        p256dh[0] = 0x04;
        byte[] auth = new byte[16];
        Subscription subscription = new Subscription("https://push.example.net/x", p256dh, auth);

        p256dh[1] = 0x7f;
        auth[0] = 0x7f;
        assertThat(subscription.p256dh()[1])
                .as("input mutation does not leak in")
                .isZero();
        assertThat(subscription.auth()[0]).isZero();

        subscription.p256dh()[1] = 0x7f;
        assertThat(subscription.p256dh()[1]).as("accessor returns a fresh copy").isZero();
    }

    @Test
    void subscriptionRejectsMalformedKeyMaterial() {
        assertThatThrownBy(() -> new Subscription("x", new byte[64], new byte[16]))
                .isInstanceOf(IllegalArgumentException.class);

        byte[] validPoint = new byte[65];
        validPoint[0] = 0x04;
        assertThatThrownBy(() -> new Subscription("x", validPoint, new byte[15]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void subscriptionFromBase64DecodesBrowserValues() {
        Subscription subscription =
                Subscription.fromBase64("https://push.example.net/x", TestVectors.UA_PUBLIC, TestVectors.AUTH_SECRET);
        assertThat(subscription.p256dh()).hasSize(65);
        assertThat(subscription.auth()).hasSize(16);
    }

    @Test
    void subscriptionHasContentValueEqualityAndRedactsTheSecret() {
        byte[] p256dh = new byte[65];
        p256dh[0] = 0x04;
        byte[] auth = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

        Subscription a = new Subscription("https://push.example.net/x", p256dh.clone(), auth.clone());
        Subscription b = new Subscription("https://push.example.net/x", p256dh.clone(), auth.clone());
        Subscription differentAuth = new Subscription(
                "https://push.example.net/x", p256dh.clone(), "fedcba9876543210".getBytes(StandardCharsets.US_ASCII));

        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b).isNotEqualTo(differentAuth);

        assertThat(a.toString())
                .as("origin stays visible, but the capability path and the auth secret do not")
                .contains("https://push.example.net")
                .doesNotContain("/x")
                .contains("redacted")
                .doesNotContain("0123456789abcdef");
    }

    @Test
    void subscriptionRejectsNonHttpsEndpoint() {
        byte[] p256dh = new byte[65];
        p256dh[0] = 0x04;
        byte[] auth = new byte[16];

        assertThatThrownBy(() -> new Subscription("http://push.example.net/secret-path", p256dh, auth))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https")
                .hasMessageNotContaining("secret-path");
        assertThatThrownBy(() -> new Subscription("ht tp://push.example.net/secret-path", p256dh, auth))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("push.example.net");

        Subscription https = new Subscription("https://push.example.net/secret-path", p256dh, auth);
        assertThat(https.endpoint()).isEqualTo("https://push.example.net/secret-path");
    }

    @Test
    void pushMessageIsImmutableAndCarriesHeaders() {
        byte[] payload = {1, 2, 3};
        PushMessage message = PushMessage.builder(payload)
                .ttl(Duration.ofHours(1))
                .urgency(Urgency.HIGH)
                .topic("orders")
                .build();

        payload[0] = 9;
        assertThat(message.payload()).as("payload is defensively copied").isEqualTo(new byte[] {1, 2, 3});
        assertThat(message.ttl()).isEqualTo(Duration.ofHours(1));
        assertThat(message.urgency()).isEqualTo(Urgency.HIGH);
        assertThat(message.topic()).isEqualTo("orders");
        assertThat(PushMessage.of(new byte[] {1}).ttl())
                .as("unset headers are null")
                .isNull();
    }

    @Test
    void pushMessageHasValueEquality() {
        PushMessage a = PushMessage.builder(new byte[] {1, 2, 3})
                .ttl(Duration.ofHours(1))
                .urgency(Urgency.HIGH)
                .build();
        PushMessage b = PushMessage.builder(new byte[] {1, 2, 3})
                .ttl(Duration.ofHours(1))
                .urgency(Urgency.HIGH)
                .build();
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b).as("different headers").isNotEqualTo(PushMessage.of(new byte[] {
            1, 2, 3
        }));
        assertThat(a.toString()).contains("payload=3 bytes").contains("urgency=HIGH");
    }

    @Test
    void pushMessageRejectsNegativeTtl() {
        PushMessage.Builder negativeTtl = PushMessage.builder(new byte[] {1}).ttl(Duration.ofSeconds(-1));
        assertThatThrownBy(negativeTtl::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void pushMessageAcceptsRfc8030CompliantTopics() {
        String fullAlphabet32 = "AZaz09-_AZaz09-_AZaz09-_AZaz09-_";
        assertThat(fullAlphabet32).hasSize(32);

        PushMessage message = new PushMessage(new byte[] {1}, null, null, fullAlphabet32);
        assertThat(message.topic()).isEqualTo(fullAlphabet32);

        assertThat(PushMessage.of(new byte[] {1}).topic())
                .as("null topic stays unset")
                .isNull();
    }

    @Test
    void pushMessageRejectsTopicsOutsideRfc8030Shape() {
        String[] badTopics = {
            "a".repeat(33), // over the 32-character limit
            "", // empty
            "orders+refunds", // '+' is standard-Base64, not URL-safe
            "orders/refunds", // '/' is standard-Base64, not URL-safe
            "orders=", // padding character
            "two words", // space
            "evil\r\nX-Injected: 1", // CR/LF header injection attempt
        };
        for (String badTopic : badTopics) {
            assertThatThrownBy(() -> new PushMessage(new byte[] {1}, null, null, badTopic))
                    .as("topic %s", badTopic.isEmpty() ? "<empty>" : badTopic)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("URL-safe Base64 alphabet");
        }

        assertThatThrownBy(() -> new PushMessage(new byte[] {1}, null, null, "orders+refunds"))
                .as("the offending value is named in the message — a topic is not secret material")
                .hasMessageContaining("orders+refunds");
    }

    @Test
    void rejectedTopicIsEchoedSafelyForLogging() {
        assertThatThrownBy(() -> new PushMessage(new byte[] {1}, null, null, "evil\r\nX-Injected: 1"))
                .as("a rejected topic must not carry its CR/LF into the log line that reports it")
                .hasMessageNotContaining("\r")
                .hasMessageNotContaining("\n")
                .hasMessageContaining("evil\\u000d\\u000aX-Injected: 1");

        String oversized = "x".repeat(5000);
        assertThatThrownBy(() -> new PushMessage(new byte[] {1}, null, null, oversized))
                .as("an oversized topic is truncated in the message but its real length is reported")
                .hasMessageContaining("5000 characters")
                .satisfies(e -> assertThat(e.getMessage()).hasSizeLessThan(200));
    }

    @Test
    void pushMessageBuilderRejectsInvalidTopicAtBuild() {
        PushMessage.Builder badTopic = PushMessage.builder(new byte[] {1}).topic("a".repeat(33));
        assertThatThrownBy(badTopic::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void urgencyHeaderValuesMatchRfc8030Tokens() {
        assertThat(Urgency.VERY_LOW.headerValue()).isEqualTo("very-low");
        assertThat(Urgency.NORMAL.headerValue()).isEqualTo("normal");
    }

    @Test
    void pushResultEnforcesTheContractItsFieldsDocument() {
        assertThatThrownBy(() -> new PushResult(null, 201, 1)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new PushResult(PushResult.Status.FAILED, -1, 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("statusCode");
        assertThatThrownBy(() -> new PushResult(PushResult.Status.DELIVERED, 201, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("attempts");

        // The documented edges stay legal: 0 means "no status was obtained", 1 is the first POST.
        assertThat(new PushResult(PushResult.Status.FAILED, 0, 1).delivered()).isFalse();
    }

    @Test
    void pushResponseRejectsANegativeStatusCode() {
        // PushHttpClient is a public seam, so a custom transport could hand back a -1 sentinel for
        // "no response"; it is refused where it is produced, not carried into the PushResult.
        assertThatThrownBy(() -> PushResponse.of(-1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("statusCode");
    }

    @Test
    void vapidKeysValidatesLengths() {
        assertThatThrownBy(() -> VapidKeys.of(new byte[64], new byte[32])).isInstanceOf(IllegalArgumentException.class);

        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;
        assertThatThrownBy(() -> VapidKeys.of(publicKey, new byte[31])).isInstanceOf(IllegalArgumentException.class);
    }
}
