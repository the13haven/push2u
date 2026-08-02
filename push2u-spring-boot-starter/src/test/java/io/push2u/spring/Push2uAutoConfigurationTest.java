package io.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.push2u.LocalEcVapidSigner;
import io.push2u.PushHttpClient;
import io.push2u.PushMessage;
import io.push2u.PushResponse;
import io.push2u.PushResult;
import io.push2u.PushSender;
import io.push2u.Subscription;
import io.push2u.VapidSigner;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * {@link Push2uAutoConfiguration} wires a {@link PushSender} (and an Actuator health indicator)
 * from {@code push2u.*} properties, backing off to application-supplied beans.
 */
class Push2uAutoConfigurationTest {

    private static String publicKeyB64;
    private static String privateKeyB64;
    /** The public half of an unrelated pair, for the mismatch case. */
    private static String otherPublicKeyB64;
    /** A well-formed subscription {@code p256dh} point, unrelated to the VAPID pair above. */
    private static String subscriptionKeyB64;

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(Push2uAutoConfiguration.class, Push2uHealthAutoConfiguration.class));

    @BeforeAll
    static void generateVapidKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        Base64.Encoder base64Url = Base64.getUrlEncoder().withoutPadding();
        publicKeyB64 = base64Url.encodeToString(uncompressed((ECPublicKey) keyPair.getPublic()));
        privateKeyB64 = base64Url.encodeToString(toFixed32(((ECPrivateKey) keyPair.getPrivate()).getS()));

        KeyPair otherPair = generator.generateKeyPair();
        otherPublicKeyB64 = base64Url.encodeToString(uncompressed((ECPublicKey) otherPair.getPublic()));

        KeyPair subscriptionPair = generator.generateKeyPair();
        subscriptionKeyB64 = base64Url.encodeToString(uncompressed((ECPublicKey) subscriptionPair.getPublic()));
    }

    @Test
    void wiresPushSenderFromProperties() {
        keyedRunner().run(context -> {
            assertThat(context).hasSingleBean(PushSender.class);
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context.getBean(VapidSigner.class)).isInstanceOf(LocalEcVapidSigner.class);
        });
    }

    @Test
    void withoutKeysThereIsNoSenderOrSigner() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(PushSender.class);
            assertThat(context).doesNotHaveBean(VapidSigner.class);
        });
    }

    @Test
    void mismatchedConfiguredKeyPairFailsTheContextInsteadOfEverySend() {
        // Operators meet this contract here, not in core: the signer is an eager @Bean, so a
        // public key that does not belong to the configured private key must break startup
        // rather than yield a sender that collects 401/403 on every send. The failure must not
        // print key material.
        runner.withPropertyValues(
                "push2u.vapid.public-key=" + otherPublicKeyB64,
                "push2u.vapid.private-key=" + privateKeyB64,
                "push2u.vapid.subject=mailto:admin@example.com")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("does not correspond");
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .hasMessageNotContaining(otherPublicKeyB64)
                    .hasMessageNotContaining(privateKeyB64);
            });
    }

    @Test
    void withoutSubjectTheContextFailsNamingTheProperty() {
        // The starter's own pre-flight, not PushSender.Builder's generic "contact is required":
        // the failure must point at the concrete property to set.
        runner.withPropertyValues(
                "push2u.vapid.public-key=" + publicKeyB64,
                "push2u.vapid.private-key=" + privateKeyB64)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("push2u.vapid.subject");
            });
    }

    @Test
    void blankSubjectFailsTheContextTheSameWayAsAnAbsentOne() {
        runner.withPropertyValues(
                "push2u.vapid.public-key=" + publicKeyB64,
                "push2u.vapid.private-key=" + privateKeyB64,
                "push2u.vapid.subject=   ")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .hasMessageContaining("push2u.vapid.subject");
            });
    }

    @Test
    void recordSizeAndMaxEncryptedBodyBytesReachTheSender() {
        // Both properties are optional pass-throughs to the builder; assert they are not silently
        // dropped by sending a payload that only fits under the raised limits. A stub transport
        // stands in for the network — the point under test is the size precondition, not delivery.
        keyedRunner()
            .withPropertyValues("push2u.record-size=8192", "push2u.max-encrypted-body-bytes=8192")
            .withUserConfiguration(StubHttpClientConfiguration.class)
            .run(context -> {
                assertThat(context).hasSingleBean(PushSender.class);
                PushSender sender = context.getBean(PushSender.class);
                // 4096 plaintext bytes: rejected by the PushSender defaults (rs=4096, body cap
                // 4096 -> 3993 max plaintext) but accepted once record-size/max-encrypted-body-bytes
                // are raised, proving the properties actually reached the builder.
                PushResult result = sender.send(subscription(), PushMessage.builder(new byte[4096]).build());
                assertThat(result.delivered()).isTrue();
            });
    }

    @Test
    void defaultRecordSizeRejectsAPayloadThatOnlyFitsUnderARaisedLimit() {
        // Control for the previous test: without raising the properties, the same 4096-byte
        // payload must be rejected by PushSender's own default limits, before any network call.
        keyedRunner().run(context -> {
            PushSender sender = context.getBean(PushSender.class);
            assertThatThrownBy(() -> sender.send(subscription(), PushMessage.builder(new byte[4096]).build()))
                .isInstanceOf(IllegalArgumentException.class);
        });
    }

    @Test
    void invalidRecordSizeFailsTheContextWithTheBuilderMessage() {
        keyedRunner().withPropertyValues("push2u.record-size=10").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                .rootCause()
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("recordSize must be at least");
        });
    }

    @Test
    void invalidMaxEncryptedBodyBytesFailsTheContextWithTheBuilderMessage() {
        keyedRunner().withPropertyValues("push2u.max-encrypted-body-bytes=10").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                .rootCause()
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxEncryptedBodyBytes must be greater than");
        });
    }

    @Test
    void anApplicationSignerOverridesTheLocalOne() {
        keyedRunner().withUserConfiguration(CustomSignerConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context.getBean(VapidSigner.class)).isSameAs(CustomSignerConfiguration.SIGNER);
            assertThat(context).hasSingleBean(PushSender.class);
        });
    }

    @Test
    void healthIndicatorReportsUpWithTheSignerType() {
        keyedRunner().run(context -> {
            assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
            Health health = context.getBean(Push2uHealthIndicator.class).health();
            assertThat(health.getStatus()).isEqualTo(Status.UP);
            assertThat(health.getDetails()).containsEntry("signer", "LocalEcVapidSigner");
        });
    }

    @Test
    void healthIndicatorReportsDownWhenTheSignerFails() {
        keyedRunner().withUserConfiguration(FailingSignerConfiguration.class).run(context -> {
            Health health = context.getBean(Push2uHealthIndicator.class).health();
            assertThat(health.getStatus()).isEqualTo(Status.DOWN);
            assertThat(health.getDetails()).containsKey("error");
        });
    }

    private ApplicationContextRunner keyedRunner() {
        return runner.withPropertyValues(
            "push2u.vapid.public-key=" + publicKeyB64,
            "push2u.vapid.private-key=" + privateKeyB64,
            "push2u.vapid.subject=mailto:admin@example.com");
    }

    /** A well-formed subscription unrelated to the VAPID key pair under test. */
    private static Subscription subscription() {
        return Subscription.fromBase64(
            "https://push.example.test/send/abc",
            subscriptionKeyB64,
            Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[16]));
    }

    /** Answers every POST with 201, so size-limit tests never touch the network. */
    @Configuration(proxyBeanMethods = false)
    static class StubHttpClientConfiguration {

        @Bean
        PushHttpClient stubHttpClient() {
            return (endpoint, headers, body) -> new PushResponse(201, Map.of());
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomSignerConfiguration {

        static final VapidSigner SIGNER = new VapidSigner() {
            @Override
            public byte[] sign(byte[] signingInput) {
                return new byte[64];
            }

            @Override
            public byte[] publicKey() {
                byte[] key = new byte[65];
                key[0] = 0x04;
                return key;
            }
        };

        @Bean
        VapidSigner applicationSigner() {
            return SIGNER;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class FailingSignerConfiguration {

        @Bean
        VapidSigner failingSigner() {
            return new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    throw new IllegalStateException("signer backend unavailable");
                }

                @Override
                public byte[] publicKey() {
                    byte[] key = new byte[65];
                    key[0] = 0x04;
                    return key;
                }
            };
        }
    }

    private static byte[] uncompressed(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed32(key.getW().getAffineX()), 0, out, 1, 32);
        System.arraycopy(toFixed32(key.getW().getAffineY()), 0, out, 33, 32);
        return out;
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        byte[] out = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return out;
    }
}
