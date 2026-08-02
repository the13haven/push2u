package io.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.push2u.LocalEcVapidSigner;
import io.push2u.PushHttpClient;
import io.push2u.PushMessage;
import io.push2u.PushResponse;
import io.push2u.PushResult;
import io.push2u.PushSender;
import io.push2u.Subscription;
import io.push2u.VapidSigner;

/**
 * {@link Push2uAutoConfiguration} wires a {@link PushSender} (and an Actuator health indicator) from {@code push2u.*}
 * properties, backing off to application-supplied beans.
 */
class Push2uAutoConfigurationTest {

    private static String publicKeyB64;
    private static String privateKeyB64;
    /** The public half of an unrelated pair, for the mismatch case. */
    private static String otherPublicKeyB64;
    /** A well-formed subscription {@code p256dh} point, unrelated to the VAPID pair above. */
    private static String subscriptionKeyB64;

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(
                    AutoConfigurations.of(Push2uAutoConfiguration.class, Push2uHealthAutoConfiguration.class));

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
                        "push2u.vapid.public-key=" + publicKeyB64, "push2u.vapid.private-key=" + privateKeyB64)
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
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.vapid.subject");
                });
    }

    @Test
    void applicationSuppliedSenderStartsWithoutTheSubject() {
        // The subject pre-flight lives in the pushSender @Bean method, which is
        // @ConditionalOnMissingBean(PushSender.class): an application-supplied PushSender bypasses
        // it entirely, so push2u.vapid.subject is not required in that case. This is now a contract
        // worth pinning — it would be easy to break by relocating the check into a property
        // validator instead.
        //
        // Local VAPID keys are configured (without a subject) so that pushSender's OTHER
        // precondition, @ConditionalOnBean(VapidSigner.class), is also satisfied here — otherwise
        // the factory method would never run regardless of @ConditionalOnMissingBean, and the test
        // would pass for the wrong reason (pinned by mutation testing: with no keys configured, the
        // test stayed green even with @ConditionalOnMissingBean deleted entirely). With a local
        // signer present, the health indicator has the VapidSigner it needs, so the field runner
        // (which includes Push2uHealthAutoConfiguration) works unmodified.
        runner.withPropertyValues(
                        "push2u.vapid.public-key=" + publicKeyB64, "push2u.vapid.private-key=" + privateKeyB64)
                .withUserConfiguration(CustomSenderConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PushSender.class);
                    assertThat(context.getBean(PushSender.class)).isSameAs(CustomSenderConfiguration.SENDER);
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
                    PushResult result = sender.send(
                            subscription(), PushMessage.builder(new byte[4096]).build());
                    assertThat(result.delivered()).isTrue();
                });
    }

    @Test
    void defaultLimitsRejectAPayloadThatOnlyFitsUnderTheRaisedOnes() {
        // Control for the previous test: without raising the properties, the same 4096-byte
        // payload must be rejected by PushSender's own default limits, before any network call.
        // At the defaults the body-size precondition (rs=4096, body cap 4096) fires first, ahead
        // of the record-size one — hence the assertion on that particular message.
        keyedRunner().run(context -> {
            PushSender sender = context.getBean(PushSender.class);
            assertThatThrownBy(() -> sender.send(
                            subscription(), PushMessage.builder(new byte[4096]).build()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("exceeding the configured maximum");
        });
    }

    @Test
    void invalidRecordSizeFailsTheContextNamingTheProperty() {
        // The builder's own message names its camelCase parameter ("recordSize"), not the YAML
        // property — the starter re-throws with push2u.record-size prefixed so the failure is
        // actionable. That re-thrown IllegalArgumentException wraps the builder's original as its
        // cause, so rootCause() would find the unprefixed message instead; and Spring's own
        // BeanCreationException.getMessage() happens to *echo* the wrapped text too, so a plain
        // "any message in the chain contains the needle" search would match that wrapper instead of
        // the actual exception. firstOfTypeContaining requires both the exact exception type and
        // the message, landing on the starter's own IllegalArgumentException specifically.
        keyedRunner().withPropertyValues("push2u.record-size=10").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.record-size:"))
                    .hasMessageContaining("push2u.record-size:")
                    .hasMessageContaining("recordSize must be at least");
        });
    }

    @Test
    void invalidMaxEncryptedBodyBytesFailsTheContextNamingTheProperty() {
        keyedRunner().withPropertyValues("push2u.max-encrypted-body-bytes=10").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(),
                            IllegalArgumentException.class,
                            "push2u.max-encrypted-body-bytes:"))
                    .hasMessageContaining("push2u.max-encrypted-body-bytes:")
                    .hasMessageContaining("maxEncryptedBodyBytes must be at least");
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

    /**
     * The first throwable that is an instance of {@code type} in {@code root}'s cause chain (inclusive) whose message
     * contains {@code needle} — including subtypes of {@code type}. Unlike a plain message search, this will not match
     * an outer wrapper (e.g. Spring's {@code BeanCreationException}) whose own message happens to echo a nested cause's
     * text.
     */
    private static <T extends Throwable> T firstOfTypeContaining(Throwable root, Class<T> type, String needle) {
        for (Throwable current = root; current != null; current = current.getCause()) {
            if (type.isInstance(current)
                    && current.getMessage() != null
                    && current.getMessage().contains(needle)) {
                return type.cast(current);
            }
        }
        throw new AssertionError("no " + type.getSimpleName() + " in the cause chain of " + root
                + " has a message containing \"" + needle + "\"");
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
    static class CustomSenderConfiguration {

        static final PushSender SENDER = PushSender.builder()
                .signer(new VapidSigner() {
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
                })
                .contact("mailto:ops@example.com")
                .build();

        @Bean
        PushSender applicationSender() {
            return SENDER;
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
