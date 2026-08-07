/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.availability.ApplicationAvailabilityAutoConfiguration;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroup;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.AvailabilityProbesAutoConfiguration;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.HealthEndpointAutoConfiguration;
import org.springframework.boot.health.autoconfigure.application.AvailabilityHealthContributorAutoConfiguration;
import org.springframework.boot.health.autoconfigure.registry.HealthContributorRegistryAutoConfiguration;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.health.registry.HealthContributorRegistry;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.EndpointRejectedException;
import com.the13haven.push2u.LocalEcVapidSigner;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushMessage;
import com.the13haven.push2u.PushResponse;
import com.the13haven.push2u.PushResult;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.RetryPolicy;
import com.the13haven.push2u.Subscription;
import com.the13haven.push2u.VapidSigner;

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
                    // The self-test's own exception, unwrapped: bad input, same as every other
                    // rejection VapidKeys.fromBase64 reports — not a crypto-shaped failure.
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("does not correspond");
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageNotContaining(otherPublicKeyB64)
                            .hasMessageNotContaining(privateKeyB64);
                    // And the starter's own translation of it, naming both YAML properties like
                    // every other IllegalArgumentException out of this bean — pinning the type here
                    // is what would catch a catch-block regression that the root-cause check above
                    // cannot: the root cause is the same exception regardless of which catch clause
                    // it is re-thrown from.
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(), IllegalArgumentException.class, "does not correspond"))
                            .hasMessageContaining("push2u.vapid.public-key")
                            .hasMessageContaining("push2u.vapid.private-key");
                });
    }

    @Test
    void withoutSubjectTheContextFailsNamingTheProperty() {
        // The starter's own pre-flight, not the PushSender.builder(...) factory's generic
        // "contact is required": the failure must point at the concrete property to set.
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
        // test stayed green even with @ConditionalOnMissingBean deleted entirely). The keyless
        // variant of this setup is a case of its own — see
        // anApplicationSenderWithoutASignerBeanStartsWithoutTheIndicator.
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
    void anApplicationSenderWithoutASignerBeanStartsWithoutTheIndicator() {
        // The documented setup this used to break: an application builds its own PushSender and
        // configures no push2u.vapid.* at all, so the signer lives inside that sender and never
        // becomes a bean. The health indicator's condition asked only for a PushSender while its
        // factory method took a VapidSigner, so the context failed to start with an
        // UnsatisfiedDependencyException on a bean the application never had reason to declare.
        //
        // Conditioning on the signer bean makes the indicator absent instead: its probe signs to learn whether
        // the signing backend answers, and there is nothing here to sign with. Actuator's health
        // endpoint simply carries no push2u entry. The sender itself is untouched and usable.
        runner.withUserConfiguration(CustomSenderConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(PushSender.class);
            assertThat(context.getBean(PushSender.class)).isSameAs(CustomSenderConfiguration.SENDER);
            assertThat(context).doesNotHaveBean(VapidSigner.class);
            assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
        });
    }

    @Test
    void aSignerBeanAloneStillGetsAnIndicator() {
        // The condition names the signer alone, so an application that keeps a signer bean and
        // builds its PushSender by hand — not as a bean — still gets the probe. That is the whole
        // point of asking about the signer rather than about the sender: the signer is what can
        // stop answering while the application runs, and here it is present and reachable.
        //
        // The main autoconfiguration is excluded so no PushSender bean can appear, which also
        // exercises the reason @EnableConfigurationProperties is restated on the health
        // autoconfiguration: without it, push2u.health.* would not bind in this context.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Push2uHealthAutoConfiguration.class))
                .withUserConfiguration(CustomSignerConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(PushSender.class);
                    assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
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
                    assertThat(result.isDelivered()).isTrue();
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
    void keyMaterialThatIsNotBase64urlFailsTheContextNamingTheKeysAndTheHalf() {
        // The likeliest first failure of all: a key generated with the standard base64 alphabet.
        // The JDK decoder's own message is "Illegal base64 character 2b" and nothing more — same
        // text for either half, naming neither VAPID nor a property. '+' is what makes it 2b.
        // '+' spliced in at a fixed position, not substituted for a '-': a random key contains no
        // '-' about half the time, and a mutation that sometimes does nothing is a test that
        // sometimes proves nothing.
        keyedRunner()
                .withPropertyValues("push2u.vapid.public-key=+" + publicKeyB64.substring(1))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(),
                                    IllegalArgumentException.class,
                                    "push2u.vapid.public-key"))
                            .hasMessageContaining("push2u.vapid.public-key")
                            .hasMessageContaining("push2u.vapid.private-key")
                            .as("the core names the half, so the operator knows which of the two to look at")
                            .hasMessageContaining("VAPID public key is not valid base64url");
                });
    }

    @Test
    void aMalformedPrivateKeyNamesThePrivateHalfRatherThanThePublicOne() {
        keyedRunner()
                .withPropertyValues("push2u.vapid.private-key=+" + privateKeyB64.substring(1))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(),
                                    IllegalArgumentException.class,
                                    "push2u.vapid.public-key"))
                            .hasMessageContaining("VAPID private key is not valid base64url");
                });
    }

    @Test
    void aKeyThatDecodesButIsNotOnTheCurveAlsoNamesTheKeys() {
        // The other likely typo: one character changed keeps the length and the 0x04 tag, so it
        // passes every length check and fails VapidKeys' own curve check instead — an
        // IllegalArgumentException, bad input like the base64 case, so it takes the same
        // property-naming translation.
        //
        // The character is changed in the MIDDLE, not at the end. 65 bytes encode to 87 characters,
        // and the last of them carries only 4 bits of data — its low 2 bits are padding the decoder
        // discards — so substituting there decodes to the same bytes for one key in sixteen. Every
        // position below 86 carries a full 6 bits, so this substitution always changes the key.
        int at = 10;
        String offCurve = publicKeyB64.substring(0, at)
                + (publicKeyB64.charAt(at) == 'A' ? 'B' : 'A')
                + publicKeyB64.substring(at + 1);

        keyedRunner().withPropertyValues("push2u.vapid.public-key=" + offCurve).run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.vapid.public-key"))
                    // as(...) labels every assertion after it, so the two claims are described
                    // separately rather than letting one rationale caption a curve regression.
                    .as("named for the properties the pair came from")
                    .hasMessageContaining("push2u.vapid.public-key")
                    .as("and the reason is the curve check, not some other rejection")
                    .hasMessageContaining("curve equation");
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
    void invalidJwtExpiryFailsTheContextNamingTheProperty() {
        // Same convention as push2u.record-size: PushSender.Builder#jwtExpiry's own message names
        // its camelCase parameter ("jwtExpiry"), not the YAML property.
        keyedRunner().withPropertyValues("push2u.jwt-expiry=25h").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.jwt-expiry:"))
                    .hasMessageContaining("push2u.jwt-expiry:")
                    .hasMessageContaining("jwtExpiry must be > 0 and <= 24h");
        });
    }

    @Test
    void invalidDefaultTtlFailsTheContextNamingTheProperty() {
        keyedRunner().withPropertyValues("push2u.default-ttl=-1s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.default-ttl:"))
                    .hasMessageContaining("push2u.default-ttl:")
                    .hasMessageContaining("defaultTtl must not be negative");
        });
    }

    @Test
    void invalidRetryMaxAttemptsFailsTheContextNamingTheProperty() {
        // The worst offender before this fix: RetryPolicy's own message ("maxAttempts must be >=
        // 1") does not even mention "retry", let alone the YAML property — an operator reading it
        // has nothing to go on.
        keyedRunner().withPropertyValues("push2u.retry.max-attempts=0").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.retry.max-attempts:"))
                    .hasMessageContaining("push2u.retry.max-attempts:")
                    .hasMessageContaining("maxAttempts must be >= 1");
        });
    }

    @Test
    void invalidRetryInitialBackoffFailsTheContextNamingTheProperty() {
        // RetryPolicy reports both backoff bounds through one message, so without the per-key probe
        // an operator cannot tell which of the two durations it is complaining about.
        keyedRunner().withPropertyValues("push2u.retry.initial-backoff=-1s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(),
                            IllegalArgumentException.class,
                            "push2u.retry.initial-backoff:"))
                    .hasMessageContaining("push2u.retry.initial-backoff:")
                    .hasMessageContaining("backoff durations must not be negative");
        });
    }

    @Test
    void invalidRetryMaxBackoffFailsTheContextNamingTheProperty() {
        keyedRunner().withPropertyValues("push2u.retry.max-backoff=-1s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.retry.max-backoff:"))
                    .hasMessageContaining("push2u.retry.max-backoff:")
                    .hasMessageContaining("backoff durations must not be negative");
        });
    }

    /**
     * The tripwire for the probes in {@code Push2uAutoConfiguration.retryPolicy}. Each of them fills the components it
     * is not testing with {@code 1} and {@code Duration.ZERO}, and attributes any rejection to the one real value it
     * passed. That attribution is only sound while those filler values stay acceptable beside an arbitrary value of the
     * component under test — which {@link RetryPolicy#none()} alone does not witness, since it fixes all three. A
     * constraint <em>between</em> components would otherwise leave the probes blaming the wrong YAML key with every
     * other test still green.
     *
     * <p>Four assertions: the {@link RetryPolicy#none()} baseline, then one per probe pairing that probe's filler with
     * a non-trivial value of its own component — the shape a cross-component constraint would break. <b>This samples
     * the invariant, it does not decide it:</b> a constraint that only bites above some threshold would survive these
     * points. What it buys is that the cheap and likely versions of that mistake fail here rather than in an operator's
     * log, and that the invariant is written down as something executable rather than as a comment nobody re-checks.
     */
    @Test
    void probeFillersStayAcceptableBesideARealValue() {
        assertThatCode(() -> new RetryPolicy(1, Duration.ZERO, Duration.ZERO))
                .as("the triple RetryPolicy.none() is built from")
                .doesNotThrowAnyException();
        assertThatCode(() -> new RetryPolicy(Integer.MAX_VALUE, Duration.ZERO, Duration.ZERO))
                .as("zero backoffs stay legal for any attempt count — what the max-attempts probe assumes")
                .doesNotThrowAnyException();
        assertThatCode(() -> new RetryPolicy(1, Duration.ofSeconds(1), Duration.ZERO))
                .as("a zero max-backoff stays legal beside a real initial-backoff")
                .doesNotThrowAnyException();
        assertThatCode(() -> new RetryPolicy(1, Duration.ZERO, Duration.ofSeconds(1)))
                .as("a zero initial-backoff stays legal beside a real max-backoff — the max-backoff probe's own"
                        + " assumption, and the one the other three assertions do not cover")
                .doesNotThrowAnyException();
    }

    /**
     * The starter's {@code @DefaultValue}s for {@code push2u.retry.*} are supposed to be {@code RetryPolicy.defaults()}
     * restated in YAML terms — that equality is what lets README.md and docs/SPRING.md describe an unset retry block as
     * "the default policy" while the starter always constructs one explicitly. Nothing else pins it, so a change to
     * either side would make both documents quietly wrong.
     */
    @Test
    void theStarterRetryDefaultsAreTheCoreRetryDefaults() {
        // Read back what Spring actually bound with no push2u.retry.* set, rather than restating
        // the @DefaultValue literals here — restating them would pin this test to itself.
        keyedRunner().run(context -> {
            Push2uProperties.Retry bound =
                    context.getBean(Push2uProperties.class).retry();

            assertThat(new RetryPolicy(bound.maxAttempts(), bound.initialBackoff(), bound.maxBackoff()))
                    .as("the @DefaultValue triple Spring binds for push2u.retry.*")
                    .isEqualTo(RetryPolicy.defaults());
        });
    }

    @Test
    void allowedOriginsPropertyEnforcesThePolicyOnTheWiredSender() {
        // Positive and negative halves of the same property: the allowlisted origin delivers
        // (through the stub transport), a foreign one is rejected before any transport call —
        // proving push2u.allowed-origins actually reached the builder rather than being dropped.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    PushResult result = sender.send(
                            subscription(), PushMessage.builder(new byte[1]).build());
                    assertThat(result.isDelivered()).isTrue();
                });
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=https://other.example")
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    assertThatThrownBy(() -> sender.send(
                                    subscription(),
                                    PushMessage.builder(new byte[1]).build()))
                            .isInstanceOf(EndpointRejectedException.class);
                });
    }

    @Test
    void malformedAllowedOriginFailsTheContextNamingTheProperty() {
        // Same contract as record-size: a misconfigured allowlist must fail startup with the YAML
        // property name, not misbehave at send time.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=http://push.example")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(),
                                    IllegalArgumentException.class,
                                    "push2u.allowed-origins:"))
                            .hasMessageContaining("push2u.allowed-origins:")
                            .hasMessageContaining("must be https");
                });
    }

    @Test
    void anApplicationEndpointPolicyBeanReachesTheWiredSender() {
        keyedRunnerWithoutEndpointPolicy()
                .withUserConfiguration(RejectingPolicyConfiguration.class, StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    assertThatThrownBy(() -> sender.send(
                                    subscription(),
                                    PushMessage.builder(new byte[1]).build()))
                            .isInstanceOf(EndpointRejectedException.class)
                            .hasMessageContaining("application policy");
                });
    }

    @Test
    void allowedOriginsPropertyPlusPolicyBeanFailsTheContextNamingBoth() {
        // Both configured is ambiguous for a security control: silently preferring either would
        // leave the operator believing the ignored one is in force. The context must fail naming
        // both sources — including the concrete bean name, since ANY autoconfiguration could have
        // contributed the EndpointPolicy bean and the operator has to find it to fix it.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(), IllegalStateException.class, "push2u.allowed-origins"))
                            .hasMessageContaining("EndpointPolicy bean")
                            .hasMessageContaining("'rejectingPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
    }

    @Test
    void emptyAllowedOriginsBesideAPolicyBeanCedesToTheBean() {
        // The escape hatch for inherited configuration: a service getting push2u.allowed-origins
        // from a shared application.yml it does not own cannot unset the property, so explicitly
        // emptying it must mean "not using the property here" and let the bean win — otherwise
        // the conflict rule wedges that service with no move at all.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=")
                .withUserConfiguration(RejectingPolicyConfiguration.class, StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PushSender sender = context.getBean(PushSender.class);
                    assertThatThrownBy(() -> sender.send(
                                    subscription(),
                                    PushMessage.builder(new byte[1]).build()))
                            .as("the bean's policy is in force, not no-policy")
                            .isInstanceOf(EndpointRejectedException.class)
                            .hasMessageContaining("application policy");
                });
    }

    @Test
    void emptyAllowedOriginsAloneStillFailsTheContext() {
        // The guard on the escape hatch: emptying the property only cedes to a bean. With no bean
        // it stays an error, so the SSRF control cannot be silently disabled by an empty value.
        // It also fails on its own ground — "at least one origin", the allowlist factory's
        // rejection — rather than as the no-decision case below: emptying the property is a
        // statement about the property, and the operator is told what is wrong with the value they
        // actually wrote.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(),
                                    IllegalArgumentException.class,
                                    "push2u.allowed-origins:"))
                            .hasMessageContaining("at least one origin");
                });
    }

    @Test
    void neitherAllowedOriginsNorAPolicyBeanFailsTheContextNamingBothWaysToFixIt() {
        // The decision has to be expressed: a sender wired with no endpoint policy would POST
        // wherever a subscription's endpoint points, and a subscription registered by a client is
        // attacker-influenced. The failure has to be actionable in both directions, so it names the
        // property and the bean — including the deliberate opt-out, which exists only as a bean.
        keyedRunnerWithoutEndpointPolicy().run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalStateException.class, "push2u.allowed-origins"))
                    .hasMessageContaining("EndpointPolicy bean")
                    .hasMessageContaining("EndpointPolicies.unrestricted()");
        });
    }

    @Test
    void anUnrestrictedPolicyBeanIsTheWayToSendAnywhereUnderSpring() {
        // No property turns the restriction off — the opt-out is a bean, so choosing it is a code
        // change that shows up in a review rather than a line copied between profiles. Pinned by
        // sending to an origin no allowlist in this test class permits.
        keyedRunnerWithoutEndpointPolicy()
                .withUserConfiguration(UnrestrictedPolicyConfiguration.class, StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PushSender sender = context.getBean(PushSender.class);
                    PushResult result = sender.send(
                            subscription("https://169.254.169.254/latest/meta-data"),
                            PushMessage.builder(new byte[1]).build());
                    assertThat(result.isDelivered())
                            .as("a cloud-metadata address is exactly what the opt-out lets through")
                            .isTrue();
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
        // The details carry a fixed reason and the exception TYPE (its full name — a simple
        // name is empty for anonymous classes) — never the message, whose content is the
        // signer's own diagnostic and belongs in the log, not the health payload (see
        // healthIndicatorNeverRepublishesTheSignerExceptionMessage below).
        keyedRunner().withUserConfiguration(FailingSignerConfiguration.class).run(context -> {
            Health health = context.getBean(Push2uHealthIndicator.class).health();
            assertThat(health.getStatus()).isEqualTo(Status.DOWN);
            assertThat(health.getDetails())
                    .containsEntry("reason", "signer probe failed")
                    .containsEntry("error", IllegalStateException.class.getName());
        });
    }

    @Test
    void healthIndicatorReportsDownWhenTheSignerFailsWithoutAMessage() {
        keyedRunner()
                .withUserConfiguration(MessagelessFailingSignerConfiguration.class)
                .run(context -> {
                    // The details are built from the exception type alone, so a messageless
                    // exception must report exactly like one with a message — this pins that no
                    // code path reaches for getMessage(), whose null Health.Builder.withDetail
                    // would reject, making health() throw precisely when the signer is broken.
                    Health health = context.getBean(Push2uHealthIndicator.class).health();
                    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
                    assertThat(health.getDetails()).containsEntry("error", IllegalStateException.class.getName());
                });
    }

    @Test
    void healthIndicatorNeverRepublishesTheSignerExceptionMessage() {
        // Signer exception messages embed internal detail by design — the Vault address, mount
        // and key name, and up to 2 KiB of Vault response body. Health details are served to
        // whoever can reach the endpoint once show-details is opened up (show-details: always
        // is common), so the message must never enter the payload — only a fixed reason and
        // the exception type.
        keyedRunner().withUserConfiguration(LeakingSignerConfiguration.class).run(context -> {
            Health health = context.getBean(Push2uHealthIndicator.class).health();
            assertThat(health.getStatus()).isEqualTo(Status.DOWN);
            assertThat(health.getDetails().values())
                    .allSatisfy(value -> assertThat(String.valueOf(value))
                            .doesNotContain("hvs.SECRET-TOKEN-MARKER")
                            .doesNotContain("vault.internal"));
        });
    }

    @Test
    void healthIndicatorNamesTheExceptionEvenWhenItsClassIsAnonymous() {
        // getSimpleName() of an anonymous class is the empty string — an "error": "" detail
        // names nothing. getName() always names something and leaks nothing a simple name
        // would not.
        keyedRunner()
                .withUserConfiguration(AnonymousFailingSignerConfiguration.class)
                .run(context -> {
                    Health health = context.getBean(Push2uHealthIndicator.class).health();
                    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
                    assertThat(String.valueOf(health.getDetails().get("error"))).isNotBlank();
                });
    }

    @Test
    void healthIndicatorCanBeDisabledByProperty() {
        // The operator's escape hatch for deployments that must not tie health to the signer at
        // all: the indicator is not registered, so no health evaluation can ever reach the signer
        // backend — while the sender itself stays wired.
        keyedRunner().withPropertyValues("push2u.health.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
            assertThat(context).hasSingleBean(PushSender.class);
        });
    }

    @Test
    void negativeHealthCacheTtlFailsTheContextNamingTheProperty() {
        // Same convention as push2u.record-size: the indicator's own validation message cannot
        // know the YAML property, so the autoconfiguration re-throws with the property prefixed.
        keyedRunner().withPropertyValues("push2u.health.cache-ttl=-1s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.health.cache-ttl:"))
                    .hasMessageContaining("push2u.health.cache-ttl:")
                    .hasMessageContaining("negative");
        });
    }

    @Test
    void livenessGroupDoesNotIncludeThePush2uIndicator() {
        // Liveness failures restart containers, and no container restart fixes an unreachable
        // Vault — so the signer probe must never gate liveness. This wires up the real health
        // endpoint machinery with Kubernetes-style probes enabled and asserts on the actual
        // group membership Boot computes: the indicator is registered (under the conventional
        // contributor name "push2u", the bean name minus the HealthIndicator suffix) and belongs
        // to the primary health group, but neither the liveness nor the readiness group — those
        // contain only the application's own availability states unless an operator explicitly
        // opts contributors in via management.endpoint.health.group.*.
        keyedRunner()
                .withConfiguration(AutoConfigurations.of(
                        ApplicationAvailabilityAutoConfiguration.class,
                        AvailabilityHealthContributorAutoConfiguration.class,
                        HealthContributorRegistryAutoConfiguration.class,
                        HealthEndpointAutoConfiguration.class,
                        AvailabilityProbesAutoConfiguration.class))
                .withPropertyValues("management.endpoint.health.probes.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
                    // The name the groups are asked about must be the name the indicator is
                    // actually registered under — assert it, or the isMember checks below could
                    // pass vacuously for a name that exists nowhere.
                    HealthContributorRegistry registry = context.getBean(HealthContributorRegistry.class);
                    assertThat(registry.getContributor("push2u")).isNotNull();

                    HealthEndpointGroups groups = context.getBean(HealthEndpointGroups.class);
                    assertThat(groups.getNames()).contains("liveness", "readiness");
                    HealthEndpointGroup liveness = Objects.requireNonNull(groups.get("liveness"));
                    HealthEndpointGroup readiness = Objects.requireNonNull(groups.get("readiness"));
                    assertThat(liveness.isMember("push2u"))
                            .as("liveness must not depend on the signer backend")
                            .isFalse();
                    assertThat(liveness.isMember("livenessState")).isTrue();
                    assertThat(readiness.isMember("push2u")).isFalse();
                    assertThat(groups.getPrimary().isMember("push2u")).isTrue();
                });
    }

    @Test
    void healthIndicatorLogsTheFullFailureOnTransitionNotOnEveryProbe() {
        // Kubernetes-style probes evaluate health every few seconds. The full exception (whose
        // message belongs in the log, not the payload) must be logged at WARN once, on the
        // transition into failure — not re-traced on every probe for the whole duration of an
        // outage. Asserted on the JUL records behind Spring's commons-logging (the backend on
        // this test classpath — no SLF4J binding is present, and JUL's ConsoleHandler holds the
        // original stderr, which is why OutputCapture cannot see it).
        //
        // cache-ttl is set to 0s so every health() call really probes the signer: the transition
        // logic must hold on its own, without the result cache masking repeated probes — and this
        // doubles as the pin that 0s means "no caching", failures included.
        java.util.logging.Logger julLogger = java.util.logging.Logger.getLogger(Push2uHealthIndicator.class.getName());
        List<LogRecord> records = new CopyOnWriteArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord logRecord) {
                records.add(logRecord);
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        Level originalLevel = julLogger.getLevel();
        julLogger.addHandler(handler);
        julLogger.setLevel(Level.ALL);
        try {
            keyedRunner()
                    .withPropertyValues("push2u.health.cache-ttl=0s")
                    .withUserConfiguration(FailingSignerConfiguration.class)
                    .run(context -> {
                        Push2uHealthIndicator indicator = context.getBean(Push2uHealthIndicator.class);
                        indicator.health();
                        indicator.health();
                        indicator.health();
                        assertThat(records)
                                .filteredOn(logRecord -> logRecord.getLevel().intValue() >= Level.WARNING.intValue())
                                .as("the full exception is logged loudly exactly once, on the transition")
                                .hasSize(1)
                                .allSatisfy(logRecord ->
                                        assertThat(logRecord.getThrown()).hasMessage("signer backend unavailable"));
                        // The two later probes really ran (cache-ttl 0s disabled the cache) and
                        // each degraded to DEBUG — JUL FINE — instead of re-tracing at WARN.
                        assertThat(records)
                                .filteredOn(logRecord -> logRecord.getLevel().equals(Level.FINE))
                                .as("while the failure persists, each re-probe logs at DEBUG")
                                .hasSize(2);
                    });
        } finally {
            julLogger.removeHandler(handler);
            julLogger.setLevel(originalLevel);
        }
    }

    /**
     * The minimum a context needs to wire a sender: keys, subject and an endpoint policy. The allowlist matches
     * {@link #subscription()}'s origin, so a send through a sender built from this runner is delivered rather than
     * rejected.
     */
    private ApplicationContextRunner keyedRunner() {
        return keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=https://push.example.test");
    }

    /** Keys and subject only — for the cases that supply the endpoint policy themselves, or deliberately omit it. */
    private ApplicationContextRunner keyedRunnerWithoutEndpointPolicy() {
        return runner.withPropertyValues(
                "push2u.vapid.public-key=" + publicKeyB64,
                "push2u.vapid.private-key=" + privateKeyB64,
                "push2u.vapid.subject=mailto:admin@example.com");
    }

    /** A well-formed subscription unrelated to the VAPID key pair under test. */
    private static Subscription subscription() {
        return subscription("https://push.example.test/send/abc");
    }

    /** The same, on a caller-chosen endpoint — for the cases where the endpoint is what is under test. */
    private static Subscription subscription(String endpoint) {
        return Subscription.fromBase64(
                endpoint,
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

    /** An application-supplied policy that rejects everything, distinguishable by its message. */
    @Configuration(proxyBeanMethods = false)
    static class RejectingPolicyConfiguration {

        @Bean
        EndpointPolicy rejectingPolicy() {
            return endpoint -> {
                throw new EndpointRejectedException("application policy rejects all endpoints");
            };
        }
    }

    /** The named opt-out, supplied the only way Spring offers it: as an application bean. */
    @Configuration(proxyBeanMethods = false)
    static class UnrestrictedPolicyConfiguration {

        @Bean
        EndpointPolicy unrestrictedPolicy() {
            return EndpointPolicies.unrestricted();
        }
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

        static final PushSender SENDER = PushSender.builder(
                        new VapidSigner() {
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
                        },
                        "mailto:ops@example.com",
                        EndpointPolicies.allowedOrigins("https://push.example.test"))
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

    /** A signer failing with an anonymous exception class, whose {@code getSimpleName()} is empty. */
    @Configuration(proxyBeanMethods = false)
    static class AnonymousFailingSignerConfiguration {

        @Bean
        VapidSigner anonymousFailingSigner() {
            return new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    throw new RuntimeException("anonymous failure") {};
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

    @Configuration(proxyBeanMethods = false)
    static class MessagelessFailingSignerConfiguration {

        @Bean
        VapidSigner failingSigner() {
            return new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    // No message — Health.Builder rejects a null detail value, so the indicator
                    // must not pass getMessage() through unguarded.
                    throw new IllegalStateException();
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

    /** A signer whose failure message carries the internals a remote signer's genuinely would. */
    @Configuration(proxyBeanMethods = false)
    static class LeakingSignerConfiguration {

        @Bean
        VapidSigner leakingSigner() {
            return new VapidSigner() {
                @Override
                public byte[] sign(byte[] signingInput) {
                    throw new IllegalStateException("Vault Transit sign failed: HTTP 403 — "
                            + "POST http://vault.internal:8200/v1/transit/sign/vapid "
                            + "(token hvs.SECRET-TOKEN-MARKER)");
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
