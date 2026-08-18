/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
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
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.the13haven.push2u.EndpointPolicies;
import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.EndpointRejectedException;
import com.the13haven.push2u.LocalEcVapidSigner;
import com.the13haven.push2u.PushHttpClient;
import com.the13haven.push2u.PushMessage;
import com.the13haven.push2u.PushOutcome;
import com.the13haven.push2u.PushResponse;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.Subscription;
import com.the13haven.push2u.VapidKeys;
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

    // The full starter composition, exactly as the imports file ships it. The removed-properties
    // tombstone rides along so every scenario here also proves that a context without the removed
    // key starts exactly as before its check existed; the endpoint-policy autoconfiguration rides
    // along so every sender wired here takes its policy from the bean, the way a real context does
    // — and so the refusals that stayed with pushSender demonstrably fire with the policy
    // autoconfiguration PRESENT, rather than being satisfied by the starter's own bean.
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    Push2uAutoConfiguration.class,
                    Push2uEndpointPolicyAutoConfiguration.class,
                    Push2uHealthAutoConfiguration.class,
                    Push2uStartupChecksAutoConfiguration.class));

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
    void withoutKeysAndWithTheStatementThereIsNoSenderOrSigner() {
        // A deployment that says it does not send holds neither, and starts. This used to be the
        // behaviour of a context that simply configured nothing, and that is exactly what changed:
        // the absence of a sender no longer passes for a decision, so the deployment states it.
        runner.withPropertyValues("push2u.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(PushSender.class);
            assertThat(context).doesNotHaveBean(VapidSigner.class);
            assertThat(context).doesNotHaveBean(PushHttpClient.class);
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
        // exercises the reason the health autoconfiguration carries its own
        // @EnableConfigurationProperties: without it, management.health.push2u.* would not bind in
        // this context.
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
    void maxEncryptedBodyBytesReachesTheSender() {
        // The one size property is an optional pass-through to the builder; assert it is not
        // silently dropped by sending a payload that only fits under the raised ceiling. A stub
        // transport stands in for the network — the point under test is the size precondition, not
        // delivery. One property is the whole of raising the limit: the record size is derived
        // from it, so there is no second key to raise in step.
        keyedRunner()
                .withPropertyValues("push2u.max-encrypted-body-bytes=8192")
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(PushSender.class);
                    PushSender sender = context.getBean(PushSender.class);
                    // 4096 plaintext bytes: rejected by the PushSender default (body cap 4096 ->
                    // 3993 max plaintext) but accepted once max-encrypted-body-bytes is raised,
                    // proving the property actually reached the builder.
                    PushOutcome result = sender.send(
                            subscription(), PushMessage.builder(new byte[4096]).build());
                    assertThat(result).isInstanceOf(PushOutcome.Accepted.class);
                });
    }

    @Test
    void defaultLimitsRejectAPayloadThatOnlyFitsUnderTheRaisedOnes() {
        // Control for the previous test: without raising the properties, the same 4096-byte
        // payload must be rejected by PushSender's own default limits, before any network call —
        // reported as the PayloadRejected outcome in plaintext octets, with the maximum the
        // default configuration carries.
        keyedRunner().run(context -> {
            PushSender sender = context.getBean(PushSender.class);
            PushOutcome outcome = sender.send(
                    subscription(), PushMessage.builder(new byte[4096]).build());
            assertThat(outcome).isEqualTo(new PushOutcome.PayloadRejected(4096, 3993));
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
    void invalidMaxEncryptedBodyBytesFailsTheContextNamingTheProperty() {
        // The builder's own message names its camelCase parameter ("maxEncryptedBodyBytes"), not
        // the YAML property — the starter re-throws with push2u.max-encrypted-body-bytes prefixed
        // so the failure is actionable. That re-thrown IllegalArgumentException wraps the builder's
        // original as its cause, so rootCause() would find the unprefixed message instead; and
        // Spring's own BeanCreationException.getMessage() happens to *echo* the wrapped text too,
        // so a plain "any message in the chain contains the needle" search would match that wrapper
        // instead of the actual exception. firstOfTypeContaining requires both the exact exception
        // type and the message, landing on the starter's own IllegalArgumentException specifically.
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
        // Same convention as push2u.max-encrypted-body-bytes: PushSender.Builder#jwtExpiry's own
        // message names its camelCase parameter ("jwtExpiry"), not the YAML property.
        keyedRunner().withPropertyValues("push2u.jwt-expiry=25h").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.jwt-expiry:"))
                    .hasMessageContaining("push2u.jwt-expiry:")
                    .hasMessageContaining("jwtExpiry must be > 0 and <= 24h");
        });
    }

    @Test
    void invalidJwtRenewBeforeFailsTheContextNamingTheProperty() {
        keyedRunner().withPropertyValues("push2u.jwt-renew-before=-1s").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.jwt-renew-before:"))
                    .hasMessageContaining("push2u.jwt-renew-before:")
                    .hasMessageContaining("jwtRenewBefore must not be negative");
        });
    }

    @Test
    void invalidJwtCacheSizeFailsTheContextNamingTheProperty() {
        // Zero is the value an operator reaches for meaning "cache nothing" — the core refuses it
        // and says so, because push2u.jwt-reuse is the switch and a cache bound is not a second
        // spelling of it. The starter's job is only to put the YAML key in front of that message.
        keyedRunner().withPropertyValues("push2u.jwt-cache-size=0").run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalArgumentException.class, "push2u.jwt-cache-size:"))
                    .hasMessageContaining("push2u.jwt-cache-size:")
                    .hasMessageContaining("jwtCacheSize must be at least 1")
                    .as("the core's message points at the declared off switch; the prefix must not truncate it")
                    .hasMessageContaining("jwtReuse(false)");
        });
    }

    @Test
    void tokenReuseIsOnByDefaultSoOneOriginCostsOneSignature() {
        // No push2u.jwt-* property set at all: the sender's own default (reuse on) must survive the
        // starter, which is exactly what leaving the properties nullable buys — the default lives in
        // one place. Two sends to one origin, one signature.
        CountingSigner signer = countingSigner();
        keyedRunner()
                .withBean(VapidSigner.class, () -> signer)
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    sendTwice(sender);
                    assertThat(signer.signOperations()).isEqualTo(1);
                });
    }

    @Test
    void jwtReuseFalseSignsEverySend() {
        // The declared off switch, and the property whose name nothing but this test pins.
        CountingSigner signer = countingSigner();
        keyedRunner()
                .withPropertyValues("push2u.jwt-reuse=false")
                .withBean(VapidSigner.class, () -> signer)
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PushSender sender = context.getBean(PushSender.class);
                    sendTwice(sender);
                    assertThat(signer.signOperations())
                            .as("with reuse off every send builds and signs a fresh token")
                            .isEqualTo(2);
                });
    }

    @Test
    void aJwtRenewBeforeAtTheTokensWholeLifeStartsCleanlyAndSignsEverySend() {
        // The margin has swallowed the token's whole life, so nothing is ever worth caching. That is
        // a consequence of the configuration and never an error: the context must start, and it is
        // deliberately not cross-validated against push2u.jwt-expiry. It doubles as the proof that
        // push2u.jwt-renew-before reached the builder — at the default 5m margin the same two sends
        // cost one signature (the test above).
        CountingSigner signer = countingSigner();
        keyedRunner()
                .withPropertyValues("push2u.jwt-expiry=12h", "push2u.jwt-renew-before=12h")
                .withBean(VapidSigner.class, () -> signer)
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PushSender sender = context.getBean(PushSender.class);
                    sendTwice(sender);
                    assertThat(signer.signOperations()).isEqualTo(2);
                });
    }

    @Test
    void aZeroJwtRenewBeforeStartsCleanlyAndIsNotAnOffSwitch() {
        // Zero margin is the MOST reuse — hold the token to its last second — not "reuse nothing".
        // An operator reaching for it as a switch must get reuse, not a rejection and not a fresh
        // signature per send.
        CountingSigner signer = countingSigner();
        keyedRunner()
                .withPropertyValues("push2u.jwt-renew-before=0s")
                .withBean(VapidSigner.class, () -> signer)
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PushSender sender = context.getBean(PushSender.class);
                    sendTwice(sender);
                    assertThat(signer.signOperations()).isEqualTo(1);
                });
    }

    @Test
    void jwtCacheSizeBoundsHowManyOriginsAreHeldAtOnce() {
        // Two origins, alternating, four sends. At the default bound both entries survive and the
        // sender signs twice; bounded at one entry, each send evicts the other origin's token and
        // every send signs — which is what a full cache costs, never a refused delivery.
        CountingSigner atDefault = countingSigner();
        twoOriginRunner()
                .withBean(VapidSigner.class, () -> atDefault)
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    alternateBetweenTwoOrigins(context.getBean(PushSender.class));
                    assertThat(atDefault.signOperations()).isEqualTo(2);
                });

        CountingSigner boundedToOne = countingSigner();
        twoOriginRunner()
                .withPropertyValues("push2u.jwt-cache-size=1")
                .withBean(VapidSigner.class, () -> boundedToOne)
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    alternateBetweenTwoOrigins(context.getBean(PushSender.class));
                    assertThat(boundedToOne.signOperations())
                            .as("a cache holding one entry evicts the other origin on every send")
                            .isEqualTo(4);
                });
    }

    @Test
    void theCachedVapidTokenNeverReachesTheHealthIndicatorDetails() {
        // The cached Authorization header is a bearer credential: it authenticates this application
        // server to the push service for the rest of the token's life, so it must not surface on any
        // observable surface. The health payload is the one such surface in this module — served to
        // whoever can reach the endpoint once show-details is opened up, which `always` commonly is.
        //
        // The indicator is given the signer, never the sender, so it has no reference through which
        // it could reach the cache at all. That is the answer, and it is pinned here rather than
        // argued: the assertion is over the payload an operator actually sees, in both of its
        // states, with a token demonstrably sitting in the sender's cache while they are produced.
        CountingSigner signer = countingSigner();
        RecordingTransport transport = new RecordingTransport();
        keyedRunner()
                .withPropertyValues("management.health.push2u.cache-ttl=0s")
                .withBean(VapidSigner.class, () -> signer)
                .withBean(PushHttpClient.class, () -> transport)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    sendTwice(sender);
                    String header = transport.authorizations.get(0);
                    assertThat(transport.authorizations)
                            .as("the second send was served from the cache, so a token is resident")
                            .containsExactly(header, header);
                    // The header is "vapid t=<jwt>, k=<public key>": the credential is the JWT, and
                    // its signature is the part no assertion on a prefix could catch.
                    String jwt = header.substring(header.indexOf("t=") + 2, header.indexOf(", k="));
                    String signature = jwt.substring(jwt.lastIndexOf('.') + 1);

                    Push2uHealthIndicator indicator = context.getBean(Push2uHealthIndicator.class);
                    Health up = indicator.health();
                    assertThat(up.getStatus()).isEqualTo(Status.UP);
                    // ...and again with the probe failing, which is the payload that carries values
                    // derived from an exception rather than fixed strings.
                    signer.failing.set(true);
                    Health down = indicator.health();
                    assertThat(down.getStatus()).isEqualTo(Status.DOWN);

                    for (Health health : List.of(up, down)) {
                        assertThat(health.getDetails().toString())
                                .doesNotContain(header)
                                .doesNotContain(jwt)
                                .doesNotContain(signature);
                    }
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
    void allowedOriginsPropertyEnforcesThePolicyOnTheWiredSender() {
        // Positive and negative halves of the same property: the allowlisted origin is accepted
        // (through the stub transport), a foreign one is refused before any transport call —
        // proving push2u.allowed-origins actually governs the wired sender, now that it travels
        // through the published policy bean rather than being built inside pushSender.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    PushOutcome result = sender.send(
                            subscription(), PushMessage.builder(new byte[1]).build());
                    assertThat(result).isInstanceOf(PushOutcome.Accepted.class);
                });
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=https://other.example")
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    assertThat(sender.send(
                                    subscription(),
                                    PushMessage.builder(new byte[1]).build()))
                            .isInstanceOf(PushOutcome.EndpointRejected.class);
                });
    }

    @Test
    void allowedDomainsPropertyEnforcesThePolicyOnTheWiredSender() {
        // The property whose whole point is that it is wider than an origin: a subdomain of the
        // configured zone is delivered to...
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-domains=notify.windows.com")
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    PushOutcome result = sender.send(
                            subscription("https://wns2-ln2p.notify.windows.com/w/?token=abc"),
                            PushMessage.builder(new byte[1]).build());
                    assertThat(result)
                            .as("a domain rule admits every subdomain at any depth, which is why it exists")
                            .isInstanceOf(PushOutcome.Accepted.class);
                });
        // ...while a host that merely ends with the configured text, with no label boundary in
        // front of it, is not. That single missing dot is the vulnerability class this feature
        // exists to keep out of every consumer's hand-written policy, so it is pinned through the
        // starter as well as in core.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-domains=notify.windows.com")
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    assertThat(sender.send(
                                    subscription("https://evilnotify.windows.com/w/?token=abc"),
                                    PushMessage.builder(new byte[1]).build()))
                            .isInstanceOf(PushOutcome.EndpointRejected.class);
                });
    }

    @Test
    void allowedDomainsAloneIsEnoughOfADecision() {
        // Origins unset entirely: a deployment serving only a zone-published service configures
        // one key and nothing else, and the context must start rather than demand the sibling.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-domains=notify.windows.com")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PushSender.class);
                    assertThat(context.getBean(Push2uProperties.class).allowedOrigins())
                            .as("the sibling property really was unset")
                            .isNull();
                });
    }

    @Test
    void bothAllowlistPropertiesAreUnionedIntoOneAllowlist() {
        // The two properties are halves of one statement, not rival settings: three exact origins
        // beside one zone is the ordinary cross-browser configuration. Each kind must match through
        // the wired sender — a union built from only one of the lists would still pass a test that
        // exercised that list alone.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues(
                        "push2u.allowed-origins=https://fcm.googleapis.com,https://updates.push.services.mozilla.com,"
                                + "https://push.example.test",
                        "push2u.allowed-domains=notify.windows.com")
                .withUserConfiguration(StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PushSender sender = context.getBean(PushSender.class);
                    for (String endpoint : new String[] {
                        "https://fcm.googleapis.com/fcm/send/abc",
                        "https://updates.push.services.mozilla.com/wpush/v2/abc",
                        "https://push.example.test/send/abc",
                        "https://wns2-ln2p.notify.windows.com/w/?token=abc"
                    }) {
                        assertThat(sender.send(
                                        subscription(endpoint),
                                        PushMessage.builder(new byte[1]).build()))
                                .as(endpoint)
                                .isInstanceOf(PushOutcome.Accepted.class);
                    }
                    assertThat(sender.send(
                                    subscription("https://other.example/send/abc"),
                                    PushMessage.builder(new byte[1]).build()))
                            .as("the union is still an allowlist")
                            .isInstanceOf(PushOutcome.EndpointRejected.class);
                });
    }

    @Test
    void anApplicationEndpointPolicyBeanReachesTheWiredSender() {
        keyedRunnerWithoutEndpointPolicy()
                .withUserConfiguration(RejectingPolicyConfiguration.class, StubHttpClientConfiguration.class)
                .run(context -> {
                    PushSender sender = context.getBean(PushSender.class);
                    PushOutcome outcome = sender.send(
                            subscription(), PushMessage.builder(new byte[1]).build());
                    assertThat(outcome).isInstanceOf(PushOutcome.EndpointRejected.class);
                    assertThat(((PushOutcome.EndpointRejected) outcome).reason())
                            .contains("application policy");
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
                    PushOutcome outcome = sender.send(
                            subscription(), PushMessage.builder(new byte[1]).build());
                    assertThat(outcome)
                            .as("the bean's policy is in force, not no-policy")
                            .isInstanceOf(PushOutcome.EndpointRejected.class);
                    assertThat(((PushOutcome.EndpointRejected) outcome).reason())
                            .contains("application policy");
                });
    }

    @Test
    void bothAllowlistPropertiesEmptyBesideAPolicyBeanCedeToTheBean() {
        // The escape hatch is per property, so a service that inherits both keys empties both and
        // still gets its bean rather than a startup failure.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=", "push2u.allowed-domains=")
                .withUserConfiguration(RejectingPolicyConfiguration.class, StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PushSender sender = context.getBean(PushSender.class);
                    PushOutcome outcome = sender.send(
                            subscription(), PushMessage.builder(new byte[1]).build());
                    assertThat(outcome)
                            .as("the bean's policy is in force, not no-policy")
                            .isInstanceOf(PushOutcome.EndpointRejected.class);
                    assertThat(((PushOutcome.EndpointRejected) outcome).reason())
                            .contains("application policy");
                });
    }

    @Test
    void everyConfiguredAllowlistEmptyWithNoBeanFailsWithTheStartersOwnMessage() {
        // The guard on the escape hatch: emptying a property only cedes to a bean. With no bean it
        // stays an error, so the SSRF control cannot be silently disabled by an empty value.
        //
        // The message is the STARTER's and names both keys, rather than being delegated to whichever
        // core factory happens to run: with two properties the emptiness is a fact about the pair,
        // and "allowedOrigins requires at least one origin" would describe half the configuration
        // while the operator's mistake may be in the other half. IllegalStateException for the same
        // reason as the neither-case beside it — this is a statement about the state of the
        // configuration, not about a bad value in it.
        //
        // The endpoint-policy autoconfiguration is in this context and must not change the answer:
        // its bean's condition is an allowlist with at least one ENTRY, so an emptied pair
        // contributes no bean, and this refusal still reaches the operator instead of being
        // satisfied by a policy the starter never should have built.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=", "push2u.allowed-domains=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(), IllegalStateException.class, "push2u.allowed-origins"))
                            .hasMessageContaining("push2u.allowed-domains")
                            .as("the emptiness case, not the never-decided one beside it")
                            .hasMessageContaining("has an entry")
                            .hasMessageContaining("cede");
                });
    }

    @Test
    void oneEmptyAllowlistPropertyAloneStillFailsTheContext() {
        // Emptying one key while never setting the other is the same statement as emptying both:
        // nothing is expressed and there is no bean to cede to. It must not fall through to the
        // unset case, whose message says the properties are "not set" — which would be untrue of
        // the one the operator did write.
        keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-domains=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(), IllegalStateException.class, "push2u.allowed-domains"))
                            .hasMessageContaining("has an entry");
                });
    }

    @Test
    void neitherPropertyNorAPolicyBeanFailsTheContextNamingThreeWaysToFixIt() {
        // The decision has to be expressed: a sender wired with no endpoint policy would POST
        // wherever a subscription's endpoint points, and a subscription registered by a client is
        // attacker-influenced. The failure has to be actionable in every direction, so it names all
        // three ways to answer — both properties and the bean, including the deliberate opt-out,
        // which exists only as a bean.
        //
        // The endpoint-policy autoconfiguration is in this context: with nothing expressed it
        // contributes no bean, so the sender's obligation refusal still fires rather than being
        // quietly satisfied by a starter-built policy.
        keyedRunnerWithoutEndpointPolicy().run(context -> {
            assertThat(context).hasFailed();
            assertThat(firstOfTypeContaining(
                            context.getStartupFailure(), IllegalStateException.class, "push2u.allowed-origins"))
                    .as("the never-decided case, not the emptiness one beside it")
                    .hasMessageContaining("nor push2u.allowed-domains is set")
                    .as("all three ways to decide")
                    .hasMessageContaining("EndpointPolicy bean")
                    .hasMessageContaining("EndpointPolicies.unrestricted()");
        });
    }

    @Test
    void expressedAllowlistWithoutThePolicyAutoConfigurationFailsNamingIt() {
        // The sender no longer builds the policy from the properties: the allowlist is one
        // definition, published as a bean so the code accepting subscriptions reads the same rule
        // the sender enforces, and a second construction inside pushSender would be a second place
        // that rule is stated. So a context that excludes the policy autoconfiguration while
        // expressing an allowlist gets a refusal naming what is missing, not a silently rebuilt
        // policy the rest of the context cannot see.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Push2uAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.public-key=" + publicKeyB64,
                        "push2u.vapid.private-key=" + privateKeyB64,
                        "push2u.vapid.subject=mailto:admin@example.com",
                        "push2u.allowed-origins=https://push.example.test")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(),
                                    IllegalStateException.class,
                                    "Push2uEndpointPolicyAutoConfiguration"))
                            .hasMessageContaining("push2u.allowed-origins")
                            .as("the property that is actually non-empty, not a slash-joined pair")
                            .hasMessageNotContaining("push2u.allowed-domains")
                            .hasMessageContaining("no EndpointPolicy bean");
                });
    }

    @Test
    void anExpressedDomainsAllowlistWithoutThePolicyAutoConfigurationNamesThatProperty() {
        // The mirror of the case above, and the reason that branch names a property at all: with
        // two allowlist keys, a refusal naming the wrong one sends the operator to the half of the
        // configuration they never wrote. Domains is the half a deployment reaches for when the
        // service operator documents varying hostnames rather than one origin.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Push2uAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.public-key=" + publicKeyB64,
                        "push2u.vapid.private-key=" + privateKeyB64,
                        "push2u.vapid.subject=mailto:admin@example.com",
                        "push2u.allowed-domains=notify.windows.com")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(),
                                    IllegalStateException.class,
                                    "Push2uEndpointPolicyAutoConfiguration"))
                            .hasMessageContaining("push2u.allowed-domains is non-empty")
                            .as("the property that is actually non-empty, not its neighbour")
                            .hasMessageNotContaining("push2u.allowed-origins")
                            .hasMessageContaining("no EndpointPolicy bean");
                });
    }

    @Test
    void bothAllowlistPropertiesWithoutThePolicyAutoConfigurationNameBoth() {
        // The plural branch of the same refusal. Naming which property was expressed is the whole
        // point of it, so with both non-empty the answer has to be both: an operator told about one
        // of them would move that one into a bean, restart, and meet the refusal again over the
        // other.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Push2uAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.public-key=" + publicKeyB64,
                        "push2u.vapid.private-key=" + privateKeyB64,
                        "push2u.vapid.subject=mailto:admin@example.com",
                        "push2u.allowed-origins=https://push.example.test",
                        "push2u.allowed-domains=notify.windows.com")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(),
                                    IllegalStateException.class,
                                    "Push2uEndpointPolicyAutoConfiguration"))
                            .hasMessageContaining("push2u.allowed-origins and push2u.allowed-domains are non-empty")
                            .hasMessageContaining("no EndpointPolicy bean");
                });
    }

    @Test
    void theContradictionSurvivesExcludingThePolicyAutoConfigurationWithASenderConfigured() {
        // The configuration that must not boot green: a fully configured sender, a non-empty
        // allowlist property, an application EndpointPolicy bean, and the policy bean's
        // auto-configuration excluded — the framework's standard tool, and the natural next move
        // for an operator who just met the contradiction refusal. The check lives in a class of
        // its own precisely so this exclusion removes only the bean: the contradiction still fails
        // the context, naming the property and the bean, instead of the sender quietly enforcing
        // the application bean while push2u.allowed-origins is read by nothing.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        Push2uAutoConfiguration.class,
                        Push2uHealthAutoConfiguration.class,
                        Push2uStartupChecksAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.public-key=" + publicKeyB64,
                        "push2u.vapid.private-key=" + privateKeyB64,
                        "push2u.vapid.subject=mailto:admin@example.com",
                        "push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.allowed-origins")
                            .hasMessageContaining("'rejectingPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
    }

    @Test
    void excludingTheChecksAutoConfigurationIsTheOneRouteAroundTheContradiction() {
        // The declared residual, pinned so it stays declared: excluding the auto-configuration
        // whose name says "startup checks" is a deliberate, visible act of switching those checks
        // off, and it is the only route by which a non-empty allowlist boots beside an application
        // bean. The context starts and the sender enforces the application bean. This also pins
        // that the contradiction has exactly ONE implementation — a second guard left inside
        // pushSender would fail this context, and two implementations of one refusal is the drift
        // the whole arrangement exists to prevent.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        Push2uAutoConfiguration.class,
                        Push2uEndpointPolicyAutoConfiguration.class,
                        Push2uHealthAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.public-key=" + publicKeyB64,
                        "push2u.vapid.private-key=" + privateKeyB64,
                        "push2u.vapid.subject=mailto:admin@example.com",
                        "push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(RejectingPolicyConfiguration.class, StubHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PushSender sender = context.getBean(PushSender.class);
                    PushOutcome outcome = sender.send(
                            subscription(), PushMessage.builder(new byte[1]).build());
                    assertThat(outcome).isInstanceOf(PushOutcome.EndpointRejected.class);
                    assertThat(((PushOutcome.EndpointRejected) outcome).reason())
                            .as("the application bean is what the sender enforces")
                            .contains("application policy");
                });
    }

    @Test
    void theSenderEnforcesTheSameDefinitionThePolicyBeanCarries() {
        // One rule, one definition: what the registration boundary refuses through the bean and
        // what the sender refuses on a send must be the same answer, because the sender reads the
        // bean rather than building a second policy from the same properties. Behaviour, not
        // identity — the wiring is a security control, so the assertion is that a non-allowlisted
        // endpoint is actually refused at both points.
        keyedRunner().withUserConfiguration(StubHttpClientConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(EndpointPolicy.class);
            EndpointPolicy policy = context.getBean(EndpointPolicy.class);
            URI foreign = URI.create("https://other.example/send/abc");
            assertThatExceptionOfType(EndpointRejectedException.class)
                    .as("the boundary's answer, through the bean")
                    .isThrownBy(() -> policy.validate(foreign));
            assertThat(context.getBean(PushSender.class)
                            .send(
                                    subscription("https://other.example/send/abc"),
                                    PushMessage.builder(new byte[1]).build()))
                    .as("the sender's answer, through the same definition")
                    .isInstanceOf(PushOutcome.EndpointRejected.class);
        });
    }

    @Test
    void anUnsetAllowlistPropertyBindsAsNullAndAnEmptyOneAsAnEmptyList() {
        // The premise every rule above rests on, and the reason neither component carries a
        // @DefaultValue: a default would make an absent key arrive as an empty list, collapsing
        // "this deployment has not decided" into "this deployment deliberately cedes to a bean" —
        // two states the starter has to answer differently, and which no other test can tell apart
        // once the binding stops distinguishing them.
        keyedRunner().run(context -> {
            Push2uProperties bound = context.getBean(Push2uProperties.class);
            assertThat(bound.allowedOrigins()).containsExactly("https://push.example.test");
            assertThat(bound.allowedDomains())
                    .as("an absent key binds as null, never as an empty list")
                    .isNull();
        });
        keyedRunner().withPropertyValues("push2u.allowed-domains=").run(context -> {
            Push2uProperties bound = context.getBean(Push2uProperties.class);
            assertThat(bound.allowedDomains())
                    .as("an explicitly empty value binds as an empty list, which is the escape hatch")
                    .isNotNull()
                    .isEmpty();
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
                    PushOutcome result = sender.send(
                            subscription("https://169.254.169.254/latest/meta-data"),
                            PushMessage.builder(new byte[1]).build());
                    assertThat(result)
                            .as("a cloud-metadata address is exactly what the opt-out lets through")
                            .isInstanceOf(PushOutcome.Accepted.class);
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
    void healthIndicatorIsRegisteredByDefault() {
        // The default this change deliberately does not move: Spring Boot's convention is that a
        // contributor is on, and neither of the two keys deciding it needs to be written for the
        // probe to exist. Stated on its own so that a regression in the condition shows up as a
        // failing default rather than only inside a test about disabling it.
        keyedRunner().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
        });
    }

    @Test
    void healthIndicatorCanBeDisabledByTheStandardProperty() {
        // The operator's escape hatch for deployments that must not tie health to the signer at
        // all: the indicator is not registered, so no health evaluation can ever reach the signer
        // backend — while the sender itself stays wired. The key is the one every Boot health
        // contributor answers to, which is the whole point of the condition being the framework's.
        keyedRunner()
                .withPropertyValues("management.health.push2u.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
                    assertThat(context).hasSingleBean(PushSender.class);
                });
    }

    @Test
    void disablingHealthIndicatorsWholesaleAlsoRemovesThePush2uOne() {
        // The behaviour the bespoke condition did not have, and the reason for the swap: a
        // deployment that turns every contributor off by default meant to turn this one off too,
        // and used to keep a probe that signs on every evaluation — against a remote signer, a real
        // audited operation per poll that nobody asked for.
        keyedRunner()
                .withPropertyValues("management.health.defaults.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
                    assertThat(context).hasSingleBean(PushSender.class);
                });
    }

    @Test
    void thePush2uKeyOutranksTheWholesaleDefault() {
        // The other half of the same contract: off by default, on by name — the shape an operator
        // uses to enumerate exactly the contributors they want. Without this, "defaults off" would
        // be a one-way door for this indicator.
        keyedRunner()
                .withPropertyValues("management.health.defaults.enabled=false", "management.health.push2u.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
                });
    }

    @Test
    void theCacheTtlPropertyReachesTheIndicator() {
        // The tuning moved to the framework's prefix with the switch, so pin that it still arrives:
        // 0s is the value whose effect is observable from outside, since it disables caching
        // entirely and every evaluation must then reach the signer. A bound-but-ignored property
        // would leave the default 30s TTL in place and collapse three probes into one signature.
        CountingSigner signer = countingSigner();
        keyedRunner()
                .withPropertyValues("management.health.push2u.cache-ttl=0s")
                .withBean(VapidSigner.class, () -> signer)
                .run(context -> {
                    Push2uHealthIndicator indicator = context.getBean(Push2uHealthIndicator.class);
                    for (int i = 0; i < 3; i++) {
                        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
                    }
                    assertThat(signer.signOperations())
                            .as("cache-ttl: 0s means every evaluation probes the signer")
                            .isEqualTo(3);
                });
    }

    @Test
    void theDefaultCacheTtlStillCollapsesRepeatedEvaluations() {
        // The control for the test above, and the behaviour that must survive the property's move:
        // with nothing configured the probe result is reused, so a burst of evaluations costs one
        // signature. Written with no property at all, which is how the default is actually met.
        CountingSigner signer = countingSigner();
        keyedRunner().withBean(VapidSigner.class, () -> signer).run(context -> {
            Push2uHealthIndicator indicator = context.getBean(Push2uHealthIndicator.class);
            for (int i = 0; i < 3; i++) {
                assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
            }
            assertThat(signer.signOperations())
                    .as("the default TTL is what keeps a polled endpoint off the signer's backend")
                    .isEqualTo(1);
        });
    }

    @Test
    void negativeHealthCacheTtlFailsTheContextNamingTheProperty() {
        // Same convention as push2u.max-encrypted-body-bytes: the indicator's own validation
        // message cannot know the YAML property, so the autoconfiguration re-throws with the
        // property prefixed — and the property it names has to be the one the operator wrote, which
        // is now the framework-prefixed key.
        keyedRunner()
                .withPropertyValues("management.health.push2u.cache-ttl=-1s")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(firstOfTypeContaining(
                                    context.getStartupFailure(),
                                    IllegalArgumentException.class,
                                    "management.health.push2u.cache-ttl:"))
                            .hasMessageContaining("management.health.push2u.cache-ttl:")
                            .hasMessageContaining("negative");
                });
    }

    @Test
    void theContributorRegistersUnderTheNameTheSwitchAndGroupsUse() {
        // Three things spell this contributor's name and only one of them is written down here: the
        // condition's argument, the property prefix its tuning binds from, and whatever a
        // deployment puts in a health group's include or exclude. The registry decides the third by
        // stripping the standard suffix from the bean name, so the bean method's name is what keeps
        // all three in step — rename it and the group entry silently names a contributor that no
        // longer exists, which fails a context that is not this one.
        keyedRunner()
                .withConfiguration(AutoConfigurations.of(HealthContributorRegistryAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
                    HealthContributorRegistry registry = context.getBean(HealthContributorRegistry.class);
                    assertThat(registry.getContributor("push2u"))
                            .as("the registered name must be the string the condition and a group both use")
                            .isSameAs(context.getBean(Push2uHealthIndicator.class));
                    assertThat(registry.getContributor("push2uHealthIndicator"))
                            .as("the bean name is not the contributor name — the suffix is stripped")
                            .isNull();
                });
    }

    @Test
    void withoutSpringBootHealthOnTheClasspathTheContextStartsWithoutTheIndicator() {
        // The starter is usable without Actuator, and the condition swap is where that could have
        // broken: the indicator's factory method now carries an annotation from spring-boot-health
        // itself. It is safe because the class-level condition is decided before the class is
        // loaded, so the method is never examined — but nothing in the code says so, and a
        // NoClassDefFoundError here would only ever appear in a consumer's application.
        keyedRunner()
                .withClassLoader(new FilteredClassLoader("org.springframework.boot.health"))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PushSender.class);
                    assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
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
                    .withPropertyValues("management.health.push2u.cache-ttl=0s")
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

    /**
     * A context whose allowlist admits two push-service origins, for the cases where more than one audience is the
     * point — the token cache is keyed by audience, so a second origin is what makes its bound observable.
     */
    private ApplicationContextRunner twoOriginRunner() {
        return keyedRunnerWithoutEndpointPolicy()
                .withPropertyValues("push2u.allowed-origins=https://push.example.test,https://other.push.example.test");
    }

    /** Two sends to one origin: the second is the one a reused token serves. */
    private static void sendTwice(PushSender sender) {
        for (int i = 0; i < 2; i++) {
            assertThat(sender.send(
                            subscription(), PushMessage.builder(new byte[1]).build()))
                    .isInstanceOf(PushOutcome.Accepted.class);
        }
    }

    /** Four sends alternating between two origins — two audiences, each visited twice. */
    private static void alternateBetweenTwoOrigins(PushSender sender) {
        for (int i = 0; i < 2; i++) {
            for (String endpoint :
                    List.of("https://push.example.test/send/abc", "https://other.push.example.test/send/abc")) {
                assertThat(sender.send(
                                subscription(endpoint),
                                PushMessage.builder(new byte[1]).build()))
                        .isInstanceOf(PushOutcome.Accepted.class);
            }
        }
    }

    /** A real local signer that counts its signatures, and can be failed for the health-probe half of a test. */
    private static CountingSigner countingSigner() {
        return new CountingSigner(new LocalEcVapidSigner(VapidKeys.fromBase64(publicKeyB64, privateKeyB64)));
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

    /**
     * A signer that counts the signatures it is asked for — the only way to observe from outside whether a token was
     * reused, since a cache hit calls {@code publicKey()} but never {@code sign()}. It can also be failed on demand,
     * for the health-probe half of the leak test.
     */
    private static final class CountingSigner implements VapidSigner {

        private final VapidSigner delegate;
        private final AtomicInteger signOperations = new AtomicInteger();
        private final AtomicBoolean failing = new AtomicBoolean();

        CountingSigner(VapidSigner delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            signOperations.incrementAndGet();
            if (failing.get()) {
                throw new IllegalStateException("signer backend unavailable");
            }
            return delegate.sign(signingInput);
        }

        @Override
        public byte[] publicKey() {
            return delegate.publicKey();
        }

        int signOperations() {
            return signOperations.get();
        }
    }

    /** Answers every POST with 201 and keeps the {@code Authorization} header each send presented. */
    private static final class RecordingTransport implements PushHttpClient {

        private final List<String> authorizations = new CopyOnWriteArrayList<>();

        @Override
        public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
            authorizations.add(headers.get("Authorization"));
            return new PushResponse(201, Map.of());
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
