/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.signer.vault.RecordingHttpClient;
import com.the13haven.push2u.signer.vault.VaultHttpResponse;
import com.the13haven.push2u.signer.vault.VaultHttpTransport;
import com.the13haven.push2u.signer.vault.VaultTransitVapidSigner;
import com.the13haven.push2u.spring.Push2uAutoConfiguration;
import com.the13haven.push2u.spring.Push2uHealthAutoConfiguration;
import com.the13haven.push2u.spring.Push2uHealthIndicator;

/**
 * {@link VaultSignerAutoConfiguration} wires a {@link VaultTransitVapidSigner} from {@code push2u.signer.vault.*},
 * outranks the core starter's local signer, and yields to an application-supplied signer. The transport extension point
 * resolves in priority order: application {@link VaultHttpTransport} bean, then a
 * {@code push2uVaultHttpClient}-qualified {@link HttpClient} wrapped with the bound transport properties, then pure
 * defaults.
 */
class VaultSignerAutoConfigurationTest {

    private static String publicKeyB64;
    private static String privateKeyB64;

    private final ApplicationContextRunner runner =
            new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(VaultSignerAutoConfiguration.class));

    @BeforeAll
    static void generateVapidKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        Base64.Encoder base64Url = Base64.getUrlEncoder().withoutPadding();
        publicKeyB64 = base64Url.encodeToString(uncompressed((ECPublicKey) keyPair.getPublic()));
        privateKeyB64 = base64Url.encodeToString(toFixed32(((ECPrivateKey) keyPair.getPrivate()).getS()));
    }

    @Test
    void wiresTheVaultSignerFromProperties() {
        vaultRunner().run(context -> {
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context.getBean(VapidSigner.class)).isInstanceOf(VaultTransitVapidSigner.class);
        });
    }

    @Test
    void absentWithoutProperties() {
        runner.run(context -> assertThat(context).doesNotHaveBean(VapidSigner.class));
    }

    @Test
    void publicKeyIsOptional_entersFetchedModeWithoutIt() {
        // With address/key-name/token but no public-key, the (relaxed) condition matches and the
        // signer is built in fetched mode — which reads the public key from Vault at construction.
        // Vault is unreachable here, so context startup fails on that fetch (contrast
        // absentWithoutProperties, which wires no bean and starts cleanly). The successful fetch is
        // covered by VaultTransitVapidSignerContractTest.
        runner.withPropertyValues(
                        "push2u.signer.vault.address=http://vault.invalid:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void aPublicKeyThatIsNotBase64urlFailsNamingTheProperty() {
        // Base64's own message ("Illegal base64 character 2c") names neither the property nor the
        // expected encoding, which leaves the operator guessing which push2u.* value is at fault.
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.public-key=not base64url!")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.public-key is not base64url");
                });
    }

    @Test
    void aKeyNameThatWouldAlterTheRequestPathFailsNamingTheProperty() {
        // TransitKeyName's own message names the constructor's viewpoint, not the YAML the
        // operator wrote — the starter prefixes the property, like every other translated failure.
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.key-name=vapid/../other")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.key-name")
                            .hasStackTraceContaining("request path");
                });
    }

    @Test
    void anInvalidTokenFailsNamingThePropertyWithoutEchoingTheValue() {
        // Translated like every other configuration failure — the message names the YAML property
        // the operator wrote — and, because VaultToken's own message carries no part of the value,
        // the translation cannot leak it either. The newline is embedded rather than trailing
        // because TestPropertyValues trims a trailing one before it ever reaches the binder — the
        // real-world trailing-newline arrival is covered by VaultTokenTest in the signer module.
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.token=secret-token-value\nsecond-line")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.token")
                            .hasStackTraceContaining("token contains a character")
                            .satisfies(
                                    failure -> assertThat(rootMessage(failure)).doesNotContain("secret-token-value"));
                });
    }

    @Test
    void anInvalidAddressFailsNamingTheProperty() {
        // The factory's own message says "address", not the YAML the operator wrote — the starter
        // translates it like every other configuration failure. '..' is the case worth pinning
        // (the path prefix rides in front of every token-bearing request path), and a query is the
        // plain-misconfiguration shape.
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.address=https://gw.example/vault/../sys")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.address")
                            .hasStackTraceContaining("'..' segment");
                });
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.address=https://vault.example:8200?ns=team-a")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.address")
                            .hasStackTraceContaining("query");
                });
    }

    @Test
    void aPathPrefixedAddressIsAccepted() {
        // Vault behind a reverse-proxy or ingress prefix is a legitimate topology; the explicit
        // mode contacts nothing at build, so acceptance alone proves the address passed the rule.
        // The joined request URIs are pinned in the signer module's own address tests.
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.address=https://gw.example/vault/")
                .run(context -> assertThat(context).hasSingleBean(VapidSigner.class));
    }

    @Test
    void anInvalidPublicKeyFailsNamingTheProperty() {
        // The supplied-key factory validates both the address and the key (the full on-curve
        // check); the starter probes the key first so each rejection is attributed to its own
        // property — this pins that a bad key is never mislabelled as a bad address.
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.public-key="
                        + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.public-key")
                            .hasStackTraceContaining("65-byte uncompressed");
                });
        // The right shape, off the curve — the VapidSigner contract requires a point on P-256,
        // so a corrupted configured key fails startup instead of drawing a push-service 401.
        byte[] offCurve = Base64.getUrlDecoder().decode(publicKeyB64);
        offCurve[64] ^= 0x01;
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.public-key="
                        + Base64.getUrlEncoder().withoutPadding().encodeToString(offCurve))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.public-key")
                            .hasStackTraceContaining("curve equation");
                });
    }

    @Test
    void aMountWithADotDotSegmentFailsNamingTheProperty() {
        // The '..' segment is the load-bearing case: a normalizing proxy in front of Vault
        // collapses it before Vault sees it, and Vault's own handler answers the decoded form
        // with a 307 redirect to the collapsed path — which a redirect-following transport would
        // re-send, X-Vault-Token included, to a different Vault path.
        vaultRunner().withPropertyValues("push2u.signer.vault.mount=../sys").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("push2u.signer.vault.mount")
                    .hasStackTraceContaining("'..' segment");
        });
    }

    @Test
    void aMountOutsideTheAllowedCharacterSetFailsNamingTheProperty() {
        // Before the allowed-set rule this value survived the mount(...) step — which the starter
        // translates — and failed later inside build(), as URI.create's raw "Malformed escape
        // pair" with no YAML property named. The step must be where it dies.
        vaultRunner().withPropertyValues("push2u.signer.vault.mount=50%off").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("push2u.signer.vault.mount")
                    .hasStackTraceContaining("allowed set");
        });
    }

    @Test
    void theNamespacePropertyReachesEveryVaultCallInFetchedMode() {
        // Observe the actual requests: the bound namespace must ride as X-Vault-Namespace on both
        // Vault calls — the startup transit/keys/<key> GET (made inside build(), the one easy to
        // miss) and the sign POST. A nested namespace doubles as the shape check.
        HeaderRecordingTransportConfiguration.CALLS.clear();
        runner.withPropertyValues(
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token",
                        "push2u.signer.vault.namespace=team-a/sub")
                .withUserConfiguration(HeaderRecordingTransportConfiguration.class)
                .run(context -> {
                    context.getBean(VapidSigner.class)
                            .sign("starter fetched namespace probe".getBytes(StandardCharsets.UTF_8));
                    assertThat(HeaderRecordingTransportConfiguration.CALLS)
                            .extracting(HeaderRecordingTransportConfiguration.RecordedCall::method)
                            .containsExactly("GET", "POST");
                    assertThat(HeaderRecordingTransportConfiguration.CALLS)
                            .allSatisfy(call -> assertThat(call.headers())
                                    .as("%s carries the bound namespace", call.method())
                                    .containsEntry("X-Vault-Namespace", "team-a/sub"));
                });
    }

    @Test
    void theNamespacePropertyReachesTheExplicitModeSignRequest() {
        // The explicit mode wires the namespace through a separate builder call in the starter —
        // this pins that second wiring site.
        HeaderRecordingTransportConfiguration.CALLS.clear();
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.namespace=team-a")
                .withUserConfiguration(HeaderRecordingTransportConfiguration.class)
                .run(context -> {
                    context.getBean(VapidSigner.class)
                            .sign("starter explicit namespace probe".getBytes(StandardCharsets.UTF_8));
                    assertThat(HeaderRecordingTransportConfiguration.CALLS)
                            .singleElement()
                            .satisfies(call -> {
                                assertThat(call.method()).isEqualTo("POST");
                                assertThat(call.headers()).containsEntry("X-Vault-Namespace", "team-a");
                            });
                });
    }

    @Test
    void withoutTheNamespacePropertyNoVaultCallCarriesTheHeader() {
        // The default must stay byte-identical to the pre-namespace behaviour: no property, no
        // X-Vault-Namespace header on any call — not an empty one, none (Vault OSS has no
        // namespaces).
        HeaderRecordingTransportConfiguration.CALLS.clear();
        runner.withPropertyValues(
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token")
                .withUserConfiguration(HeaderRecordingTransportConfiguration.class)
                .run(context -> {
                    context.getBean(VapidSigner.class)
                            .sign("starter no-namespace probe".getBytes(StandardCharsets.UTF_8));
                    assertThat(HeaderRecordingTransportConfiguration.CALLS)
                            .extracting(HeaderRecordingTransportConfiguration.RecordedCall::method)
                            .containsExactly("GET", "POST");
                    assertThat(HeaderRecordingTransportConfiguration.CALLS)
                            .allSatisfy(call -> assertThat(call.headers())
                                    .as("%s must not carry any namespace header", call.method())
                                    .doesNotContainKey("X-Vault-Namespace"));
                });
    }

    @Test
    void anInvalidNamespaceFailsStartupNamingTheProperty() {
        // The builder's own message says "namespace", not the YAML the operator wrote — the
        // starter translates it like every other configuration failure. '..' is the case worth
        // pinning: it cannot name a real namespace, so it is a configuration mistake that should
        // stop startup rather than travel.
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.namespace=../root")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining("push2u.signer.vault.namespace")
                            .hasStackTraceContaining("'..' segment");
                });
        vaultRunner().withPropertyValues("push2u.signer.vault.namespace=a|b").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("push2u.signer.vault.namespace")
                    .hasStackTraceContaining("allowed set");
        });
    }

    /** The root cause's message, where the token rejection surfaces. */
    private static String rootMessage(Throwable failure) {
        Throwable cursor = failure;
        while (cursor.getCause() != null) {
            cursor = cursor.getCause();
        }
        return String.valueOf(cursor.getMessage());
    }

    @Test
    void keyVersionPinsTheExplicitSigner() {
        // Observe the actual sign request through a recording transport: the wired signer must
        // send the configured key_version to Vault. A bean-type assertion alone would stay green
        // even if the wiring dropped the version.
        RecordingTransportConfiguration.SIGN_REQUEST_BODIES.clear();
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.key-version=3")
                .withUserConfiguration(RecordingTransportConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    byte[] signature = context.getBean(VapidSigner.class)
                            .sign("starter key-version probe".getBytes(StandardCharsets.UTF_8));
                    assertThat(signature)
                            .as("decoded raw r||s signature from the stub response")
                            .hasSize(64);
                    assertThat(RecordingTransportConfiguration.SIGN_REQUEST_BODIES)
                            .singleElement()
                            .asString()
                            .contains("\"key_version\":3");
                });
    }

    @Test
    void withoutKeyVersionTheExplicitSignerSendsNoPin() {
        // Omitting key-version is the unpinned form: no version travels in the request, so Vault
        // signs with its latest.
        RecordingTransportConfiguration.SIGN_REQUEST_BODIES.clear();
        vaultRunner()
                .withUserConfiguration(RecordingTransportConfiguration.class)
                .run(context -> {
                    context.getBean(VapidSigner.class).sign("starter no-pin probe".getBytes(StandardCharsets.UTF_8));
                    assertThat(RecordingTransportConfiguration.SIGN_REQUEST_BODIES)
                            .singleElement()
                            .asString()
                            .doesNotContain("key_version");
                });
    }

    @Test
    void keyVersionWithoutPublicKeyFailsLoudly() {
        // key-version only makes sense with an explicit public-key: the fetched mode pins the
        // version it reads from Vault itself. A stray key-version must fail startup, not be
        // silently ignored.
        runner.withPropertyValues(
                        "push2u.signer.vault.address=http://vault.invalid:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token",
                        "push2u.signer.vault.key-version=2")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining("key-version requires push2u.signer.vault.public-key");
                });
    }

    @Test
    void anApplicationSignerOverridesTheVaultOne() {
        vaultRunner().withUserConfiguration(CustomSignerConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(VapidSigner.class);
            assertThat(context.getBean(VapidSigner.class)).isSameAs(CustomSignerConfiguration.SIGNER);
        });
    }

    @Test
    void theHealthIndicatorStillAppearsWhenTheSignerIsTheVaultOne() {
        // The health indicator is @ConditionalOnBean(VapidSigner.class), and a condition sees only
        // the beans registered by the time it runs. When the only signer is the
        // Vault one, this module has to have been evaluated first, or the condition finds nothing
        // and the indicator disappears for every Vault deployment — silently, with no error to
        // notice. This pins the outcome: all three autoconfigurations together still produce it.
        //
        // What it does not pin is the beforeName on this class. Dropping it leaves the test green,
        // because the sorter falls back to class name and ...signer.vault.spring.VaultSigner...
        // happens to sort ahead of ...spring.Push2uAutoConfiguration anyway. The declaration stays
        // because relying on that coincidence would be worse than stating the order.
        //
        // No local VAPID keys here: the Vault signer is the only one, so the assertion cannot pass
        // through the core starter's fallback.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        VaultSignerAutoConfiguration.class,
                        Push2uAutoConfiguration.class,
                        Push2uHealthAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.subject=mailto:ops@example.com",
                        "push2u.signer.vault.address=http://vault.example:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token",
                        "push2u.signer.vault.public-key=" + publicKeyB64)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(VapidSigner.class)).isInstanceOf(VaultTransitVapidSigner.class);
                    assertThat(context).hasSingleBean(Push2uHealthIndicator.class);
                });
    }

    @Test
    void theVaultSignerOutranksTheCoreLocalSigner() {
        new ApplicationContextRunner()
                .withConfiguration(
                        AutoConfigurations.of(VaultSignerAutoConfiguration.class, Push2uAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.public-key=" + publicKeyB64,
                        "push2u.vapid.private-key=" + privateKeyB64,
                        "push2u.vapid.subject=mailto:admin@example.com",
                        "push2u.signer.vault.address=http://vault.example:8200",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token",
                        "push2u.signer.vault.public-key=" + publicKeyB64)
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    assertThat(context.getBean(VapidSigner.class)).isInstanceOf(VaultTransitVapidSigner.class);
                    assertThat(context).hasSingleBean(PushSender.class);
                });
    }

    // The next four tests reproduce the two Vault Spring Boot YAML examples from README.md verbatim
    // (as of the push2u.vapid.subject fix) as property values, since a test cannot literally read
    // the README. That copy is manual and can silently drift from the document — nothing here
    // fails if someone edits the README example without touching this file; treat these as a
    // targeted regression for the reported gap, not as living documentation.

    @Test
    void theReadmeExplicitPublicKeyExampleComposesIntoAWorkingSender() {
        // Regression for a README gap: the "Explicit public key" Vault Spring Boot example printed
        // only push2u.signer.vault.* until push2u.vapid.subject was added alongside it. This test
        // reproduces that exact composition (Vault properties + the core starter's subject) and
        // asserts it actually yields a usable PushSender, not just a VapidSigner bean. It covers the
        // explicit-mode example only; theReadmeFetchedPublicKeyExampleComposesIntoAWorkingSender
        // below covers the other (recommended, fetched-mode) example — the gap was in both.
        //
        // Unlike theVaultSignerOutranksTheCoreLocalSigner above, no push2u.vapid.public-key/
        // private-key are set: that test's point is precedence between two signers, this one
        // reproduces the README scenario, where no local VAPID keys exist at all.
        new ApplicationContextRunner()
                .withConfiguration(
                        AutoConfigurations.of(VaultSignerAutoConfiguration.class, Push2uAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.subject=mailto:ops@example.com",
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.mount=transit",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token",
                        "push2u.signer.vault.public-key=" + publicKeyB64,
                        "push2u.signer.vault.key-version=3")
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    assertThat(context.getBean(VapidSigner.class)).isInstanceOf(VaultTransitVapidSigner.class);
                    assertThat(context).hasSingleBean(PushSender.class);
                });
    }

    @Test
    void theReadmeFetchedPublicKeyExampleComposesIntoAWorkingSender() {
        // The other half of the same README gap: the "Fetched public key" example is the one README
        // calls recommended, so it is the one most users copy first. Fetched mode performs a startup
        // GET against transit/keys/<key>, so a stub VaultHttpTransport (an application transport bean
        // — first in the starter's transport priority order) answers it with latest_version + a PEM
        // public key, exactly as the real Vault Transit API would.
        FetchedMetadataTransportConfiguration.SIGN_REQUEST_BODIES.clear();
        new ApplicationContextRunner()
                .withConfiguration(
                        AutoConfigurations.of(VaultSignerAutoConfiguration.class, Push2uAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.vapid.subject=mailto:ops@example.com",
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.mount=transit",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token")
                .withUserConfiguration(FetchedMetadataTransportConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(VapidSigner.class);
                    assertThat(context.getBean(VapidSigner.class)).isInstanceOf(VaultTransitVapidSigner.class);
                    assertThat(context).hasSingleBean(PushSender.class);
                    // Exercise the wired signer, not just its bean type: a real sign call proves the
                    // fetched public key/version pair from the stub GET actually reached a working
                    // signer, and that it pins the fetched latest_version (1) on every sign request.
                    byte[] signature = context.getBean(VapidSigner.class)
                            .sign("starter fetched-mode README probe".getBytes(StandardCharsets.UTF_8));
                    assertThat(signature).hasSize(64);
                    assertThat(FetchedMetadataTransportConfiguration.SIGN_REQUEST_BODIES)
                            .singleElement()
                            .asString()
                            .contains("\"key_version\":1");
                });
    }

    @Test
    void theReadmeVaultExampleWithoutTheCoreSubjectFailsNamingTheProperty() {
        // Same (explicit-mode) composition as above, minus push2u.vapid.subject: a user who copies
        // only the push2u.signer.vault.* block must get a diagnostic that names the missing
        // property, not PushSender.Builder's generic "contact is required" message.
        new ApplicationContextRunner()
                .withConfiguration(
                        AutoConfigurations.of(VaultSignerAutoConfiguration.class, Push2uAutoConfiguration.class))
                .withPropertyValues(
                        "push2u.signer.vault.address=https://vault.example:8200",
                        "push2u.signer.vault.mount=transit",
                        "push2u.signer.vault.key-name=vapid",
                        "push2u.signer.vault.token=test-token",
                        "push2u.signer.vault.public-key=" + publicKeyB64,
                        "push2u.signer.vault.key-version=3")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.vapid.subject");
                });
    }

    @Test
    void aVaultHttpTransportBeanOutranksTheQualifiedHttpClient() {
        // Both extension points present at once: the transport bean must win, and the qualified
        // client must stay untouched — otherwise a user migrating to a full transport would keep
        // silently sending through the leftover client.
        RecordingTransportConfiguration.SIGN_REQUEST_BODIES.clear();
        QualifiedHttpClientConfiguration.CLIENT.reset();
        vaultRunner()
                .withUserConfiguration(RecordingTransportConfiguration.class, QualifiedHttpClientConfiguration.class)
                .run(context -> {
                    context.getBean(VapidSigner.class)
                            .sign("starter transport-priority probe".getBytes(StandardCharsets.UTF_8));
                    assertThat(RecordingTransportConfiguration.SIGN_REQUEST_BODIES)
                            .hasSize(1);
                    assertThat(QualifiedHttpClientConfiguration.CLIENT.sends())
                            .as("the qualified HttpClient is bypassed when a transport bean exists")
                            .isZero();
                });
    }

    @Test
    void theQualifiedHttpClientBacksTheDefaultTransport() throws Exception {
        // No VaultHttpTransport bean: the starter must wrap the push2uVaultHttpClient-qualified
        // client — the mTLS/proxy extension point — and route the sign call through it.
        QualifiedHttpClientConfiguration.CLIENT.reset();
        withStubVault(
                signResponse(),
                stubAddress -> explicitRunner(stubAddress)
                        .withUserConfiguration(QualifiedHttpClientConfiguration.class)
                        .run(context -> {
                            byte[] signature = context.getBean(VapidSigner.class)
                                    .sign("starter qualified-client probe".getBytes(StandardCharsets.UTF_8));
                            assertThat(signature).hasSize(64);
                            assertThat(QualifiedHttpClientConfiguration.CLIENT.sends())
                                    .as("the sign request went through the qualified HttpClient")
                                    .isEqualTo(1);
                        }));
    }

    @Test
    void aRedirectFollowingQualifiedClientFailsStartupInsteadOfOfferingTheTokenCrossOrigin() {
        // The JDK client does not strip custom headers such as X-Vault-Token across a
        // cross-origin redirect: a Vault address resolving to an attacker (DNS hijack, squatted
        // typo host, compromised reverse proxy) could answer 307 and receive the token. An
        // injected client that follows redirects must fail startup with a message saying so,
        // not be silently accepted.
        vaultRunner()
                .withUserConfiguration(RedirectFollowingHttpClientConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("redirect");
                });
    }

    @Test
    void theClientTheStarterBuildsItselfDoesNotFollowRedirects() throws Exception {
        // The other branch of resolveTransport: with no qualified HttpClient bean the starter
        // builds the client, and that one has to carry Redirect.NEVER as deliberately as
        // JdkVaultHttpTransport's own no-argument constructor does. A followed 307 would replay
        // X-Vault-Token against whatever host the Location names, so the sign call must come back
        // with the redirect as its status and the target must stay untouched.
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        AtomicInteger redirectTargetHits = new AtomicInteger();
        try {
            server.createContext("/v1", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.getResponseHeaders().add("Location", "/stolen");
                exchange.sendResponseHeaders(307, -1);
                exchange.close();
            });
            server.createContext("/stolen", exchange -> {
                redirectTargetHits.incrementAndGet();
                exchange.getRequestBody().readAllBytes();
                byte[] body = signResponse().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();

            explicitRunner("http://127.0.0.1:" + server.getAddress().getPort()).run(context -> {
                assertThatThrownBy(() -> context.getBean(VapidSigner.class)
                                .sign("starter redirect probe".getBytes(StandardCharsets.UTF_8)))
                        .isInstanceOf(PushCryptoException.class)
                        .hasMessageContaining("HTTP 307");
                assertThat(redirectTargetHits)
                        .as("the redirect target never saw the request")
                        .hasValue(0);
            });
        } finally {
            server.stop(0);
        }
    }

    @Test
    void anUnqualifiedHttpClientBeanIsNotPickedUp() throws Exception {
        // The whole point of the qualifier: an application HttpClient bean meant for something
        // else (push delivery, arbitrary REST calls) must not be silently drafted into carrying
        // Vault tokens. Without the qualifier the starter builds its own default client.
        UnqualifiedHttpClientConfiguration.CLIENT.reset();
        withStubVault(
                signResponse(),
                stubAddress -> explicitRunner(stubAddress)
                        .withUserConfiguration(UnqualifiedHttpClientConfiguration.class)
                        .run(context -> {
                            byte[] signature = context.getBean(VapidSigner.class)
                                    .sign("starter unqualified-client probe".getBytes(StandardCharsets.UTF_8));
                            assertThat(signature)
                                    .as("the default transport still signs")
                                    .hasSize(64);
                            assertThat(UnqualifiedHttpClientConfiguration.CLIENT.sends())
                                    .as("an HttpClient bean without the push2uVaultHttpClient qualifier is ignored")
                                    .isZero();
                        }));
    }

    @Test
    void fetchedModeStartupFailsOnTheRequestTimeoutInsteadOfHanging() throws Exception {
        // The original regression: the fetched mode's metadata GET used a client without a request
        // timeout, so a Vault that accepted the connection but never answered blocked context
        // startup forever. With the bound request-timeout the refresh must fail fast instead.
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            runner.withPropertyValues(
                            "push2u.signer.vault.address=http://127.0.0.1:" + silent.getLocalPort(),
                            "push2u.signer.vault.key-name=vapid",
                            "push2u.signer.vault.token=test-token",
                            "push2u.signer.vault.request-timeout=500ms")
                    .run(context -> {
                        assertThat(context).hasFailed();
                        assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("timed out");
                    });
        }
    }

    @Test
    void maxResponseBytesReachesTheBuiltTransport() throws Exception {
        // Bind a deliberately tiny cap and let the stub Vault answer with a normal-size sign
        // response: the call must fail closed with the transport's limit error — proving the
        // property actually shapes the transport instead of being silently dropped.
        withStubVault(
                signResponse(),
                stubAddress -> explicitRunner(stubAddress)
                        .withPropertyValues("push2u.signer.vault.max-response-bytes=16")
                        .run(context -> assertThatThrownBy(() -> context.getBean(VapidSigner.class)
                                        .sign("starter cap probe".getBytes(StandardCharsets.UTF_8)))
                                .isInstanceOf(PushCryptoException.class)
                                .hasMessageContaining("exceeded the configured limit of 16 bytes")));
    }

    @Test
    void requestTimeoutReachesTheBuiltTransport() throws Exception {
        // A socket that accepts but never answers: only the bound request-timeout can end the
        // exchange. The metadata GET used to set a connect timeout alone, which such a server
        // satisfies, so startup could hang forever — that part was a defect, and this pins its fix.
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            explicitRunner("http://127.0.0.1:" + silent.getLocalPort())
                    .withPropertyValues("push2u.signer.vault.request-timeout=500ms")
                    .run(context -> assertThatThrownBy(() -> context.getBean(VapidSigner.class)
                                    .sign("starter timeout probe".getBytes(StandardCharsets.UTF_8)))
                            .isInstanceOf(PushCryptoException.class)
                            .hasMessageContaining("timed out"));
        }
    }

    @Test
    void nonPositiveTransportPropertiesFailStartup() {
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.request-timeout=0s")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining("request-timeout must be positive");
                });
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.max-response-bytes=0")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining("max-response-bytes must be positive");
                });
        vaultRunner()
                .withPropertyValues("push2u.signer.vault.connect-timeout=-1s")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining("connect-timeout must be positive");
                });
    }

    private ApplicationContextRunner vaultRunner() {
        return runner.withPropertyValues(
                "push2u.signer.vault.address=http://vault.example:8200",
                "push2u.signer.vault.key-name=vapid",
                "push2u.signer.vault.token=test-token",
                "push2u.signer.vault.public-key=" + publicKeyB64);
    }

    /** An explicit-mode runner pointed at a live local stub Vault (no transport bean). */
    private ApplicationContextRunner explicitRunner(String address) {
        return runner.withPropertyValues(
                "push2u.signer.vault.address=" + address,
                "push2u.signer.vault.key-name=vapid",
                "push2u.signer.vault.token=test-token",
                "push2u.signer.vault.public-key=" + publicKeyB64);
    }

    /** A well-formed Transit sign response carrying 64 zero bytes as the signature. */
    private static String signResponse() {
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
        return "{\"data\":{\"signature\":\"vault:v1:" + signature + "\"}}";
    }

    /** Serve {@code responseBody} for every request on an ephemeral port and run {@code test}. */
    private static void withStubVault(String responseBody, StubVaultTest test) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        try {
            byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
            server.createContext("/", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
            test.run("http://127.0.0.1:" + server.getAddress().getPort());
        } finally {
            server.stop(0);
        }
    }

    private interface StubVaultTest {
        void run(String address) throws Exception;
    }

    /**
     * A {@link VaultHttpTransport} stub the autoconfigured signer picks up (an application transport bean outranks
     * every built-in default): records every sign request body and answers like Vault's Transit sign endpoint, so tests
     * can assert what was actually sent.
     */
    @Configuration(proxyBeanMethods = false)
    static class RecordingTransportConfiguration {

        static final List<String> SIGN_REQUEST_BODIES = new ArrayList<>();

        @Bean
        VaultHttpTransport recordingTransport() {
            return new VaultHttpTransport() {
                @Override
                public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                    throw new AssertionError("the explicit mode must never read key metadata from Vault");
                }

                @Override
                public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                    SIGN_REQUEST_BODIES.add(new String(body, StandardCharsets.UTF_8));
                    String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
                    return new VaultHttpResponse(200, "{\"data\":{\"signature\":\"vault:v3:" + signature + "\"}}");
                }
            };
        }
    }

    /**
     * A {@link VaultHttpTransport} stub for fetched mode: answers the startup {@code transit/keys/<key>} {@code GET}
     * with {@code latest_version} + a PEM public key (as the real Vault Transit API does) and the {@code sign}
     * {@code POST} like the recording stub above.
     */
    @Configuration(proxyBeanMethods = false)
    static class FetchedMetadataTransportConfiguration {

        private static final KeyPair KEY_PAIR = generateKeyPair();
        static final List<String> SIGN_REQUEST_BODIES = new ArrayList<>();

        @Bean
        VaultHttpTransport fetchedMetadataTransport() {
            return new VaultHttpTransport() {
                @Override
                public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                    return new VaultHttpResponse(200, metadataBody(KEY_PAIR));
                }

                @Override
                public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                    SIGN_REQUEST_BODIES.add(new String(body, StandardCharsets.UTF_8));
                    String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
                    return new VaultHttpResponse(200, "{\"data\":{\"signature\":\"vault:v1:" + signature + "\"}}");
                }
            };
        }

        private static KeyPair generateKeyPair() {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                return generator.generateKeyPair();
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        }

        /**
         * A minimal {@code transit/keys/<name>} response advertising the pair's public key as v1. {@code type} is part
         * of the minimum: the signer refuses any key not advertised as {@code ecdsa-p256} (see
         * {@code VaultTransitVapidSignerKeyValidationTest} in the signer module).
         */
        private static String metadataBody(KeyPair keyPair) {
            String pem = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, new byte[] {'\n'})
                            .encodeToString(keyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";
            return "{\"data\":{\"keys\":{\"1\":{\"public_key\":\"" + pem.replace("\n", "\\n")
                    + "\"}},\"latest_version\":1,\"type\":\"ecdsa-p256\"}}";
        }
    }

    /**
     * A {@link VaultHttpTransport} stub that records the <em>headers</em> of every call while answering both the
     * fetched mode's {@code transit/keys/<key>} {@code GET} (with {@code latest_version} + a PEM public key) and the
     * {@code sign} {@code POST} — so tests can assert exactly which headers each Vault call carried.
     */
    @Configuration(proxyBeanMethods = false)
    static class HeaderRecordingTransportConfiguration {

        record RecordedCall(String method, Map<String, String> headers) {}

        private static final KeyPair KEY_PAIR = FetchedMetadataTransportConfiguration.generateKeyPair();
        static final List<RecordedCall> CALLS = new ArrayList<>();

        @Bean
        VaultHttpTransport headerRecordingTransport() {
            return new VaultHttpTransport() {
                @Override
                public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                    CALLS.add(new RecordedCall("GET", Map.copyOf(headers)));
                    return new VaultHttpResponse(200, FetchedMetadataTransportConfiguration.metadataBody(KEY_PAIR));
                }

                @Override
                public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
                    CALLS.add(new RecordedCall("POST", Map.copyOf(headers)));
                    String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]);
                    return new VaultHttpResponse(200, "{\"data\":{\"signature\":\"vault:v1:" + signature + "\"}}");
                }
            };
        }
    }

    /** The mTLS/proxy extension point: an {@link HttpClient} qualified {@code push2uVaultHttpClient}. */
    @Configuration(proxyBeanMethods = false)
    static class QualifiedHttpClientConfiguration {

        static final RecordingHttpClient CLIENT = new RecordingHttpClient(HttpClient.newHttpClient());

        @Bean("push2uVaultHttpClient")
        HttpClient push2uVaultHttpClient() {
            return CLIENT;
        }
    }

    /** A qualified client that follows redirects — the configuration the starter must refuse. */
    @Configuration(proxyBeanMethods = false)
    static class RedirectFollowingHttpClientConfiguration {

        @Bean("push2uVaultHttpClient")
        HttpClient redirectFollowingVaultHttpClient() {
            return HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.ALWAYS)
                    .build();
        }
    }

    /** An application {@link HttpClient} bean for other purposes — lacking the Vault qualifier. */
    @Configuration(proxyBeanMethods = false)
    static class UnqualifiedHttpClientConfiguration {

        static final RecordingHttpClient CLIENT = new RecordingHttpClient(HttpClient.newHttpClient());

        @Bean
        HttpClient plainHttpClient() {
            return CLIENT;
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
