/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.net.URI;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import com.the13haven.push2u.EndpointPolicy;
import com.the13haven.push2u.EndpointRejectedException;
import com.the13haven.push2u.PushSender;
import com.the13haven.push2u.VapidSigner;

/**
 * {@link Push2uEndpointPolicyAutoConfiguration} publishes the allowlist the properties express as an
 * {@link EndpointPolicy} bean — reachable by the application code that accepts subscriptions, with or without a sender
 * in the context. The two startup checks about the allowlist's values — a malformed entry, named by property and index,
 * and a non-empty property beside an application-supplied policy bean — are covered here beside the bean they guard,
 * although they are hosted in {@link Push2uStartupChecksAutoConfiguration}: an auto-configuration that contributes a
 * bean an operator might want to remove may not also host a check, and the tests below include the scenario that rule
 * exists for — excluding the bean's class must leave both checks running. Both checks run from the post-processor
 * phase, ahead of every bean-creation failure, and neither depends on a signer, a sender or Actuator being anywhere in
 * sight.
 *
 * <p>Most contexts here configure no VAPID keys on purpose: the deployment this autoconfiguration exists for accepts
 * subscriptions and leaves the sending to another service, so proving the bean and the checks in senderless contexts is
 * the point rather than a convenience. (ADR-024 is the record behind all of it.)
 */
class Push2uEndpointPolicyAutoConfigurationTest {

    /**
     * The full starter composition, exactly as the imports file ships it, with the statement a registration-only
     * deployment makes: it accepts subscriptions, holds a policy and sends nothing, so {@code push2u.enabled=false} is
     * a statement it can make truthfully — and without it every senderless context here would now be refused for
     * holding no signer. Every assertion below therefore doubles as proof that the switch does not reach the endpoint
     * policy: the bean is contributed, and the checks guarding its properties run, with delivery off.
     */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    Push2uAutoConfiguration.class,
                    Push2uEndpointPolicyAutoConfiguration.class,
                    Push2uHealthAutoConfiguration.class,
                    Push2uStartupChecksAutoConfiguration.class))
            .withPropertyValues("push2u.enabled=false");

    @Test
    void theBeanExistsWhenOriginsHaveAnEntry() {
        // The starter's own bean sits beside the expressed property that built it. That pair is
        // also the trap the exclusivity check has to step around: if the check took its own bean
        // for an application-supplied one, this context would fail as a contradiction instead of
        // starting. Behaviour is asserted, not shape — the policy must actually refuse a
        // non-allowlisted endpoint, because the bean is a security control and not a marker.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(EndpointPolicy.class);
                    EndpointPolicy policy = context.getBean(EndpointPolicy.class);
                    assertThatCode(() -> policy.validate(URI.create("https://push.example.test/send/abc")))
                            .doesNotThrowAnyException();
                    assertThatExceptionOfType(EndpointRejectedException.class)
                            .isThrownBy(() -> policy.validate(URI.create("https://other.example/send/abc")));
                });
    }

    @Test
    void theBeanExistsWhenDomainsHaveAnEntry() {
        // The domain kind must survive the trip through the bean with its label boundary intact:
        // a subdomain at any depth is admitted, a host that merely ends with the configured text
        // is not — the vulnerability class the domain rule exists to keep out of hand-written
        // policies, pinned at the boundary the bean now serves.
        runner.withPropertyValues("push2u.allowed-domains=notify.windows.com").run(context -> {
            assertThat(context).hasNotFailed();
            EndpointPolicy policy = context.getBean(EndpointPolicy.class);
            assertThatCode(() -> policy.validate(URI.create("https://wns2-ln2p.notify.windows.com/w/?t=abc")))
                    .doesNotThrowAnyException();
            assertThatExceptionOfType(EndpointRejectedException.class)
                    .isThrownBy(() -> policy.validate(URI.create("https://evilnotify.windows.com/w/?t=abc")));
        });
    }

    @Test
    void theBeanUnionsBothProperties() {
        // Two halves of one statement: an origin entry and a domain entry land in one allowlist,
        // and the union is still an allowlist.
        runner.withPropertyValues(
                        "push2u.allowed-origins=https://push.example.test", "push2u.allowed-domains=notify.windows.com")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    EndpointPolicy policy = context.getBean(EndpointPolicy.class);
                    assertThatCode(() -> {
                                policy.validate(URI.create("https://push.example.test/send/abc"));
                                policy.validate(URI.create("https://cloud.notify.windows.com/w/?t=abc"));
                            })
                            .doesNotThrowAnyException();
                    assertThatExceptionOfType(EndpointRejectedException.class)
                            .isThrownBy(() -> policy.validate(URI.create("https://other.example/send/abc")));
                });
    }

    @Test
    void noBeanWhenNeitherPropertyIsSet() {
        // Nothing stated means no bean, and a context that also builds no sender starts exactly as
        // it did before this autoconfiguration existed — a deployment carrying the starter on its
        // classpath without configuring web push is not refused for want of an allowlist nobody
        // asked it for.
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(EndpointPolicy.class);
        });
    }

    @Test
    void noBeanWhenEverySetPropertyIsEmpty() {
        // An explicitly empty property is a statement — "deliberately not using this property
        // here" — not an allowlist with no entries. The condition asks for an ENTRY, so emptied
        // keys contribute no bean, and in a senderless context that is the end of it: the refusal
        // over an emptied pair belongs to the sender, whose obligation it guards.
        runner.withPropertyValues("push2u.allowed-origins=", "push2u.allowed-domains=")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(EndpointPolicy.class);
                });
        runner.withPropertyValues("push2u.allowed-domains=").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(EndpointPolicy.class);
        });
    }

    @Test
    void aRegistrationOnlyContextHoldsThePolicyBuiltFromItsProperties() {
        // The deployment ADR-024 exists for: it accepts subscriptions, stores rows, and leaves the
        // sending to another service — no VAPID keys, no signer, no sender, no Actuator wiring.
        // Its stated allowlist must still become the policy it validates registrations against;
        // gating the bean on a signer was the first form of this and would have withheld the
        // policy from exactly this context.
        runner.withPropertyValues(
                        "push2u.allowed-origins=https://push.example.test", "push2u.allowed-domains=notify.windows.com")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(PushSender.class);
                    assertThat(context).doesNotHaveBean(VapidSigner.class);
                    assertThat(context).doesNotHaveBean(Push2uHealthIndicator.class);
                    assertThat(context).hasSingleBean(EndpointPolicy.class);
                    EndpointPolicy policy = context.getBean(EndpointPolicy.class);
                    assertThatCode(() -> policy.validate(URI.create("https://wns2-ln2p.notify.windows.com/w/?t=abc")))
                            .doesNotThrowAnyException();
                    assertThatExceptionOfType(EndpointRejectedException.class)
                            .as("the boundary can refuse a row that would otherwise fail on every later send")
                            .isThrownBy(() -> policy.validate(URI.create("https://10.0.0.5/internal")));
                });
    }

    @Test
    void theBeanDoesNotDependOnAnyOtherConfiguration() {
        // Alone in the context, the autoconfiguration still binds the properties (it restates
        // @EnableConfigurationProperties for exactly this composition) and still yields a working
        // policy.
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Push2uEndpointPolicyAutoConfiguration.class))
                .withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(EndpointPolicy.class);
                    assertThatExceptionOfType(EndpointRejectedException.class)
                            .isThrownBy(() -> context.getBean(EndpointPolicy.class)
                                    .validate(URI.create("https://other.example/send/abc")));
                });
    }

    @Test
    void theChecksDoNotDependOnAnyOtherConfiguration() {
        // The checks' own auto-configuration, alone in the context: both allowlist refusals still
        // fire, with nothing else from the starter anywhere in sight — nothing standing between a
        // check and the context may narrow the set of deployments it protects.
        ApplicationContextRunner checksAlone = new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Push2uStartupChecksAutoConfiguration.class));
        checksAlone
                .withPropertyValues("push2u.allowed-origins=http://push.example")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("push2u.allowed-origins[0]:");
                });
        checksAlone
                .withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("'rejectingPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
    }

    @Test
    void theChecksSurviveExcludingTheAutoConfigurationThatContributesTheBean() {
        // The scenario that decides where the checks live. An operator who meets the contradiction
        // refusal reaches for the framework's standard tool and excludes the auto-configuration
        // that publishes the policy bean. If a check rode in that same class, the exclusion would
        // silence it, and the stated allowlist would be ignored without a word — the exact outcome
        // the check exists to prevent. So the exclusion (modelled here as the shipped composition
        // minus that one class) must remove only the bean: the contradiction still fails the
        // context, naming the property and the bean, from the check's own phase.
        ApplicationContextRunner withoutPolicyClass = new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        Push2uAutoConfiguration.class,
                        Push2uHealthAutoConfiguration.class,
                        Push2uStartupChecksAutoConfiguration.class));
        withoutPolicyClass
                .withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .isNotInstanceOf(BeanCreationException.class)
                            .hasMessageContaining("push2u.allowed-origins")
                            .hasMessageContaining("'rejectingPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
        // The malformed-entry check survives the same exclusion, for the same reason.
        withoutPolicyClass
                .withPropertyValues("push2u.allowed-origins=http://push.example")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("push2u.allowed-origins[0]:");
                });
    }

    @Test
    void theConditionReadsEverySpellingRelaxedBindingAccepts() {
        // The environment-variable spelling arrives through a SystemEnvironmentPropertySource,
        // whose mapping a literal property lookup would not apply — the same reason the tombstone
        // reads through Binder. The bean's condition, reading the same way, must see it too.
        runner.withInitializer(environmentVariable("PUSH2U_ALLOWED_ORIGINS", "https://push.example.test"))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(EndpointPolicy.class);
                });
    }

    @Test
    void anApplicationPolicyBeanSuppressesTheStarters() {
        // With no allowlist expressed, an application bean is simply the policy — one bean, the
        // application's own instance, and the sender-side tests prove the sender reads it.
        runner.withUserConfiguration(RejectingPolicyConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(EndpointPolicy.class);
            assertThat(context.getBean(EndpointPolicy.class)).isSameAs(RejectingPolicyConfiguration.POLICY);
        });
    }

    @Test
    void aNonEmptyOriginsPropertyBesideAnApplicationBeanFailsNamingBoth() {
        // Both configured is ambiguous for a security control: silently preferring either would
        // leave the operator believing the ignored one is in force. The context must fail naming
        // both sources — including the concrete bean name, since any configuration could have
        // contributed the EndpointPolicy bean and the operator has to find it to fix it.
        //
        // No sender anywhere in this context, deliberately: left with pushSender, this refusal was
        // unreachable in a registration-only deployment, which is exactly where an ignored
        // allowlist goes unnoticed. The failure arrives from the startup check itself, not from a
        // bean under construction.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .isNotInstanceOf(BeanCreationException.class)
                            .hasMessageContaining("push2u.allowed-origins")
                            .hasMessageContaining("EndpointPolicy bean")
                            .hasMessageContaining("'rejectingPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
    }

    @Test
    void aNonEmptyDomainsPropertyBesideAnApplicationBeanFailsNamingThatProperty() {
        // The exclusivity holds for the domains property exactly as for origins — including naming
        // WHICH property is non-empty, which with two of them is the difference between a fix and
        // a search.
        runner.withPropertyValues("push2u.allowed-domains=notify.windows.com")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.allowed-domains")
                            .hasMessageNotContaining("push2u.allowed-origins is non-empty")
                            .hasMessageContaining("'rejectingPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
    }

    @Test
    void bothAllowlistPropertiesBesideABeanNameBothPropertiesAndTheBean() {
        // The plural branch of the same refusal. Naming which property collided is the whole point
        // of that branch, and with both non-empty the answer is "both" — an operator told about
        // one of them would empty it, restart, and meet the refusal again over the other.
        runner.withPropertyValues(
                        "push2u.allowed-origins=https://push.example.test", "push2u.allowed-domains=notify.windows.com")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.allowed-origins")
                            .hasMessageContaining("push2u.allowed-domains")
                            .hasMessageContaining("'rejectingPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
    }

    @Test
    void anApplicationBeanNamedLikeTheStartersIsStillTheApplications() {
        // Which bean is whose is answered by where its definition came from, never by its name: an
        // application is free to call its bean push2uEndpointPolicy, and a check matching on the
        // name would take it for the starter's own — letting the stated allowlist be ignored
        // without a word, in a context (senderless, like this one) where nothing else would ever
        // read those properties.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(StarterNamedPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.allowed-origins")
                            .hasMessageContaining("'push2uEndpointPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
    }

    @Test
    void aBeanWhoseOriginCannotBeEstablishedCountsAsTheApplications() {
        // A definition registered without factory-method metadata — a supplier-backed registration
        // here — carries nothing to establish where it came from. It must count as the
        // application's: erring this way produces a startup failure naming the conflicting bean,
        // where the other reading would silently drop a stated allowlist.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withBean("suppliedPolicy", EndpointPolicy.class, () -> endpoint -> {})
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("'suppliedPolicy'")
                            .hasMessageContaining("Configure exactly one");
                });
    }

    @Test
    void theContradictionIsDetectedWithoutCreatingTheBean() {
        // The check reads bean definitions, not instances: a policy bean whose factory would blow
        // up if invoked stays uninvoked, and the operator reads the contradiction — proof that
        // nothing is forced into existence to answer a question about the configuration.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test")
                .withUserConfiguration(ExplodingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .isNotInstanceOf(BeanCreationException.class)
                            .hasMessageContaining("'explodingPolicy'")
                            .hasMessageContaining("Configure exactly one")
                            .hasMessageNotContaining("must not be created");
                });
    }

    @Test
    void aMalformedOriginEntryFailsNamingThePropertyAndTheIndex() {
        // Same contract as every property the starter translates: a misconfigured allowlist fails
        // startup with the YAML property name, not at some later read. The index comes with it —
        // the rule is built one entry at a time, so the refusal knows which entry of which list,
        // and an operator with a dozen origins does not hunt for the bad one. The failure is the
        // startup check's own exception, from the post-processor phase, not a bean-creation
        // wrapper — and it fires with no sender in the context, where the old arrangement checked
        // nothing at all.
        runner.withPropertyValues("push2u.allowed-origins=https://push.example.test,http://push.example")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalArgumentException.class)
                            .isNotInstanceOf(BeanCreationException.class)
                            .hasMessageContaining("push2u.allowed-origins[1]:")
                            .hasMessageContaining("must be https");
                });
    }

    @Test
    void aMalformedDomainEntryFailsNamingItsOwnProperty() {
        // The domain field is exactly where a pasted endpoint URL lands, so its refusal is the one
        // most worth attributing precisely — and it must name push2u.allowed-domains, not the
        // sibling property whose entries were all fine.
        runner.withPropertyValues("push2u.allowed-domains=notify.windows.com,https://push.example")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("push2u.allowed-domains[1]:")
                            .hasMessageContaining("bare hostname");
                });
    }

    @Test
    void theIndexIsCountedWithinItsOwnPropertyWhenBothAreConfigured() {
        // The case the per-property index was designed for, and the one a single test populating
        // one list can never fail on: with both lists populated, an index counted across the pair
        // — or a property name captured once for whichever list ran first — still points
        // somewhere, just not at the entry the operator has to fix. Asserted in both directions,
        // since a shared counter is only visibly wrong for the list that is processed second.
        runner.withPropertyValues(
                        "push2u.allowed-origins=https://fcm.googleapis.com,https://push.example.test,"
                                + "https://updates.push.services.mozilla.com",
                        "push2u.allowed-domains=good.example,bad..example")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("push2u.allowed-domains[1]:")
                            .as("the index is this property's own, not a position in the concatenated pair")
                            .hasMessageNotContaining("push2u.allowed-origins")
                            .hasMessageContaining("empty label");
                });
        runner.withPropertyValues(
                        "push2u.allowed-origins=https://fcm.googleapis.com,http://push.example",
                        "push2u.allowed-domains=good.example,notify.windows.com")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("push2u.allowed-origins[1]:")
                            .hasMessageNotContaining("push2u.allowed-domains")
                            .hasMessageContaining("must be https");
                });
    }

    @Test
    void theCheckReadsEverySpellingRelaxedBindingAccepts() {
        // The check binds through Binder, exactly as the properties record does — a check reading
        // only the canonical spelling would let a camelCase entry through and hand the refusal
        // back to bean creation, behind every broader failure, which is the ordering this check
        // exists to prevent.
        runner.withPropertyValues("push2u.allowedOrigins=http://push.example").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalArgumentException.class)
                    .isNotInstanceOf(BeanCreationException.class)
                    .hasMessageContaining("push2u.allowed-origins[0]:");
        });
    }

    @Test
    void aBlankEntryIsAnEntryRatherThanTheEscapeHatch() {
        // The escape hatch works on an explicitly EMPTY value. A blank one is not the same input:
        // bound from a single delimited string, only a zero-length value yields no entries, while a
        // space yields one that trims to nothing. So the property counts as expressing an allowlist
        // and its entry is refused — and what makes that survivable is the index, since an entry
        // that shows nothing of itself is still push2u.allowed-origins[0]. The guide states this,
        // and the position it promises is ours rather than the framework's, so it is pinned here.
        //
        // The property goes in as a property source rather than through withPropertyValues, which
        // trims what it is given: a blank cannot be expressed that way at all, and a test written
        // with it would silently assert the empty case while reading as though it covered this one.
        runner.withInitializer(blankAllowedOrigins()).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .isInstanceOf(IllegalArgumentException.class)
                    .as("a blank entry is refused by position, not read as an empty property")
                    .hasMessageContaining("push2u.allowed-origins[0]:");
        });
    }

    @Test
    void aBlankEntryBesideABeanIsRefusedAsTheMalformedEntryItIs() {
        // The blank in the case the hatch exists for: beside a bean, a blanked property both looks
        // expressed (the contradiction) and holds a malformed entry (the blank itself). The
        // malformed-entry check runs first, so the operator is pointed at the entry by property
        // and index — the value that made the property look expressed — rather than at a
        // contradiction they would resolve by hunting through a bean that was configured on
        // purpose. This is also the declared order of the two checks, pinned by which message
        // arrives.
        runner.withInitializer(blankAllowedOrigins())
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("push2u.allowed-origins[0]:")
                            .as("the malformed entry outranks the contradiction")
                            .hasMessageNotContaining("Configure exactly one");
                });
    }

    @Test
    void aMalformedEntryOutranksTheContradiction() {
        // One context earning both allowlist refusals at once: a malformed entry in an expressed
        // property, beside an application bean. The declared order says the value refusal is the
        // more specific finding and arrives first — pinned by the message the operator reads,
        // never by comparing constants, which would only prove a number was typed twice.
        runner.withPropertyValues("push2u.allowed-origins=http://push.example")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("push2u.allowed-origins[0]:")
                            .hasMessageNotContaining("Configure exactly one");
                });
    }

    @Test
    void theTombstoneOutranksBothAllowlistChecks() {
        // A context earning three declared checks at once: a removed key, a malformed entry, and
        // an allowlist beside a bean. The tombstone's position is ahead of both allowlist checks —
        // a key that no longer exists makes every reading of the configuration under it suspect —
        // so its message is the one that arrives. Pinned by the message, not by constants.
        runner.withPropertyValues("push2u.record-size=8192", "push2u.allowed-origins=http://push.example")
                .withUserConfiguration(RejectingPolicyConfiguration.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("push2u.record-size")
                            .hasMessageNotContaining("push2u.allowed-origins[")
                            .hasMessageNotContaining("Configure exactly one");
                });
    }

    @Test
    void theMalformedEntryCheckPrecedesEveryBeanCreationFailure() {
        // A context holding a malformed entry AND unusable key material that would fail the signer
        // bean. The check runs in the post-processor phase, before any bean is created, so the
        // operator reads the entry refusal — a refusal left inside the policy's factory method
        // would lose this race to whichever bean happened to fail first, which is why the check
        // exists at its declared position at all.
        //
        // push2u.enabled=true overrides the runner's statement on purpose: with delivery off there
        // is no signer bean to fail, and the test would pass without proving anything about order.
        runner.withPropertyValues(
                        "push2u.enabled=true",
                        "push2u.allowed-origins=http://push.example",
                        "push2u.vapid.public-key=!!not-base64url!!",
                        "push2u.vapid.private-key=!!not-base64url!!",
                        "push2u.vapid.subject=mailto:ops@example.com")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .as("the check's own exception, not a bean-creation wrapper")
                            .isInstanceOf(IllegalArgumentException.class)
                            .isNotInstanceOf(BeanCreationException.class)
                            .hasMessageContaining("push2u.allowed-origins[0]:");
                });
    }

    /** Puts one variable into the environment through the source type real environment variables arrive by. */
    private static ApplicationContextInitializer<ConfigurableApplicationContext> environmentVariable(
            String name, String value) {
        return context -> context.getEnvironment()
                .getPropertySources()
                .addFirst(new SystemEnvironmentPropertySource("policy-test-environment", Map.of(name, value)));
    }

    /**
     * Puts {@code push2u.allowed-origins} into the environment as a single blank string, which is what an operator
     * writes when they mean to empty an inherited property. It cannot go through {@code withPropertyValues}, which
     * trims the value it is handed.
     */
    private static ApplicationContextInitializer<ConfigurableApplicationContext> blankAllowedOrigins() {
        return context -> context.getEnvironment()
                .getPropertySources()
                .addFirst(new MapPropertySource("blank-allowlist", Map.of("push2u.allowed-origins", " ")));
    }

    /** An application-supplied policy that rejects everything, distinguishable by identity and message. */
    @Configuration(proxyBeanMethods = false)
    static class RejectingPolicyConfiguration {

        static final EndpointPolicy POLICY = endpoint -> {
            throw new EndpointRejectedException("application policy rejects all endpoints");
        };

        @Bean
        EndpointPolicy rejectingPolicy() {
            return POLICY;
        }
    }

    /** An application bean that happens to reuse the starter's own bean name. */
    @Configuration(proxyBeanMethods = false)
    static class StarterNamedPolicyConfiguration {

        @Bean
        EndpointPolicy push2uEndpointPolicy() {
            return endpoint -> {
                throw new EndpointRejectedException("application policy rejects all endpoints");
            };
        }
    }

    /** A policy bean that must never be instantiated — the definitions-not-instances probe. */
    @Configuration(proxyBeanMethods = false)
    static class ExplodingPolicyConfiguration {

        @Bean
        EndpointPolicy explodingPolicy() {
            throw new IllegalStateException("the policy bean must not be created to detect the contradiction");
        }
    }
}
