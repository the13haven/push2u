/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import org.springframework.core.Ordered;

/**
 * The declared positions of this module's startup checks — the refusals raised from post-processors of the bean
 * factory, ahead of every application singleton, rather than from an ordinary bean's factory method. One context can
 * earn several of them at once, and the operator reads whichever arrives first, so their order is declared here rather
 * than taken from the registration sequence the framework promises only as far as it can.
 *
 * <p>The order is one list spanning the whole starter family, most specific first: the value of the activation switch,
 * then the tombstones over removed properties, then the allowlist refusals, then a signer starter's own diagnostic,
 * then the general refusal over a missing signer. A check declares only the position it implements — a number reserved
 * for a check that does not exist yet would be a claim nothing keeps true — and each position leaves a gap of 100 so
 * the checks around it can take theirs when they are built. Positions of checks in other modules cannot live here,
 * because a signer starter deliberately does not depend on this one; each module keeps its own constants and reads them
 * against the same list. What pins the list is therefore not any constant's value — a test asserting that a number here
 * equals a number written in the decision proves only that someone typed it twice, and stays green while the module
 * next door moves its own — but the message that arrives in a context holding every starter and earning several
 * refusals at once.
 *
 * <p>The framework sorts post-processors into buckets by the kind of precedence their <em>class</em> declares and
 * compares numbers only within a bucket, so every check taking a position from this class implements {@link Ordered} on
 * the class itself and is contributed from a {@code static} {@code @Bean} method whose declared return type is that
 * concrete class — a method declaring the post-processor interface lands in the bucket the framework never sorts,
 * carrying a number nothing reads.
 */
final class StartupCheckOrder {

    /**
     * The value of the activation switch itself, ahead of everything: a deployment that mistyped the one key deciding
     * whether any of this applies is owed that sentence rather than a consequence of it. Every check below reads
     * configuration whose meaning depends on that key having been understood, and the switch's own condition — which
     * runs earlier still, while the configuration classes are parsed — treats an unrecognised value as off, so a typo
     * would otherwise surface as a refusal about a signer nobody was asked for.
     */
    static final int ACTIVATION_SWITCH_VALUE = Ordered.HIGHEST_PRECEDENCE + 100;

    /**
     * The tombstones over properties a release removed: they precede every value and wiring refusal below them, because
     * a key that no longer exists makes any reading of the configuration under it a reading of something the operator
     * did not mean to write. Only the activation switch's own value outranks them.
     *
     * <p>However many keys have been removed, this position holds <em>one</em> check that names all of them it finds. A
     * check per key would have to share this number, since no tombstone is more specific than another, and then the
     * only order between them would be the sequence the framework happened to register them in — leaving an operator
     * holding several dead keys to meet one per failed startup. There is deliberately no order among tombstones to
     * declare, because they arrive together.
     */
    static final int REMOVED_PROPERTY_TOMBSTONE = Ordered.HIGHEST_PRECEDENCE + 200;

    /**
     * A malformed allowlist entry — one that is not a well-formed origin or domain, named by property and index. The
     * most specific finding of the family, so it precedes the contradiction below and every signer refusal: an entry
     * that is not an origin is wrong whoever ends up reading it, and an operator holding several faults should meet the
     * one that points at a value before any that describes the configuration around it.
     */
    static final int MALFORMED_ALLOWLIST_ENTRY = Ordered.HIGHEST_PRECEDENCE + 300;

    /**
     * A non-empty allowlist property beside an application-supplied {@code EndpointPolicy} bean. A contradiction
     * between two well-formed statements, so it yields to the malformed-entry check above — a bad value is the sharper
     * finding, and fixing or emptying that entry may be what resolves the contradiction — while preceding every refusal
     * about signers and the delivery path, which the contradiction is not about.
     */
    static final int ALLOWLIST_BESIDE_POLICY_BEAN = Ordered.HIGHEST_PRECEDENCE + 400;

    /**
     * The general refusal over a deployment that is on and holds no signer — the least specific finding of the family,
     * so every check above it goes first. One position above it belongs to a signer starter's own partial-configuration
     * diagnostic, which is declared in that starter's own module and cannot be named here: a signer starter
     * deliberately does not depend on this one, so the two modules keep their constants apart and each reads them
     * against the same list. That gap is not free space — leaving this refusal at a number a starter's diagnostic could
     * share would put the general finding ahead of the specific one whenever the framework happened to register it
     * first.
     */
    static final int MISSING_SIGNER = Ordered.HIGHEST_PRECEDENCE + 600;

    private StartupCheckOrder() {}
}
