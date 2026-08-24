/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import org.springframework.core.Ordered;

/**
 * The declared position of this starter's one startup check — the refusal raised from a post-processor of the bean
 * factory, ahead of every application singleton, rather than from an ordinary bean's factory method. One context can
 * earn several such refusals at once across the starter family, and the operator reads whichever arrives first, so the
 * position is declared here rather than taken from the registration sequence the framework promises only as far as it
 * can.
 *
 * <p><b>The list this number belongs to spans two modules, and cannot live in either of them.</b> The order, most
 * specific first, is: the value of the activation switch, a malformed allowlist entry, an allowlist stated beside an
 * application policy bean, <em>a signer starter's partial-configuration diagnostic</em>, and last the general refusal
 * over a missing signer. The first three and the last belong to the core starter, which this module deliberately does
 * not depend on — it orders itself against that starter by name and nothing more — so no constant is visible to both.
 * Each module keeps its own and reads it against the same list.
 *
 * <p>What pins the list is therefore not the value written here. A test asserting that this constant equals a number
 * written in a document proves that someone typed it twice, and stays green while the module next door moves its own.
 * The order is pinned by the message that arrives in a context holding every starter that declares a position,
 * configured to earn several refusals at once — which is why that test lives in this module's suite, the only one with
 * both starters on a classpath.
 *
 * <p>The framework sorts post-processors into buckets by the kind of precedence their <em>class</em> declares and
 * compares numbers only within a bucket, so the check taking this position implements {@link Ordered} on the class
 * itself and is contributed from a {@code static} {@code @Bean} method whose declared return type is that concrete
 * class — a method declaring the post-processor interface lands in the bucket the framework never sorts, carrying a
 * number nothing reads.
 */
final class VaultStartupCheckOrder {

    /**
     * This starter's diagnostic over a partially stated {@code push2u.signer.vault.*} block: more specific than the
     * general refusal over a missing signer, which knows only that no signer exists, and less specific than every
     * refusal about a configured value, which is wrong whether or not this deployment sends. So it sits between them,
     * and the gap of 100 either side is what leaves the neighbouring positions free for the checks that hold them.
     */
    static final int SIGNER_PARTIAL_CONFIGURATION = Ordered.HIGHEST_PRECEDENCE + 500;

    private VaultStartupCheckOrder() {}
}
