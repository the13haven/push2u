/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * A {@link VapidSigner} delegating to a real one while counting {@code sign} calls. The count is the token cache's one
 * observable effect from outside the sender: a cache hit is a send that did not sign, a miss is one that did.
 */
final class CountingVapidSigner implements VapidSigner {

    private final VapidSigner delegate;
    private final AtomicInteger signCalls = new AtomicInteger();

    CountingVapidSigner(VapidSigner delegate) {
        this.delegate = delegate;
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        signCalls.incrementAndGet();
        return delegate.sign(signingInput);
    }

    @Override
    public byte[] publicKey() {
        return delegate.publicKey();
    }

    int signCount() {
        return signCalls.get();
    }
}
