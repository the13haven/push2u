/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.spring;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.bind.BindResult;
import org.springframework.boot.context.properties.bind.Binder;

/**
 * The one key that says whether this deployment sends, and the reading that decides whether a property naming key
 * material has been stated at all.
 *
 * <p><b>{@code push2u.enabled} is a statement, not a convenience.</b> A deployment states that it does not send, or the
 * autoconfigured delivery path is present and usable; the third state — on, with neither a sender nor a signer in the
 * context — fails startup. The default is on, because the deployments that most need the refusal are precisely the ones
 * that could not tell, before it existed, whether they were sending at all.
 *
 * <p><b>Only {@code true} and {@code false} are values of it.</b> This is the one key where a typo would be free to
 * mean the opposite of what was typed, so anything else fails the context naming the property instead of being read as
 * one of them. The framework's usual reading of an {@code enabled} key — anything not literally {@code false} is on —
 * is the safer of the two directions and still not good enough here: it turns {@code flase} into a deployment that
 * sends although it said not to. Absent is not a value: it is the default, and the default is on. A <em>blank</em>
 * value is neither absent nor one of the two, so it is refused like any other unrecognised value — the "blank counts as
 * unset" reading below belongs to the properties that activate a signer and stops there, because for those a blank
 * could never have produced a signer while here it would silently pick one of two opposite meanings.
 */
final class Push2uActivation {

    /** The key that states whether this deployment sends. Its absence is the default, and the default is on. */
    static final String DELIVERY_SWITCH = "push2u.enabled";

    /**
     * The only value that means on. Written out so the condition and the refusal cannot disagree about the spelling.
     */
    static final String ON = "true";

    /** The only value that means off. */
    static final String OFF = "false";

    private Push2uActivation() {}

    /**
     * Whether {@code property} states a value that could activate a signer: bound in the environment, and not blank.
     *
     * <p><b>A blank value counts as unset, and that reading belongs to activation alone.</b> Spring treats an empty
     * property as a present one, so {@code public-key: ${PUSH2U_VAPID_PUBLIC_KEY:}} beside a private key defaulted the
     * same way would otherwise activate a signer and then be refused for the length of the point it did not carry — a
     * failure describing a shape rather than what the operator did. No blank value of any activating property could
     * have produced a signer, so nothing is lost by reading it as unset: the only outcomes traded are two failures, and
     * the one this chooses names the missing configuration. It says nothing about the allowlist properties, where an
     * explicitly empty value is a statement with a meaning of its own.
     *
     * <p>Read through {@link Binder} rather than by a literal property lookup, so every spelling relaxed binding
     * accepts — the kebab-case name a guide prints, the camelCase form, and the upper-case environment-variable form —
     * answers the same way the properties record binds it.
     */
    static boolean isStated(Binder binder, String property) {
        BindResult<String> bound = binder.bind(property, String.class);
        return bound.isBound() && !bound.get().isBlank();
    }

    /**
     * The value written for {@link #DELIVERY_SWITCH}, or {@code null} where the key is absent — which is the default,
     * and the default is on. Read here rather than in each of its two readers, so the check that refuses an
     * unrecognised value and the diagnostic that recognises {@code false} cannot come to disagree about what was
     * written.
     */
    static @Nullable String writtenSwitchValue(Binder binder) {
        BindResult<String> bound = binder.bind(DELIVERY_SWITCH, String.class);
        return bound.isBound() ? bound.get() : null;
    }

    /** Whether the deployment stated that it does not send. An absent or unrecognised value is not that statement. */
    static boolean isStatedOff(Binder binder) {
        String written = writtenSwitchValue(binder);
        return written != null && OFF.equalsIgnoreCase(written);
    }
}
