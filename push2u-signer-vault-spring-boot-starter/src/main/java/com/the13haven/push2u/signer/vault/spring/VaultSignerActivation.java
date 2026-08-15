/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.BindResult;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * The three keys that activate this signer, the reading that decides whether one of them has been stated, and the key
 * that says whether this deployment sends at all.
 *
 * <p><b>{@code push2u.enabled} belongs to the core starter's namespace, and honouring it here is not the coupling this
 * module otherwise avoids.</b> Naming another module's property prefixes <em>inside a message</em> copies that module's
 * activation rules and goes stale when they change; honouring a switch copies nothing — it is one fact about the
 * namespace, stated once, whose meaning cannot drift. This starter already orders itself against the core starter by
 * name without depending on it, so the condition costs no dependency either. What it buys is that a deployment which
 * has declared the custodian unused never constructs the Vault signer, and so never pays for the metadata read its
 * fetched mode performs while the context starts.
 */
final class VaultSignerActivation {

    /** The core starter's key stating whether this deployment sends. Its absence is the default, and that is on. */
    static final String DELIVERY_SWITCH = "push2u.enabled";

    /** The only value of that key which means on. */
    static final String ON = "true";

    /** The Vault base address. */
    static final String ADDRESS = "push2u.signer.vault.address";

    /** The Transit key name. */
    static final String KEY_NAME = "push2u.signer.vault.key-name";

    /** The Vault token. */
    static final String TOKEN = "push2u.signer.vault.token";

    /** The three keys that together activate this signer, in the order a diagnostic should list them. */
    static final List<String> ACTIVATING_PROPERTIES = List.of(ADDRESS, KEY_NAME, TOKEN);

    private VaultSignerActivation() {}

    /**
     * Whether {@code property} states a value: bound in the environment, and not blank.
     *
     * <p><b>A blank value counts as unset, and that reading belongs to activation alone.</b> Spring treats an empty
     * property as a present one, so a token defaulted as {@code ${VAULT_TOKEN:}} would otherwise activate the signer
     * and then be refused as an empty token — a failure describing the shape of an empty string rather than the
     * configuration that is missing. No blank value of any of these three could have produced a signer, so the only
     * outcomes traded are two failures, and the one this chooses names what was not configured.
     *
     * <p>Read through {@link Binder} rather than by a literal property lookup, so every spelling relaxed binding
     * accepts answers the same way the properties record binds it.
     */
    static boolean isStated(Binder binder, String property) {
        BindResult<String> bound = binder.bind(property, String.class);
        return bound.isBound() && !bound.get().isBlank();
    }

    /** The activating properties this context states, in declaration order. */
    static List<String> stated(Binder binder) {
        List<String> stated = new ArrayList<>();
        for (String property : ACTIVATING_PROPERTIES) {
            if (isStated(binder, property)) {
                stated.add(property);
            }
        }
        return stated;
    }

    /**
     * The condition under which this starter contributes its signer: all three activating properties state a value.
     * Replaces the framework's own property condition precisely because that one counts a blank as set.
     */
    static final class OnVaultSignerConfigured extends SpringBootCondition {

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Binder binder = Binder.get(context.getEnvironment());
            List<String> stated = stated(binder);
            ConditionMessage.Builder message = ConditionMessage.forCondition("push2u Vault signer configured");
            if (stated.size() == ACTIVATING_PROPERTIES.size()) {
                return ConditionOutcome.match(message.because("every activating property is set"));
            }
            List<String> missing = new ArrayList<>(ACTIVATING_PROPERTIES);
            missing.removeAll(stated);
            return ConditionOutcome.noMatch(message.because(String.join(", ", missing) + " unset or blank"));
        }
    }
}
