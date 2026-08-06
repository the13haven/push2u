/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault.spring;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Supplier;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import com.the13haven.push2u.P256PublicKeys;
import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.signer.vault.JdkVaultHttpTransport;
import com.the13haven.push2u.signer.vault.TransitKeyName;
import com.the13haven.push2u.signer.vault.VaultHttpTransport;
import com.the13haven.push2u.signer.vault.VaultToken;
import com.the13haven.push2u.signer.vault.VaultTransitVapidSigner;

/**
 * Autoconfigures a {@link VaultTransitVapidSigner} as the {@link VapidSigner} from {@code push2u.signer.vault.*}.
 * Active when {@code address}, {@code key-name} and {@code token} are set; {@code public-key} is optional — when
 * omitted (or blank) the signer reads its public key and key version from {@code transit/keys/<key>} at startup and
 * pins that version for signing (the recommended single-source-of-truth mode; the token then needs {@code read} on the
 * key), and when supplied the signer uses it verbatim (token needs only {@code sign}). With an explicit
 * {@code public-key}, set {@code key-version} to pin the matching Transit key version — without it Vault signs with the
 * latest version, which stops matching the configured public key after a key rotation. {@code namespace} is likewise
 * optional: set it when the Transit engine lives in a Vault Enterprise/HCP namespace, and the signer sends it as the
 * {@code X-Vault-Namespace} header on every Vault call; unset, no such header is sent at all.
 *
 * <p>Ordered before the core starter's {@code Push2uAutoConfiguration} (by name, so this module need not depend on it)
 * and {@link ConditionalOnMissingBean}: when both starters are present this remote signer wins over the in-JVM local
 * signer, while an application-supplied {@link VapidSigner} still overrides both.
 *
 * <p><b>Transport.</b> Every Vault call (the Transit {@code sign} POST and the fetched mode's startup metadata GET)
 * goes through one {@link VaultHttpTransport}, resolved in priority order:
 *
 * <ol>
 *   <li>an application {@link VaultHttpTransport} bean — full control (custom HTTP stack, observability); the
 *       {@code request-timeout}/{@code connect-timeout}/{@code max-response-bytes} properties are then ignored, the
 *       bean owns those concerns;
 *   <li>an application {@link HttpClient} bean qualified {@code "push2uVaultHttpClient"} — the middle road for
 *       mTLS/proxy setups: the starter wraps it in a {@link JdkVaultHttpTransport} with the configured
 *       {@code request-timeout} and {@code max-response-bytes} ({@code connect-timeout} is ignored, the supplied client
 *       owns it). The client must be built with {@link HttpClient.Redirect#NEVER}: the JDK client re-sends
 *       {@code X-Vault-Token} to a redirect target, so {@link JdkVaultHttpTransport} rejects a client whose
 *       {@code followRedirects()} is anything else, failing startup. If the setup relied on following a redirect —
 *       typically a Vault HA standby with {@code disable_clustering = true} answering 307 towards the active node —
 *       point {@code push2u.signer.vault.address} at the active node's {@code api_addr} (or a load balancer in front of
 *       it), or terminate the redirect in the proxy;
 *   <li>otherwise a {@link JdkVaultHttpTransport} built entirely from the properties.
 * </ol>
 *
 * The qualifier keeps the Vault client separate from any push-delivery {@code HttpClient} the application may define —
 * the two transports face different trust domains on purpose.
 */
@AutoConfiguration(beforeName = "com.the13haven.push2u.spring.Push2uAutoConfiguration")
@EnableConfigurationProperties(VaultSignerProperties.class)
public final class VaultSignerAutoConfiguration {

    VaultSignerAutoConfiguration() {
        // Explicit + package-private: the autoconfiguration is framework plumbing, not public API;
        // Spring still instantiates it reflectively. (This also avoids an undocumented public
        // default constructor that Javadoc/doclint flags.)
    }

    /**
     * The Vault Transit signer, built from {@code push2u.signer.vault.*}. Absent unless the address, key name and token
     * are all set, and yields to an application-supplied signer.
     *
     * @param properties the bound configuration
     * @param transport an optional application {@link VaultHttpTransport} for the Vault calls
     * @param vaultHttpClient an optional {@code "push2uVaultHttpClient"}-qualified {@link HttpClient} the default
     *     transport wraps when no transport bean exists
     * @return the signer
     */
    @Bean
    @ConditionalOnMissingBean(VapidSigner.class)
    @ConditionalOnProperty(
            prefix = "push2u.signer.vault",
            name = {"address", "key-name", "token"})
    VapidSigner vaultTransitVapidSigner(
            VaultSignerProperties properties,
            ObjectProvider<VaultHttpTransport> transport,
            @Qualifier("push2uVaultHttpClient") ObjectProvider<HttpClient> vaultHttpClient) {
        VaultHttpTransport resolved = resolveTransport(properties, transport, vaultHttpClient);
        // @ConditionalOnProperty already gates this bean on all three being set; restated as checks
        // so the contract holds in the type system too, and so a future change to the condition
        // fails here naming the property rather than with a NullPointerException.
        URI address = Objects.requireNonNull(properties.address(), "push2u.signer.vault.address");
        // The value types (and the mount step) validate on construction; each rejection is
        // re-thrown with the YAML property name in front, the same translation every other
        // configuration failure in this starter gets — the library's message names the Java-side
        // viewpoint, not the property the operator wrote. The token's message carries no part of
        // the value, so the translation cannot leak it either.
        TransitKeyName keyName = translated(
                "push2u.signer.vault.key-name",
                () -> new TransitKeyName(Objects.requireNonNull(properties.keyName(), "push2u.signer.vault.key-name")));
        VaultToken token = translated(
                "push2u.signer.vault.token",
                () -> new VaultToken(Objects.requireNonNull(properties.token(), "push2u.signer.vault.token")));
        String publicKey = properties.publicKey();
        Integer keyVersion = properties.keyVersion();
        String namespace = properties.namespace();
        if (publicKey == null || publicKey.isBlank()) {
            if (keyVersion != null) {
                throw new IllegalStateException(
                        "push2u.signer.vault.key-version requires push2u.signer.vault.public-key: in the"
                                + " fetched mode the signer pins the key version it reads from Vault itself");
            }
            // Fetched mode: the signer reads the public key + key version from transit/keys/<key> at
            // construction and pins that version, keeping the Transit key the single source of truth
            // (the token needs `read` on the key). The factory validates the address (the key name
            // and token are already-valid value types), so an IllegalArgumentException out of this
            // call is the address's and is translated to its YAML property name.
            VaultTransitVapidSigner.FetchedPublicKeyBuilder fetched = translated(
                    "push2u.signer.vault.address",
                    () -> VaultTransitVapidSigner.builderWithFetchedPublicKey(address, keyName, token));
            translated("push2u.signer.vault.mount", () -> fetched.mount(properties.mount()));
            if (namespace != null) {
                translated("push2u.signer.vault.namespace", () -> fetched.namespace(namespace));
            }
            return fetched.transport(resolved).build();
        }
        // Explicit mode: the published public key is supplied; the token needs only `sign`. Without a
        // key-version the sign requests use Vault's latest key version — rotation-unsafe by contract.
        // The factory validates two of its arguments — the supplied key's shape and the address — so
        // one translated call could not attribute a rejection to the right property. The key is
        // probed first with the same core check the factory applies; whatever IllegalArgumentException
        // then escapes the factory call is the address's.
        byte[] decodedPublicKey = decodePublicKey(publicKey);
        translated("push2u.signer.vault.public-key", () -> {
            P256PublicKeys.requireUncompressedPoint(decodedPublicKey, "public-key");
            return decodedPublicKey;
        });
        VaultTransitVapidSigner.SuppliedPublicKeyBuilder builder = translated(
                "push2u.signer.vault.address",
                () -> VaultTransitVapidSigner.builderWithSuppliedPublicKey(address, keyName, token, decodedPublicKey));
        translated("push2u.signer.vault.mount", () -> builder.mount(properties.mount()));
        if (namespace != null) {
            translated("push2u.signer.vault.namespace", () -> builder.namespace(namespace));
        }
        builder.transport(resolved);
        if (keyVersion != null) {
            builder.keyVersion(keyVersion);
        }
        return builder.build();
    }

    /**
     * Runs {@code supplier} and re-throws its {@link IllegalArgumentException} with {@code property} prefixed — the
     * library's own message names the builder's viewpoint, not the YAML the operator wrote. The cause is kept: the
     * original message carries the actual constraint.
     */
    private static <T> T translated(String property, Supplier<T> supplier) {
        try {
            return supplier.get();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(property + ": " + e.getMessage(), e);
        }
    }

    /**
     * The configured public key, decoded from base64url. {@link Base64}'s own message names neither the property nor
     * the expected encoding, and a context failure that only says "Illegal base64 character" leaves the operator
     * guessing which of the {@code push2u.*} values is at fault.
     */
    private static byte[] decodePublicKey(String publicKey) {
        try {
            return Base64.getUrlDecoder().decode(publicKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "push2u.signer.vault.public-key is not base64url: expected the 65-byte uncompressed"
                            + " P-256 point as base64url (RFC 4648 §5)",
                    e);
        }
    }

    /** Transport priority: {@code VaultHttpTransport} bean > qualified {@code HttpClient} > defaults. */
    private static VaultHttpTransport resolveTransport(
            VaultSignerProperties properties,
            ObjectProvider<VaultHttpTransport> transport,
            ObjectProvider<HttpClient> vaultHttpClient) {
        VaultHttpTransport supplied = transport.getIfAvailable();
        if (supplied != null) {
            return supplied;
        }
        HttpClient client = vaultHttpClient.getIfAvailable();
        if (client == null) {
            // Redirect.NEVER is set here rather than inherited from the JDK's default, the same
            // way JdkVaultHttpTransport's own no-argument constructor does it: the property is
            // the library's invariant, not the JDK's to change.
            client = HttpClient.newBuilder()
                    .connectTimeout(properties.connectTimeout())
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        }
        return new JdkVaultHttpTransport(client, properties.requestTimeout(), properties.maxResponseBytes());
    }
}
