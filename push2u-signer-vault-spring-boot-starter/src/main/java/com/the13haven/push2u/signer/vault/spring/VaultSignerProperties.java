package com.the13haven.push2u.signer.vault.spring;

import java.net.URI;
import java.time.Duration;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Binds {@code push2u.signer.vault.*} for the Vault Transit signer starter.
 *
 * <p>The transport properties ({@code request-timeout}, {@code connect-timeout}, {@code max-response-bytes}) shape the
 * default {@code JdkVaultHttpTransport} the starter builds. They are ignored when the application supplies its own
 * {@code VaultHttpTransport} bean, and {@code connect-timeout} is additionally ignored when a
 * {@code push2uVaultHttpClient}-qualified {@code HttpClient} bean is supplied (the client owns its connect timeout).
 *
 * @param address the Vault base address, e.g. {@code https://vault.example:8200}
 * @param mount the Transit mount path (default {@code transit})
 * @param keyName the {@code ecdsa-p256} Transit key name
 * @param token the Vault token authorising {@code sign} on the key (plus {@code read} on {@code transit/keys/<key>}
 *     when {@code publicKey} is omitted)
 * @param publicKey the VAPID public key as base64url (the 65-byte uncompressed P-256 point); <b>optional</b> — when
 *     null/blank the signer reads it from Vault at startup
 * @param keyVersion the Transit key version {@code publicKey} belongs to, pinned on every sign request; <b>optional</b>
 *     and only valid together with {@code publicKey} (the fetched mode pins the version it reads from Vault itself).
 *     Without it the explicit mode signs with Vault's latest version, which breaks after a key rotation — set it
 *     whenever the Transit key may ever be rotated
 * @param requestTimeout the per-request timeout for every Vault call (default 30s; must be positive) — bounds the whole
 *     exchange, so a Vault that accepts the connection but never answers cannot hang application startup
 * @param connectTimeout the connect timeout of the default HTTP client (default 10s; must be positive)
 * @param maxResponseBytes the Vault response-size cap in raw bytes (default 1048576 = 1 MiB; must be positive); an
 *     oversized response fails the call instead of being truncated
 *     <p>The three transport defaults restate {@code JdkVaultHttpTransport}'s own ({@code DEFAULT_REQUEST_TIMEOUT},
 *     {@code DEFAULT_CONNECT_TIMEOUT}, {@code DEFAULT_MAX_RESPONSE_BYTES}): {@code @DefaultValue} takes literals, and
 *     those constants are module-private. Keep the two in step when either changes.
 */
@ConfigurationProperties("push2u.signer.vault")
public record VaultSignerProperties(
        @Nullable URI address,
        @DefaultValue("transit") String mount,
        @Nullable String keyName,
        @Nullable String token,
        @Nullable String publicKey,
        @Nullable Integer keyVersion,
        @DefaultValue("30s") Duration requestTimeout,
        @DefaultValue("10s") Duration connectTimeout,
        @DefaultValue("1048576") int maxResponseBytes) {

    /**
     * Rejects non-positive transport settings at binding time — a zero or negative timeout would silently disable the
     * hang protection, and a non-positive cap can never buffer a response.
     */
    public VaultSignerProperties {
        if (requestTimeout == null || requestTimeout.isZero() || requestTimeout.isNegative()) {
            throw new IllegalArgumentException(
                    "push2u.signer.vault.request-timeout must be positive, got " + requestTimeout);
        }
        if (connectTimeout == null || connectTimeout.isZero() || connectTimeout.isNegative()) {
            throw new IllegalArgumentException(
                    "push2u.signer.vault.connect-timeout must be positive, got " + connectTimeout);
        }
        if (maxResponseBytes <= 0) {
            throw new IllegalArgumentException(
                    "push2u.signer.vault.max-response-bytes must be positive, got " + maxResponseBytes);
        }
    }

    /**
     * The record-generated {@code toString()} prints every component, {@code token} included — and while push2u never
     * stringifies this record and the actuator env/configprops endpoints mask values by default, the consuming
     * application is one accidental {@code log.info("{}", properties)} or debugger dump away from its live Vault token
     * in a log line. The token renders as {@code ***} when set (and as {@code null} when not, so the mask never reads
     * as "a token is configured"); everything else keeps the generated shape.
     */
    @Override
    public String toString() {
        return "VaultSignerProperties[address=" + address
                + ", mount=" + mount
                + ", keyName=" + keyName
                + ", token=" + (token == null ? null : "***")
                + ", publicKey=" + publicKey
                + ", keyVersion=" + keyVersion
                + ", requestTimeout=" + requestTimeout
                + ", connectTimeout=" + connectTimeout
                + ", maxResponseBytes=" + maxResponseBytes + "]";
    }
}
