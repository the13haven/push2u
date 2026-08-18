/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

import com.the13haven.push2u.P256PublicKeys;
import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.VapidSigner;
import com.the13haven.push2u.VapidSignerUnavailableException;

/**
 * A {@link VapidSigner} that signs the VAPID JWT via HashiCorp Vault Transit — the private key never leaves Vault. It
 * POSTs the signing input to {@code {vaultAddress}/v1/{mount}/sign/{keyName}} — any trailing slash of the address
 * dropped before the join — with {@code marshaling_algorithm=jws}, so Vault returns the raw {@code r || s} pair JOSE
 * wants, and decodes it.
 *
 * <p><b>The Vault address</b> is validated at both factory methods: it must be an absolute URI with a host and must
 * carry neither a query nor a fragment — Vault API paths are appended to it, so neither could survive the join. A path
 * is legal and preserved: {@code https://gw.example/vault} (with or without a trailing slash — the two are the same
 * base) addresses a Vault served under the {@code /vault} prefix of a reverse proxy or Kubernetes ingress, and the
 * signer then calls {@code https://gw.example/vault/v1/{mount}/sign/{keyName}}. The path follows the same per-segment
 * rule as {@code mount} — every {@code /}-separated segment non-empty, not {@code .} or {@code ..}, drawn from
 * {@code [A-Za-z0-9_.-]} — for the same reasons (see {@link #requireValidVaultPath}'s rationale): the prefix rides in
 * front of every token-bearing request path, so a segment a normalizing hop would rewrite must fail loudly at
 * configuration instead.
 *
 * <p><b>The scheme</b> must be {@code http} or {@code https} — compared case-insensitively, as RFC 3986 §3.1 defines
 * schemes — because the signer speaks Vault's HTTP API and nothing else; any other scheme is rejected at the factory.
 * {@code https} is always accepted. Plain {@code http} is accepted without ceremony only when the host is a <em>literal
 * loopback</em>: {@code localhost}, a name under {@code .localhost}, an IPv4 dotted-quad in {@code 127.0.0.0/8}
 * (canonical decimal, no leading zeros), or a bracketed IP literal that denotes a loopback address — {@code [::1]} in
 * any of its spellings, and equally {@code [::ffff:127.0.0.1]} or {@code [::ffff:7f00:1]}, the IPv4-mapped writings of
 * a {@code 127.0.0.0/8} address, whose traffic goes to that IPv4 loopback and so no further than the {@code 127.0.0.1}
 * form does. That carve-out is the Vault Agent and service-mesh sidecar pattern — the application talks plain HTTP to
 * {@code http://127.0.0.1:8200}, and the agent beside it terminates TLS — a mainstream production deployment, not a
 * development convenience. {@code http} to any other host makes {@code build()} throw unless the builder's optional
 * {@code allowInsecureHttp()} step was called: the Vault token travels in the {@code X-Vault-Token} request header, and
 * over plain HTTP to a remote host it would cross the network in clear text. Loopback is decided from the literal host
 * text, never by resolving the name, so the rule stays readable from the address alone — {@code http://my-vault}
 * pointing at {@code 127.0.0.1} through the hosts file still needs the opt-in.
 *
 * <p>The Vault key must be an {@code ecdsa-p256} Transit key. The VAPID public key is your published identity; Vault
 * holds only the private half. There are three ways to obtain the public key, one builder each — they differ in
 * contract, not merely in parameters, which is why none of them is the default:
 *
 * <ul>
 *   <li><b>Explicit</b> ({@link #builderWithSuppliedPublicKey(URI, TransitKeyName, VaultToken, byte[])} — the builder
 *       is named for what the caller does, supply the key) — pass the 65-byte X9.62 uncompressed point. {@code build()}
 *       performs no I/O. The Vault token then needs only the {@code sign} capability ({@code update} on
 *       {@code transit/sign/<key>}); the public key is never read from Vault. Use this for a strict sign-only token or
 *       an air-gapped public key.
 *       <p>The supplied key is validated as a <em>point on P-256</em> — 65 bytes with the {@code 0x04} uncompressed
 *       tag, both coordinates in the field, the curve equation satisfied — because the {@link VapidSigner} contract
 *       requires exactly that of {@code publicKey()}, and no legal VAPID key can fail it. What nothing here can check
 *       is that it is the public half of the Transit key being signed with: that remains the caller's responsibility,
 *       and a mismatch surfaces on the first signature to a VAPID-bound subscription, as a push-service rejection of
 *       the JWT. The Vault-side validation described below applies to the fetched mode alone.
 *   <li><b>Fetched</b> ({@link #builderWithFetchedPublicKey(URI, TransitKeyName, VaultToken)}) — omit the public key.
 *       The signer reads {@code transit/keys/<key>} once, inside {@code build()} (a {@code GET}), takes the
 *       {@code latest_version} and <em>that version's</em> public key as an atomic pair, and reduces the PEM to the
 *       uncompressed point. This keeps a <em>single source of truth</em> — the Transit key — so the published key can
 *       never drift from the signing key. The token additionally needs {@code read} on {@code transit/keys/<key>}
 *       (which exposes only the public keys + metadata, never private material). This is the recommended mode.
 *       <p>Construction fails fast unless the key really is P-256: the response's {@code type} must be
 *       {@code ecdsa-p256} (or Vault Enterprise's {@code managed_key}), and the parsed public key must carry P-256's
 *       domain parameters <em>and</em> be a point that satisfies the curve equation. The checks are independent — the
 *       type is only Vault's claim about the key, while the curve checks inspect the key material itself — and any
 *       failure raises a {@link PushCryptoException} at construction instead of surfacing as an unexplained
 *       push-service rejection on the first send.
 *   <li><b>Deferred fetch</b> ({@link #builderWithDeferredPublicKeyFetch(URI, TransitKeyName, VaultToken)}) — the same
 *       fetched key, read at first use instead of at construction: what is deferred is the <em>call</em>, not the key.
 *       {@code build()} contacts Vault not at all, so an application whose context is refreshed while Vault is still
 *       sealing, unsealing or mounting starts anyway; the first {@code sign}, {@code publicKey} or
 *       {@code publicKeyBase64Url} performs the one {@code transit/keys/<key>} read, with the same atomic
 *       version-and-key pair and the same P-256 validation the eager fetched mode applies at construction — moved in
 *       time, not weakened. A successful pair is retained for the signer's lifetime; a failed or interrupted read is
 *       never remembered, so a later call simply tries again. The token needs the same {@code sign} plus {@code read}
 *       capabilities as the eager fetched mode.
 * </ul>
 *
 * <p>Both Vault calls — the Transit {@code sign} POST and the fetched modes' one-time {@code transit/keys} read, at
 * startup or at first use — go through this module's {@link VaultHttpTransport} seam (default
 * {@link JdkVaultHttpTransport}), so an application's mTLS, proxy, or observability transport applies to the metadata
 * read as much as to signing. Deliberately <em>not</em> push2u-core's {@code PushHttpClient}: push delivery talks to
 * untrusted capability URLs and discards response bodies, while Vault's responses must be read — buffered under the
 * transport's size cap and per-request timeout. The small Vault request/response JSON is built and parsed by hand — no
 * JSON library.
 *
 * <p>Every factory method takes everything required — the Vault base address, the {@link TransitKeyName} and the
 * {@link VaultToken} — so an incomplete signer cannot be expressed and {@code build()} never refuses over a missing
 * value; the value types keep the arguments impossible to swap and carry their own validation. The builders hold only
 * the optional steps: {@code mount} (default {@code "transit"}), {@code namespace} (default none — see below),
 * {@code transport} (default {@link JdkVaultHttpTransport}) and {@code allowInsecureHttp()} (off by default — see the
 * scheme rule above). Only the supplied-key builder has {@code keyVersion} — in the fetched modes the version is
 * Vault's to state, not the caller's.
 *
 * <p><b>Vault namespaces (Enterprise/HCP):</b> when the Transit engine lives inside a <a
 * href="https://developer.hashicorp.com/vault/docs/enterprise/namespaces">Vault Enterprise or HCP Vault namespace</a>,
 * set it with the builders' {@code namespace(...)} step. The signer then sends the {@code X-Vault-Namespace} header on
 * <em>both</em> Vault calls — every Transit {@code sign} POST and the fetched modes' one-time {@code transit/keys}
 * read. Without the step no such header is sent at all, which is what Vault OSS (which has no namespaces) expects.
 *
 * <p><b>Key rotation:</b> the fetched modes capture the key version together with its public key — at construction, or
 * at first use in the deferred mode — and pin that version on every {@code sign} call ({@code key_version} in the
 * request body), so signatures always match the advertised public key — rotating the Transit key in Vault does not
 * break signing <em>by itself</em>. What the pin does not survive is the operator raising the key's
 * {@code min_encryption_version} above the pinned version: Vault then rejects sign requests carrying that
 * {@code key_version}, and every {@code sign} call fails loudly with a {@link PushCryptoException}. Trimming old key
 * versions (raising {@code min_available_version}) deletes the pinned version outright and breaks signing the same way.
 * Recover by recreating the signer (a fetched mode re-reads the then-latest version and its public key) or, in the
 * explicit mode, by supplying the new version's public key with the matching {@code keyVersion}. The rotated key is
 * also not picked up until the signer is recreated, which is the behaviour VAPID wants: the public key is your
 * published identity, and push subscriptions pin it at subscribe time. There is deliberately no operation that re-reads
 * the key on a live signer: swapping the advertised key under a live sender would not adopt a new identity but
 * invalidate every subscription taken out under the old one — RFC 8292 §4.2 entitles a push service to refuse a JWT
 * whose key is not the one the subscription was created under — so adopting a new key version is a migration built on a
 * <em>new</em> signer and a new sender, run beside the old pair until the subscriptions created under the previous key
 * are gone. The explicit mode pins whatever version {@link SuppliedPublicKeyBuilder#keyVersion(int)} was given.
 * Omitting that step sends no {@code key_version}, so Vault signs with the latest — that form is only safe if the
 * Transit key is never rotated; set {@code keyVersion} otherwise.
 */
// GodClass / complexity: the bulk of this class is the anchored JSON reader for Vault's responses
// (see extractSignature). Keeping it here is what keeps the module free of an implementation
// dependency — pulling a
// JSON library in would trade these metrics for a transitive surface the library exists to avoid.
// ExcessiveImports / CouplingBetweenObjects: the deferred mode's first-use initialization crossed
// PMD's count thresholds. It lives in this class because the retained pair, the flight record and
// the two Vault calls are one object's private state — a class of its own would either export that
// state or grow a wider constructor than the coupling it removes.
@SuppressWarnings({
    "PMD.GodClass",
    "PMD.CyclomaticComplexity",
    "PMD.CognitiveComplexity",
    "PMD.ExcessiveImports",
    "PMD.CouplingBetweenObjects"
})
public final class VaultTransitVapidSigner implements VapidSigner {

    /**
     * Vault's marshalled signature envelope: the literal {@code vault}, the key version (captured — a pinned signer
     * checks it against its pin in {@link #stripVaultPrefix}), and the base64url payload, whose alphabet
     * ({@code A-Za-z0-9-_} plus {@code =} padding) contains no colon — so the payload group cannot swallow a further
     * separator. The payload is allowed to be empty on purpose: {@code vault:v1:} is a well-formed envelope carrying no
     * signature, and the length check in {@link #sign} reports that far more usefully ("expected 64 bytes, got 0") than
     * a format complaint would.
     */
    private static final Pattern VAULT_SIGNATURE = Pattern.compile("vault:v(\\d+):([A-Za-z0-9\\-_]*={0,2})");
    /**
     * Cap for response text echoed into exception messages — enough context, log-safe size. It bounds the escaped
     * excerpt including its truncation marker, so no message carries more than this many characters of a response
     * however many of them had to be escaped.
     */
    private static final int ERROR_ECHO_LIMIT = 2048;
    /** Width of one escaped character in an echoed excerpt: a backslash, a {@code u} and four hex digits. */
    private static final int ESCAPE_LENGTH = 6;
    /** {@code U+2028}, a line break by the Unicode rules although its category is punctuation, not control. */
    private static final int LINE_SEPARATOR = 0x2028;
    /** {@code U+2029}, the paragraph counterpart of {@link #LINE_SEPARATOR} and a line break for the same reason. */
    private static final int PARAGRAPH_SEPARATOR = 0x2029;

    private static final int UNCOMPRESSED_LENGTH = 65;
    private static final int COORDINATE_LENGTH = 32;
    private static final byte UNCOMPRESSED_TAG = 0x04;
    /**
     * JCA names for the one curve Web Push uses. Copied rather than shared: core's equivalents
     * ({@code com.the13haven.push2u.Algorithms}, {@code com.the13haven.push2u.EcKeys}) are package-private internals,
     * and widening core's public API for two string literals would trade a real API commitment for a trivial saving.
     */
    private static final String EC = "EC";

    private static final String SECP256R1 = "secp256r1";
    /**
     * The Vault Transit key type VAPID needs: RFC 8292 §2 mandates ES256, i.e. ECDSA over NIST P-256. Vault reports it
     * as {@code data.type} of {@code transit/keys/<name>}.
     */
    private static final String REQUIRED_KEY_TYPE = "ecdsa-p256";
    /**
     * Vault Enterprise's HSM/KMS-backed key type, whose {@code data.type} describes the wrapper instead of the curve —
     * accepted on the strength of the curve check (see {@link #requireP256KeyType}).
     */
    private static final String MANAGED_KEY_TYPE = "managed_key";
    /** An ES256 signature is exactly {@code r || s}, two 32-byte big-endian scalars. */
    private static final int SIGNATURE_LENGTH = 2 * COORDINATE_LENGTH;
    /** The Transit mount path both builders assume unless {@code mount(...)} says otherwise — Vault's own default. */
    private static final String DEFAULT_MOUNT = "transit";
    /** The one scheme always acceptable for the Vault address: TLS keeps the token confidential on the wire. */
    private static final String HTTPS_SCHEME = "https";
    /** Acceptable only towards a literal loopback host, or with the builders' explicit {@code allowInsecureHttp()}. */
    private static final String HTTP_SCHEME = "http";
    /** The header carrying the Vault token on every Vault call. */
    private static final String TOKEN_HEADER = "X-Vault-Token";
    /** The header addressing a Vault Enterprise/HCP namespace — sent only when {@code namespace(...)} was set. */
    private static final String NAMESPACE_HEADER = "X-Vault-Namespace";
    /**
     * How many suppressed entries one failed read's exception may carry before this signer stops adding to it. Small on
     * purpose: the recordings made here come in at most a handful of distinct shapes for one failure, so a few of them
     * carry every distinct thing that can be said, and anything beyond that is the same sentence repeated by a defect
     * that repeats. Entries a consumer recorded itself count towards it, which is the conservative direction — an
     * exception already carrying that many diagnostics is not one this signer has to add a further one to. The bound
     * holds under concurrent recording, which takes holding the exception's own monitor across the check and the
     * recording together: one flight per signer serialises the description within a signer and not across several, so
     * several signers over one transport can describe one shared instance at the same moment, and each of them would
     * otherwise pass a check at seven and record anyway.
     */
    private static final int SUPPRESSED_RECORDING_CEILING = 8;
    /**
     * How far the interruption test walks a failure's cause chain before it stops. A chain a defective transport
     * fabricates fresh on every read is acyclic and endless, so the identity set that ends a cycle never fires on it:
     * without this bound the walk spins and allocates until the process dies, and the one flight it runs inside is
     * never released — which parks every caller of a deferred signer on a latch nobody counts down. High on purpose, so
     * that reaching it cannot mean an honest chain was cut short: a real diagnostic is a handful of elements deep, and
     * this sits two orders of magnitude beyond that.
     */
    private static final int CAUSE_CHAIN_CEILING = 1000;

    private final VaultHttpTransport transport;
    private final URI signUri;
    private final String token;
    /** The Vault Enterprise/HCP namespace every call addresses; {@code null} sends no namespace header. */
    @Nullable
    private final String namespace;

    /**
     * The signer's published identity — the key version every {@code sign} call pins beside the public key it belongs
     * to — as one immutable pair behind a single volatile field. The two immediate modes write it in the constructor
     * and it never changes; the deferred mode leaves it unset until the first successful metadata read publishes it,
     * and from that moment it is equally final in effect: only a successful pair is ever written, exactly once, and it
     * is retained for the signer's lifetime because the advertised key is the identity subscriptions are bound to.
     */
    @Nullable
    private volatile VaultKeyMetadata metadata;

    /** The deferred mode's first-use initialization; {@code null} in the two modes that hold their pair from birth. */
    @Nullable
    private final DeferredInitialization deferredInitialization;

    /**
     * The (version, public key) pair, read atomically from one {@code transit/keys/<name>} response in the fetched
     * modes; the supplied mode carries the caller's key here with the version it pinned, or none. A {@code null}
     * version sends no {@code key_version}, so Vault signs with its latest.
     */
    // ArrayRecordComponent: a private carrier that never escapes this class — every array wrapped
    // here is freshly produced or defensively copied first, and publicKey() clones on the way out.
    @SuppressWarnings("ArrayRecordComponent")
    private record VaultKeyMetadata(@Nullable Integer version, byte[] publicKey) {}

    /**
     * A builder for the <b>fetched</b> mode: {@link FetchedPublicKeyBuilder#build()} reads {@code transit/keys/<key>}
     * from Vault, so it performs I/O and can fail — with {@link VapidSignerUnavailableException} where Vault cannot
     * serve the read now, and with {@link PushCryptoException} where the failure recurs; {@code build()}'s own
     * documentation carries the order a startup supervisor reads those in, interruption first. It has no
     * {@code keyVersion} step — the version comes from Vault together with the public key it belongs to, as one atomic
     * pair.
     *
     * @param address the Vault base address, e.g. {@code https://vault.example:8200} — or, for a Vault behind a reverse
     *     proxy or ingress prefix, e.g. {@code https://gw.example/vault} (see the class Javadoc for the address
     *     contract; the scheme must be {@code http} or {@code https}, and plain {@code http} beyond a literal loopback
     *     host additionally needs the builder's {@code allowInsecureHttp()} step). Userinfo in the address is
     *     preserved, but the built-in transport does not use it — no {@code Authorization} header is formed from it;
     *     Vault authentication is the token. A custom {@link VaultHttpTransport} may honour it, e.g. for a basic-auth
     *     fronting proxy
     * @param keyName the {@code ecdsa-p256} Transit key name
     * @param token the Vault token authorising {@code sign} on the key plus {@code read} on {@code transit/keys/<key>}
     *     (this mode reads the key metadata)
     * @return a new builder
     * @throws IllegalArgumentException if {@code address} is not an absolute URI with a host, has a scheme other than
     *     {@code http} or {@code https} (case-insensitive), carries a query or fragment, or has a path violating the
     *     per-segment rule (empty, {@code .} or {@code ..} segments, or characters outside {@code [A-Za-z0-9_.-]})
     */
    public static FetchedPublicKeyBuilder builderWithFetchedPublicKey(
            URI address, TransitKeyName keyName, VaultToken token) {
        return new FetchedPublicKeyBuilder(address, keyName, token);
    }

    /**
     * A builder for the <b>explicit</b> mode: the caller supplies the published VAPID public key, and
     * {@link SuppliedPublicKeyBuilder#build()} contacts nothing. The Vault token then needs only {@code sign}.
     *
     * @param address the Vault base address, e.g. {@code https://vault.example:8200} — or, for a Vault behind a reverse
     *     proxy or ingress prefix, e.g. {@code https://gw.example/vault} (see the class Javadoc for the address
     *     contract; the scheme must be {@code http} or {@code https}, and plain {@code http} beyond a literal loopback
     *     host additionally needs the builder's {@code allowInsecureHttp()} step). Userinfo in the address is
     *     preserved, but the built-in transport does not use it — no {@code Authorization} header is formed from it;
     *     Vault authentication is the token. A custom {@link VaultHttpTransport} may honour it, e.g. for a basic-auth
     *     fronting proxy
     * @param keyName the {@code ecdsa-p256} Transit key name
     * @param token the Vault token authorising {@code sign} on the key — this mode never reads the key metadata, so a
     *     sign-only token is enough
     * @param publicKey the VAPID public key — a 65-byte X9.62 uncompressed point on the P-256 curve, validated here
     *     ({@link P256PublicKeys#requireOnCurve}) because the {@link VapidSigner} contract requires it; that it is the
     *     public half of the Transit key remains the caller's responsibility
     * @return a new builder
     * @throws IllegalArgumentException if {@code publicKey} does not encode a point on P-256, or if {@code address}
     *     violates the contract of {@link #builderWithFetchedPublicKey(URI, TransitKeyName, VaultToken)}
     */
    public static SuppliedPublicKeyBuilder builderWithSuppliedPublicKey(
            URI address, TransitKeyName keyName, VaultToken token, byte[] publicKey) {
        return new SuppliedPublicKeyBuilder(address, keyName, token, publicKey);
    }

    /**
     * A builder for the <b>deferred fetch</b> mode: the public key and its version come from Vault, exactly as in the
     * fetched mode, but the {@code transit/keys/<key>} read happens at first use instead of inside
     * {@link DeferredPublicKeyFetchBuilder#build()} — what is deferred is the <em>call</em>, not the key. Use it where
     * the application must start while Vault may still be sealing, unsealing or mounting — a Vault brought up beside
     * the application rather than before it — and where the key should still be stated in exactly one place.
     *
     * @param address the Vault base address, e.g. {@code https://vault.example:8200} — or, for a Vault behind a reverse
     *     proxy or ingress prefix, e.g. {@code https://gw.example/vault} (see the class Javadoc for the address
     *     contract; the scheme must be {@code http} or {@code https}, and plain {@code http} beyond a literal loopback
     *     host additionally needs the builder's {@code allowInsecureHttp()} step). Userinfo in the address is
     *     preserved, but the built-in transport does not use it — no {@code Authorization} header is formed from it;
     *     Vault authentication is the token. A custom {@link VaultHttpTransport} may honour it, e.g. for a basic-auth
     *     fronting proxy
     * @param keyName the {@code ecdsa-p256} Transit key name
     * @param token the Vault token authorising {@code sign} on the key plus {@code read} on {@code transit/keys/<key>}
     *     (this mode reads the key metadata, merely later than the fetched one)
     * @return a new builder
     * @throws IllegalArgumentException if {@code address} is not an absolute URI with a host, has a scheme other than
     *     {@code http} or {@code https} (case-insensitive), carries a query or fragment, or has a path violating the
     *     per-segment rule (empty, {@code .} or {@code ..} segments, or characters outside {@code [A-Za-z0-9_.-]})
     */
    public static DeferredPublicKeyFetchBuilder builderWithDeferredPublicKeyFetch(
            URI address, TransitKeyName keyName, VaultToken token) {
        return new DeferredPublicKeyFetchBuilder(address, keyName, token);
    }

    private VaultTransitVapidSigner(
            URI vaultAddress,
            String mount,
            @Nullable String namespace,
            TransitKeyName keyName,
            VaultToken token,
            @Nullable Integer keyVersion,
            byte[] publicKey,
            VaultHttpTransport transport) {
        Objects.requireNonNull(vaultAddress, "vaultAddress");
        Objects.requireNonNull(mount, "mount");
        Objects.requireNonNull(keyName, "keyName");
        Objects.requireNonNull(publicKey, "publicKey");
        // The full on-curve check: the VapidSigner contract (and the published conformance kit)
        // requires publicKey() to return a point on P-256, so a signer violating it must be
        // unbuildable. For the fetched mode's array this re-checks what fetchKeyMetadata already
        // validated; what no check here can establish is the supplied key's agreement with the
        // Transit key — that surfaces on the first signature (see the class Javadoc).
        P256PublicKeys.requireOnCurve(publicKey, "publicKey");
        if (keyVersion != null && keyVersion < 1) {
            throw new IllegalArgumentException("keyVersion must be >= 1, got " + keyVersion);
        }
        this.signUri = vaultApiUri(vaultAddress, "/v1/" + mount + "/sign/" + keyName.value());
        // Unwrapped once, here: a VaultToken is valid by construction (visible ASCII, hence
        // header-safe), so nothing downstream re-validates it — and the raw String never
        // reaches any toString() or exception message.
        this.token = Objects.requireNonNull(token, "token").value();
        // Validated at the namespace(...) step that set it (allowed set [A-Za-z0-9_.-] plus '/'),
        // so by construction the value is visible ASCII and header-safe — see requireValidVaultPath.
        this.namespace = namespace;
        this.metadata = new VaultKeyMetadata(keyVersion, publicKey.clone());
        this.deferredInitialization = null;
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    /**
     * The deferred-fetch constructor: no pair yet, and the {@code transit/keys/<keyName>} URI kept for the first-use
     * read that will publish one. Everything local is validated exactly as the other constructors validate it; what is
     * absent is only what a Vault response would have supplied.
     */
    private VaultTransitVapidSigner(
            URI vaultAddress,
            String mount,
            @Nullable String namespace,
            TransitKeyName keyName,
            VaultToken token,
            VaultHttpTransport transport) {
        Objects.requireNonNull(vaultAddress, "vaultAddress");
        Objects.requireNonNull(mount, "mount");
        Objects.requireNonNull(keyName, "keyName");
        this.signUri = vaultApiUri(vaultAddress, "/v1/" + mount + "/sign/" + keyName.value());
        // Unwrapped once, as in the canonical constructor: valid by construction, never printed.
        this.token = Objects.requireNonNull(token, "token").value();
        this.namespace = namespace;
        // The pair field stays unset here — the first successful read is its only writer.
        this.deferredInitialization =
                new DeferredInitialization(vaultApiUri(vaultAddress, "/v1/" + mount + "/keys/" + keyName.value()));
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    /**
     * The signer's (version, public key) pair: the one it was built with, or — in the deferred mode — the one the first
     * use reads from Vault, initializing if no successful read has published a pair yet.
     */
    private VaultKeyMetadata keyMetadata() {
        VaultKeyMetadata current = metadata;
        if (current != null) {
            return current;
        }
        // Only the deferred mode can arrive here: the other two constructors publish the pair
        // before the signer exists.
        return Objects.requireNonNull(deferredInitialization, "deferredInitialization")
                .initialize();
    }

    /**
     * The deferred mode's first-use initialization: at most one metadata read in flight per signer, and only a
     * successful pair ever retained.
     *
     * <p><b>At most one flight is active at a time</b> — the signer's own record of an active fetch,
     * {@code activeFlight}, is what bounds the reads it starts. Without that bound, a cold fan-out of N concurrent
     * senders would open N reads of one value against a custodian that audits every request; with it, one caller
     * fetches and the rest wait on that caller's read, bounded by the transport's own connect and request timeouts and
     * by nothing added here. The bound is over reads this signer <em>starts</em>: a transport whose request was
     * abandoned may still be finishing I/O underneath, and nothing here reaches into that.
     *
     * <p><b>A flight ends in one of four ways, and the three that do not succeed are distinct on purpose.</b> A
     * successful pair is published through the signer's one volatile field and kept for the signer's lifetime. A
     * failure of one of the two contract types — the custodian unable to serve the read now, or a failure that recurs —
     * is shared with the callers already waiting on this flight and then forgotten: each waiter throws its own fresh
     * exception built from an immutable description of the failure, and a caller arriving after the flight ended starts
     * a new read, because a custodian that could not serve a moment ago is exactly the thing that recovers on its own
     * terms and remembering the refusal would turn a transient outage into a permanent one. Sharing such a failure
     * depends on describing it, which is done by calling the failure's own overridable members, so one of those
     * throwing leaves a contract-type failure shared with nobody — its caller still keeps it, and its waiters retry as
     * they do after any abandoned flight. A cancellation of the fetching caller is not shared at all — handing it to
     * threads nobody interrupted would convert their calls into cancellations they never asked for — so the fetching
     * caller keeps its own exception, the flight is abandoned, and the waiters retry with one of them taking over. And
     * a failure of neither contract type is a defect in a replaceable transport: it reaches its own caller exactly as
     * thrown, is never laundered into a contract type, and abandons the flight the way a cancellation does — as does
     * anything the transport lets out that is not a {@code RuntimeException} at all, since an implementation written in
     * a language without checked exceptions can deliver one through a method that declares none, and a flight left
     * recorded as active would be a signer that never answers again.
     *
     * <p><b>No signing request ever runs while this guard is held.</b> The monitor below protects only the record of
     * the active flight; the read itself runs on the fetching caller's thread outside it, waiters block on the flight's
     * latch rather than on the monitor, and once a pair is published every later call takes the volatile fast path
     * without touching either — so one caller blocked inside the transport never serializes another caller's signature.
     */
    private final class DeferredInitialization {

        /** The {@code transit/keys/<keyName>} URI of the one read this initialization performs. */
        private final URI keyUri;

        /** Guards {@link #activeFlight} and nothing else — never held across any I/O. */
        private final Object guard = new Object();

        /** The signer's record of the one fetch currently in flight; {@code null} when none is. */
        @Nullable
        private Flight activeFlight;

        private DeferredInitialization(URI keyUri) {
            this.keyUri = keyUri;
        }

        /**
         * The published pair, fetching it if this caller is the first — or waiting on the caller that already is.
         * Returns only a successfully read pair; every failure leaves as an exception, as {@link #fetch} and
         * {@link #awaitSharedOutcome} decide.
         */
        VaultKeyMetadata initialize() {
            while (true) {
                VaultKeyMetadata published = metadata;
                if (published != null) {
                    return published;
                }
                Flight flight;
                boolean fetching = false;
                synchronized (guard) {
                    // Re-checked under the guard: a flight that succeeded between the read above
                    // and this monitor must be honoured, never re-fetched — the pair is read once
                    // per signer, and a second read after a success is what this re-check rules out.
                    published = metadata;
                    if (published != null) {
                        return published;
                    }
                    if (activeFlight == null) {
                        activeFlight = new Flight();
                        fetching = true;
                    }
                    flight = activeFlight;
                }
                if (fetching) {
                    return fetch(flight);
                }
                VaultKeyMetadata shared = awaitSharedOutcome(flight);
                if (shared != null) {
                    return shared;
                }
                // The flight was abandoned — its fetching caller was cancelled, met a failure of
                // neither contract type, met one of a contract type whose description could not be
                // taken, or met something the transport should never have let out at all. Nothing
                // was shared, so this caller retries: one of the remaining callers becomes the next
                // fetching one.
            }
        }

        /**
         * Performs this flight's one metadata read, publishes a success for the signer's lifetime, and decides what the
         * flight leaves for its waiters. The fetching caller always keeps the exception it was given — rethrown here
         * unchanged, whatever the waiters are handed — and the flight ends on <em>every</em> exit, since a flight left
         * recorded as active is a signer that never signs again.
         */
        private VaultKeyMetadata fetch(Flight flight) {
            VaultKeyMetadata fetched;
            try {
                fetched = fetchKeyMetadata(keyUri, namespace, token, transport);
                // The same belt over the same braces the eager mode's constructor applies: the
                // fetch validated the pair against the platform's own P-256 parameters, and this
                // re-checks the point against the core's hard-coded constants before anything is
                // published — the check moved from construction to first use, not out of the path.
                P256PublicKeys.requireOnCurve(fetched.publicKey(), "publicKey");
            } catch (RuntimeException failure) {
                endFailedFlight(flight, failure);
                throw failure;
            } catch (Throwable defect) {
                // Anything else the read let out: an Error, or a checked exception through a method
                // that declares none — the transport is a seam an application implements, and a
                // language without checked exceptions, or a helper that erases them from a
                // signature, delivers one here whatever this interface says. Neither is this seam's
                // to classify, but both must still end the flight: a flight left recorded as active
                // leaves its waiters parked on a latch nobody will count down, and every later
                // caller attaches to that same dead flight — a transport defect turned into a
                // signer that never answers again. The rethrow needs no throws clause: nothing the
                // block above calls declares a checked exception, so the compiler knows this can be
                // no more than an unchecked throwable.
                finish(flight, null);
                throw defect;
            }
            metadata = fetched;
            finish(flight, fetched);
            return fetched;
        }

        /**
         * Ends a flight whose read raised {@code failure}, taking the description of what to share <em>inside</em> the
         * guarantee that the flight is released whatever that takes.
         *
         * <p>Describing a failure consults it — its cause chain, its message, and for an unavailability its status and
         * declared delay — and every one of those is an overridable member of an exception a replaceable transport
         * produced, so any of them may throw; the walk over that chain raises a complaint of its own where the chain
         * does not end within the depth an honest diagnostic reaches. Two things must survive that. The flight ends,
         * because a description that threw is no reason to leave the waiters parked forever — and it ends even if
         * recording that secondary fails in turn, since the release sits in the {@code finally} below rather than
         * beside the recording. And the caller keeps the failure it was given, because a defect in an exception's own
         * accessors says nothing about what the read met: the secondary is filed on the failure as a suppressed
         * exception — where a secondary raised while handling a primary belongs — and the failure travels on as the
         * classified thing it is. Filing it has three limits, all deliberate: nothing can suppress itself, so an
         * accessor that threw the failure itself leaves nothing to record and the failure travels alone; the filing is
         * bounded per exception instance, so a transport reusing one preallocated exception for every failed read of a
         * long outage stops accumulating copies of the same diagnostic rather than growing a list for as long as the
         * custodian is down; and a machine failure out of the recording is not swallowed, so that one reaches the
         * caller in place of the failure rather than being hidden behind it. A failure whose description could not be
         * taken is shared with nobody, so the waiters retry, exactly as they do for a failure of neither contract type.
         */
        private void endFailedFlight(Flight flight, RuntimeException failure) {
            SharedFailure shared = null;
            try {
                shared = describeIfShareable(failure);
            } catch (Throwable secondary) {
                // Everything above this line is consumer-supplied code called on a
                // consumer-supplied failure, so the catch is as wide as what it stands in front
                // of: whatever the description-taking does, the caller keeps its failure.
                suppress(failure, secondary);
            } finally {
                finish(flight, shared);
            }
        }

        /**
         * Ends {@code flight}: records what it leaves behind ({@code outcome} — the pair, a {@link SharedFailure}, or
         * {@code null} for an abandoned flight), clears the signer's record of an active fetch, and wakes the waiters.
         * Cleared before the latch opens so that a waiter waking from an abandoned flight and retrying can only meet
         * the <em>next</em> flight or start one — never re-attach to this finished one and wait forever.
         */
        // NullAssignment: null IS the recorded state here — "no fetch in flight" — and the whole
        // single-flight bound is this field returning to it; a wrapper value would rename the null
        // without removing it.
        @SuppressWarnings("PMD.NullAssignment")
        private void finish(Flight flight, @Nullable Object outcome) {
            flight.outcome = outcome;
            synchronized (guard) {
                if (activeFlight == flight) {
                    activeFlight = null;
                }
            }
            flight.done.countDown();
        }

        /**
         * Waits for the active flight this caller attached to, and reads what it shared: the pair on success, a fresh
         * exception of the contract type on a shared failure, or {@code null} where the flight was abandoned and this
         * caller should retry.
         *
         * <p>A caller interrupted <em>while waiting</em> takes its own cancellation and leaves the flight running for
         * everyone else — it did not start the fetch and must not end it. It holds no transport failure of its own, so
         * its cancellation takes the shape the transport would have produced: the unavailability type with the
         * {@link InterruptedException} beneath it and the interrupt flag re-set, which is exactly what a caller
         * supervising the call — or the sender's own cancellation test — recognises as an interruption.
         */
        private @Nullable VaultKeyMetadata awaitSharedOutcome(Flight flight) {
            try {
                flight.done.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new VapidSignerUnavailableException(
                        "interrupted while waiting for another caller's read of the Vault Transit key metadata"
                                + " — the read itself continues for the callers that were not interrupted",
                        interrupted);
            }
            Object outcome = flight.outcome;
            if (outcome instanceof VaultKeyMetadata pair) {
                return pair;
            }
            if (outcome instanceof SharedFailure failure) {
                throw failure.reconstruct();
            }
            return null;
        }
    }

    /**
     * One deferred fetch in flight: the latch its waiters block on, and what the flight left them — the pair, a
     * {@link SharedFailure}, or {@code null} for a flight that was abandoned, after which a waiter retries. A flight is
     * abandoned by any failure it cannot share: its fetching caller cancelled, a failure of neither contract type, a
     * failure of a contract type whose description could not be taken, and anything the transport let out that is not a
     * {@code RuntimeException} at all. Written by the fetching caller before the latch opens, so every waiter that
     * wakes reads a settled value.
     */
    private static final class Flight {

        private final CountDownLatch done = new CountDownLatch(1);

        @Nullable
        private volatile Object outcome;
    }

    /**
     * The immutable description of a flight's shared failure, taken once when the flight ends: the message, the fetch's
     * own failure whole, and — for the unavailability, the only one of the two contract types that reports either — the
     * custodian's status and declared delay.
     *
     * <p>Each waiter throws a <em>fresh</em> exception built from this, never the one instance the fetching caller was
     * given: one instance thrown from several threads would carry the fetching caller's stack, leave each waiter
     * without its own, and hand them all one mutable suppressed-exception list. The fetch's failure travels as the
     * reconstruction's cause — the whole exception, not that exception's own cause, because an unavailability built
     * from an answered status often has no cause at all, and a waiter rebuilt from nothing would say nothing about the
     * read that failed. A cause reached from several chains is diagnostics; nothing here writes into one.
     *
     * <p>Two details are deliberate. The reconstruction promises the <b>contract type</b> —
     * {@code VapidSignerUnavailableException} or {@code PushCryptoException} — never the runtime class: both types are
     * extensible, a transport's subclass cannot be rebuilt without reflection, and no published contract lets a caller
     * branch on it. And the two declared values are read <b>exactly once</b>, here, because the accessors are not final
     * and an extending exception may answer differently on every call.
     */
    private record SharedFailure(
            boolean unavailability,
            String message,
            Throwable failure,
            boolean hasStatus,
            int status,
            @Nullable Duration retryAfter) {

        private static SharedFailure of(VapidSignerUnavailableException failure) {
            OptionalInt status = failure.status();
            Optional<Duration> retryAfter = failure.retryAfter();
            return new SharedFailure(
                    true, messageOf(failure), failure, status.isPresent(), status.orElse(0), retryAfter.orElse(null));
        }

        private static SharedFailure of(PushCryptoException failure) {
            return new SharedFailure(false, messageOf(failure), failure, false, 0, null);
        }

        /** A detail message is not contractual on either type; a subclass answering none still gets a sentence. */
        private static String messageOf(RuntimeException failure) {
            String message = failure.getMessage();
            return message != null ? message : "the Vault Transit key metadata read failed without a detail message";
        }

        private RuntimeException reconstruct() {
            if (!unavailability) {
                return new PushCryptoException(message, failure);
            }
            if (hasStatus) {
                return new VapidSignerUnavailableException(message, status, retryAfter, failure);
            }
            if (retryAfter != null) {
                return new VapidSignerUnavailableException(message, retryAfter, failure);
            }
            return new VapidSignerUnavailableException(message, failure);
        }
    }

    /**
     * What a failed flight shares with its waiters: a description of the failure where it was one of the two contract
     * types and not an interruption, and {@code null} — the abandoned flight — otherwise.
     *
     * <p><b>The interruption test runs first, before any classification by type</b>, and it is the same disjunction the
     * sender applies before converting a failure into an outcome: the current thread's interrupt status — the fetching
     * caller's own thread, since this runs where the fetch failed — or an {@link InterruptedException} anywhere in the
     * cause chain. Neither half is sound alone, and testing the type first would let a defective transport that wrapped
     * an interruption in a recurring type share a cancellation with callers nobody interrupted. The fetching caller
     * still receives such a failure exactly as it was labelled; refusing to <em>share</em> it is the whole of what this
     * decides. A chain that cannot be walked to its end is refused in the same direction, by the test raising rather
     * than answering: nothing is classified and nothing is shared, an interruption beyond the cut being exactly what
     * cannot be ruled out.
     */
    private static @Nullable SharedFailure describeIfShareable(RuntimeException failure) {
        if (isInterruption(failure)) {
            return null;
        }
        if (failure instanceof VapidSignerUnavailableException unavailable) {
            return SharedFailure.of(unavailable);
        }
        if (failure instanceof PushCryptoException recurring) {
            return SharedFailure.of(recurring);
        }
        return null;
    }

    /**
     * Records {@code secondary} on {@code failure} without letting the recording displace it. Exactly one refusal is
     * reachable here, and it is caught: {@code addSuppressed} rejects an exception offered as its own suppressor, which
     * is what an accessor that threw the failure itself hands it. The set is closed rather than assumed — the method is
     * {@code final} on {@code Throwable}, so no consumer type can make it refuse for reasons of its own, and its one
     * other refusal is a {@code null} argument, which a catch clause cannot produce. Anything else out of that call is
     * the machine and not the diagnostics, so it is left to leave: the caller then receives it in place of the failure,
     * and the flight is released regardless, because the release sits in the caller's {@code finally} rather than
     * beside this record.
     *
     * <p>Recording mutates an exception a replaceable transport produced, so the number of recordings one instance can
     * take is bounded here. Preallocating a single exception and throwing it for every failed read is an ordinary thing
     * for a transport to do — a custodian refusing every call while a breaker is open gives it no reason to build a new
     * instance each time — and the accessors this guards against are the ones that break on every read. A failed flight
     * is forgotten rather than cached, so the next caller starts a fresh one: a custodian down for an hour, with
     * signing called in a loop, would otherwise grow one instance's suppressed list by one entry per read for as long
     * as the outage lasts, without limit and for no gain, since the hundredth copy of the same diagnostic says nothing
     * the first did not. Neither of the two exception types a description can be taken from can opt out of the
     * accumulation, because every constructor they offer reaches a superclass constructor that leaves suppression
     * enabled. Any other type reaches this too — the cause-chain walk that begins a description runs before any test by
     * type — and one of those built with suppression disabled records nothing here at all, so it grows nothing. So the
     * first few recordings are kept and the rest are dropped, which costs a diagnostic nothing and keeps a defective
     * accessor from turning memory into the failure mode. Entries the consumer recorded itself count towards the same
     * bound.
     *
     * <p>The check and the recording are one critical section, because several flights describing one shared exception
     * at the same moment would otherwise pass the check together and record past the limit. The monitor is the
     * exception's own — the one {@code addSuppressed} takes anyway, so nothing new is locked here, only held across
     * both steps, and it is reentrant, so the members called inside may take it again. What deliberately does not
     * happen inside it is a call to anything a consumer wrote: {@code addSuppressed} and {@code getSuppressed} are both
     * {@code final} on {@code Throwable}, so this section cannot be made to wait on consumer code while holding a
     * monitor that consumer code can also take, nor can a consumer type make either of them refuse for reasons of its
     * own: the only refusal reachable here is {@code addSuppressed}'s own, caught below, and the count the check reads
     * is one {@code getSuppressed} can neither withhold nor misstate.
     *
     * @param failure the primary failure, which stays what the caller receives
     * @param secondary the defect worth recording beside it
     */
    private static void suppress(Throwable failure, Throwable secondary) {
        synchronized (failure) {
            if (failure.getSuppressed().length >= SUPPRESSED_RECORDING_CEILING) {
                return;
            }
            try {
                failure.addSuppressed(secondary);
            } catch (IllegalArgumentException selfSuppression) {
                // The failure was offered as its own suppressor, which only its own accessor
                // throwing it can produce. There is nothing to record and nothing to report: the
                // caller is owed the failure the read produced, not a complaint about the
                // exception carrying it.
            }
        }
    }

    /**
     * The same interruption disjunction the sender applies, for the same reason neither half is sound alone: an
     * interruption can surface as an {@link java.io.InterruptedIOException} with no {@link InterruptedException}
     * beneath it (the flag half catches those), and a transport can attach a cause without re-setting the flag (the
     * chain half catches that). The walk carries a guard against each of the two ways a chain a defective transport
     * built by overriding {@code getCause()} can fail to end, because a fetch must not spin over someone else's broken
     * diagnostics: an identity set ends a cycle, and a depth ceiling ends an acyclic chain that never runs out, which a
     * read fabricating a fresh wrapper every time produces and no identity test can detect.
     *
     * <p>The two ends differ in what they leave known. A cycle is walked to its end — every element of it was seen — so
     * the answer is sound and the failure goes on to be classified. The ceiling leaves the tail unread, so whether an
     * {@link InterruptedException} sat beyond the cut cannot be known by anybody; rather than guess, the walk raises
     * its own diagnostic, which the caller files on the failure and treats exactly as it treats an accessor that threw:
     * the flight is abandoned, its waiters retry, and the fetching caller keeps the failure it was given. Guessing the
     * other way and sharing the failure would risk handing a cancellation to callers nobody interrupted, which is the
     * one thing this test exists to prevent.
     *
     * <p>The flag is asked once more after the walk, however the walk ended, and that second look is the method's exit:
     * the walk runs consumer code, so an interruption can land between the first look and the last element read — and
     * with the first look alone, a cancellation the fetching caller had already taken would be shared with waiters
     * nobody interrupted. A walk cut at the ceiling reaches the same abandonment by the other route, since what it
     * raises is not answered with a classification at all.
     */
    private static boolean isInterruption(RuntimeException failure) {
        if (Thread.currentThread().isInterrupted()) {
            return true;
        }
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            if (cause instanceof InterruptedException) {
                return true;
            }
            if (seen.size() >= CAUSE_CHAIN_CEILING) {
                throw new IllegalStateException("cause chain still unfinished after " + CAUSE_CHAIN_CEILING
                        + " elements; a chain this deep is being generated, not walked, so the walk stops here");
            }
        }
        return Thread.currentThread().isInterrupted();
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        // The pair is taken first, and taken once: in the deferred mode this is the call that may
        // perform the one-time metadata read, and it returns before any lock-free path below runs —
        // so the signing POST never runs while the initialization guard is held, and the version in
        // the request below and the version checked against the response envelope are one value.
        VaultKeyMetadata key = keyMetadata();
        String request = "{\"input\":\"" + Base64.getEncoder().encodeToString(signingInput)
                + "\",\"marshaling_algorithm\":\"jws\""
                + (key.version() == null ? "" : ",\"key_version\":" + key.version()) + "}";
        VaultHttpResponse response =
                transport.post(signUri, vaultHeaders(token, namespace), request.getBytes(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            throw answerFailure("Vault Transit sign", response);
        }
        String marshalled = extractSignature(response.body());
        byte[] signature;
        try {
            signature = Base64.getUrlDecoder().decode(stripVaultPrefix(marshalled, key.version()));
        } catch (IllegalArgumentException e) {
            // Report the failure as this module's exception, next to the cause — and without the
            // response payload, whose content is not worth echoing into logs.
            throw new PushCryptoException("Vault Transit returned a signature that is not valid base64url", e);
        }
        // Fail here, next to the cause — a wrong-size blob would otherwise surface only as an
        // opaque push-service rejection of the VAPID JWT, far from the malformed Vault response.
        if (signature.length != SIGNATURE_LENGTH) {
            throw new PushCryptoException("Vault Transit returned a malformed ES256 signature: expected "
                    + SIGNATURE_LENGTH + " bytes (r || s), got " + signature.length);
        }
        return signature;
    }

    @Override
    public byte[] publicKey() {
        return keyMetadata().publicKey().clone();
    }

    /**
     * Read the latest key version and <em>that version's</em> public key from {@code transit/keys/<keyName>} as one
     * atomic pair, reducing the key to the 65-byte uncompressed P-256 point. Taking both from a single response closes
     * the rotation race: even if the key is rotated right after this read, the signer keeps signing with the version
     * its advertised public key belongs to. A single {@code GET} — at startup, or at first use in the deferred mode —
     * over the same {@link VaultHttpTransport} the {@code sign} calls use; the token needs {@code read} on the key.
     *
     * <p>The key is validated as P-256 before the pair exists, all fail-fast: the Transit {@code type}
     * ({@link #requireP256KeyType}), then the key's domain parameters and its point ({@link #requireP256PublicKey}). No
     * check subsumes another — the metadata is only Vault's claim, right parameters do not put the point on the curve,
     * and a key on another curve would otherwise be squeezed into 32-byte coordinates and published as a nonsense VAPID
     * key that fails much later, as an opaque push-service rejection. The eager builder runs this inside
     * {@code build()}; the deferred mode runs the very same method from its first-use initialization — the checks move
     * in time, never in substance.
     */
    private static VaultKeyMetadata fetchKeyMetadata(
            URI keyUri, @Nullable String namespace, String token, VaultHttpTransport transport) {
        Objects.requireNonNull(keyUri, "keyUri");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(transport, "transport");
        // No token or namespace validation here: a VaultToken is valid by construction (visible
        // ASCII, hence header-safe), and the namespace was validated at the namespace(...) step
        // that set it — so this call, which in the eager fetched mode runs before the canonical
        // constructor, cannot offer an invalid value to the transport.
        VaultHttpResponse response = transport.get(keyUri, vaultHeaders(token, namespace));
        if (response.statusCode() != 200) {
            throw answerFailure("Vault Transit key read", response);
        }
        String body = response.body();
        requireP256KeyType(body);
        int latestVersion = extractLatestVersion(body);
        ECPublicKey key;
        try {
            key = parsePublicKeyPem(extractPublicKeyPem(body, latestVersion));
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("Vault Transit returned an unparseable public key", e);
        }
        requireP256PublicKey(key);
        return new VaultKeyMetadata(latestVersion, uncompressedPoint(key));
    }

    /**
     * Reject any Transit key whose advertised {@code type} is neither {@code ecdsa-p256} nor {@code managed_key} — the
     * common misconfiguration is an {@code ecdsa-p384} (or {@code ed25519}) key, which cannot produce the ES256
     * signatures VAPID requires. A missing {@code type} is equally loud: silently accepting a response that does not
     * describe the key would defeat the check.
     *
     * <p>{@code managed_key} is Vault Enterprise's HSM/KMS-backed key type: the response then describes the wrapper,
     * not the curve, so the type says nothing either way. It is accepted here because {@link #requireP256PublicKey}
     * inspects the key material itself and is the authoritative check — the same reason the curve check exists at all.
     * This path has <em>not</em> been exercised against a real Vault Enterprise; the curve check still refuses anything
     * that is not P-256, so the worst case is a clear failure, never a bogus VAPID key.
     */
    private static void requireP256KeyType(String json) {
        String type = extractKeyType(json);
        if (!REQUIRED_KEY_TYPE.equals(type) && !MANAGED_KEY_TYPE.equals(type)) {
            throw new PushCryptoException(
                    "Vault Transit key type is '" + logSafeExcerpt(type) + "', but VAPID requires '"
                            + REQUIRED_KEY_TYPE + "' (or Vault Enterprise's '" + MANAGED_KEY_TYPE
                            + "') — RFC 8292 mandates ES256 over NIST P-256");
        }
    }

    /**
     * Reject a public key that is not a point on NIST P-256, independently of what the Transit metadata claimed. Two
     * steps, both necessary:
     *
     * <ol>
     *   <li>the key's domain parameters must be P-256's. They are compared against the canonical {@code secp256r1}
     *       parameters <em>by value</em> — prime field modulus, curve coefficients, generator, order and cofactor —
     *       because {@link ECParameterSpec} has no {@code equals} and providers hand back equivalent-but-distinct
     *       instances (named-curve subclasses, cached singletons, keys carrying explicit parameters) that an identity
     *       or {@code equals} comparison on the spec would wrongly reject;
     *   <li>the key's point must satisfy the curve equation. Right parameters do not imply a point on the curve: the
     *       JCA does not validate this — SunEC accepts a {@code KeyFactory} spec with P-256 parameters and a point such
     *       as {@code (1, 2)}, or a coordinate at or above the field prime — so without this step the signer would
     *       still publish a VAPID key that no push service can verify.
     * </ol>
     *
     * <p>Both answers a key gives about itself — {@code getParams()} and {@code getW()} — come from the provider's own
     * key implementation, and a defective provider installed ahead of the platform's can answer {@code null} to either;
     * each is refused as this module's crypto exception rather than dereferenced.
     */
    private static void requireP256PublicKey(ECPublicKey key) {
        ECParameterSpec expected = p256Parameters();
        ECParameterSpec actual = key.getParams();
        if (actual == null || !sameCurve(actual, expected)) {
            throw new PushCryptoException("Vault Transit public key is not on NIST P-256 (" + SECP256R1 + "): "
                    + describe(actual, expected) + ". VAPID requires ES256 over P-256 (RFC 8292)");
        }
        requireOnCurve(key.getW(), expected);
    }

    /**
     * Check {@code point} against the short Weierstrass equation of {@code parameters}: {@code 0 <= x,y < p} and
     * {@code y² ≡ x³ + ax + b (mod p)}. Called only with the canonical P-256 parameters, so the field is known to be an
     * {@link ECFieldFp}. A {@code null} point — a defective provider's key answering {@code getW()} with nothing — is
     * refused first and by name: {@code ECPoint.POINT_INFINITY.equals(null)} is {@code false}, so the infinity guard
     * alone would wave the null through to the affine-coordinate arithmetic. Coordinates are public key material, but
     * the message quotes none of it — the failure is structural, and there is nothing an operator can do with the
     * digits.
     */
    private static void requireOnCurve(@Nullable ECPoint point, ECParameterSpec parameters) {
        if (point == null) {
            throw new PushCryptoException(
                    "Vault Transit public key reports no point at all, which is not a usable VAPID key");
        }
        if (ECPoint.POINT_INFINITY.equals(point)) {
            throw new PushCryptoException(
                    "Vault Transit public key is the point at infinity, which is not a usable VAPID key");
        }
        EllipticCurve curve = parameters.getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
            throw new PushCryptoException("Vault Transit public key has a coordinate outside the P-256 field "
                    + "(0 <= x, y < p), so it is not a point on the curve");
        }
        BigInteger left = y.multiply(y).mod(p);
        BigInteger right = x.multiply(x)
                .multiply(x)
                .add(curve.getA().multiply(x))
                .add(curve.getB())
                .mod(p);
        if (!left.equals(right)) {
            throw new PushCryptoException("Vault Transit public key does not satisfy the NIST P-256 curve equation "
                    + "(y² = x³ + ax + b), so it is not a point on the curve");
        }
    }

    /**
     * The canonical NIST P-256 domain parameters, resolved from the platform JCE providers. A lookup answered with no
     * spec at all — {@code getParameterSpec} runs in whichever provider wins the {@code AlgorithmParameters}
     * resolution, and a defective one installed ahead of the platform's can answer {@code null} — is refused here as
     * this module's crypto exception, not left to dereference inside the curve comparison.
     */
    private static ECParameterSpec p256Parameters() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC);
            parameters.init(new ECGenParameterSpec(SECP256R1));
            ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
            if (spec == null) {
                throw new PushCryptoException("EC AlgorithmParameters answered the " + SECP256R1
                        + " lookup with no parameter spec at all, so there is nothing to verify the Vault key against");
            }
            return spec;
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException(
                    "EC AlgorithmParameters (" + SECP256R1 + ") are unavailable from the platform JCE providers", e);
        }
    }

    /** Value-wise equality of two EC domain parameter sets (see {@link #requireP256PublicKey}). */
    private static boolean sameCurve(ECParameterSpec actual, ECParameterSpec expected) {
        EllipticCurve actualCurve = actual.getCurve();
        EllipticCurve expectedCurve = expected.getCurve();
        return sameField(actualCurve.getField(), expectedCurve.getField())
                && actualCurve.getA().equals(expectedCurve.getA())
                && actualCurve.getB().equals(expectedCurve.getB())
                && actual.getOrder().equals(expected.getOrder())
                && actual.getCofactor() == expected.getCofactor()
                && sameGenerator(actual.getGenerator(), expected.getGenerator());
    }

    /**
     * Prime-field equality. Only {@link ECFieldFp} counts: comparing bit sizes alone would accept a binary field
     * ({@code ECFieldF2m}) of the same size as P-256's prime field.
     */
    private static boolean sameField(ECField actual, ECField expected) {
        return actual instanceof ECFieldFp actualFp
                && expected instanceof ECFieldFp expectedFp
                && actualFp.getP().equals(expectedFp.getP());
    }

    /** Affine equality of two generators; the point at infinity (null affine coordinates) never matches. */
    private static boolean sameGenerator(ECPoint actual, ECPoint expected) {
        return !ECPoint.POINT_INFINITY.equals(actual)
                && !ECPoint.POINT_INFINITY.equals(expected)
                && actual.getAffineX().equals(expected.getAffineX())
                && actual.getAffineY().equals(expected.getAffineY());
    }

    /**
     * A short, log-safe description of a key's curve for the mismatch message. The field size alone is useless for the
     * curves most likely to be confused with P-256 — secp256k1 and brainpoolP256r1 are also 256-bit prime-field curves,
     * so "a 256-bit prime field" reads as a self-contradiction. The {@code b} coefficient discriminates them, and being
     * a published domain parameter it is safe to log.
     */
    private static String describe(@Nullable ECParameterSpec parameters, ECParameterSpec expected) {
        if (parameters == null) {
            return "the key carries no EC domain parameters";
        }
        ECField field = parameters.getCurve().getField();
        return "the key's curve is over a " + field.getFieldSize() + "-bit "
                + (field instanceof ECFieldFp ? "prime" : "non-prime") + " field with b=0x"
                + parameters.getCurve().getB().toString(16) + ", while P-256 has a "
                + expected.getCurve().getField().getFieldSize() + "-bit prime field with b=0x"
                + expected.getCurve().getB().toString(16);
    }

    /**
     * Pull the {@code signature} value out of Vault's {@code {"data":{"signature":"vault:v1:..."}}} response, anchored
     * the whole way: {@code data} as a direct member of the root object, {@code signature} as a direct member of
     * {@code data} — a string value that merely looks like one of those labels can never hijack the lookup. Targeted
     * extraction (fixed Vault response shape), not a general JSON parser.
     */
    private static String extractSignature(String json) {
        int dataOpen = directMemberObjectStart(json, rootObjectStart(json), "data");
        int valueStart = directMemberValueStart(json, dataOpen, "signature");
        if (valueStart < 0) {
            throw new PushCryptoException("Vault response has no 'signature' field: " + logSafeExcerpt(json));
        }
        return stringValueAt(json, valueStart, "signature");
    }

    /**
     * Pull the integer {@code latest_version} out of {@code transit/keys/<name>}, anchored the whole way: {@code data}
     * as a direct member of the root object, {@code latest_version} as a direct member of {@code data} — a string value
     * that merely looks like the label can never hijack the lookup. Targeted extraction (fixed Vault response shape),
     * not a general JSON parser. Package-private for the extraction unit tests.
     *
     * <p>The value must be a whole positive number and nothing else. Reading the leading digit run and stopping
     * wherever it ends would take {@code "latest_version": 1.5} — or a quoted {@code "1"}, or {@code 1abc} — for
     * version 1, then pin that version on every {@code sign} call and publish the public key of a version the response
     * never named. A response Vault cannot have produced is a reason to fail construction, not to guess: the value is
     * checked to run to the member's end, i.e. to the next {@code ,} or the enclosing {@code }}.
     *
     * <p>{@code Character.isDigit} is not used: it accepts non-ASCII digits (Arabic-Indic and the rest), which
     * {@link Integer#parseInt} would then happily convert — JSON numbers are ASCII.
     */
    static int extractLatestVersion(String json) {
        int dataOpen = directMemberObjectStart(json, rootObjectStart(json), "data");
        int valueStart = directMemberValueStart(json, dataOpen, "latest_version");
        if (valueStart < 0) {
            throw new PushCryptoException("Vault key response has no 'latest_version' field: " + logSafeExcerpt(json));
        }
        int start = valueStart;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < json.length() && json.charAt(end) >= '0' && json.charAt(end) <= '9') {
            end++;
        }
        if (end == start || !endsMember(json, end)) {
            throw new PushCryptoException(
                    "malformed Vault 'latest_version' field — expected a whole number: " + logSafeExcerpt(json));
        }
        // Bounded BEFORE Integer.parseInt sees it: parseInt's NumberFormatException carries the
        // ENTIRE digit run in its message, and attaching that as a cause would put a run as long
        // as the response body into every logged stack trace — defeating ERROR_ECHO_LIMIT. The
        // nine-digit bound is deliberately tighter than the int boundary (some ten-digit runs
        // still fit an int): no plausible Transit version comes near either limit, and nine
        // ASCII digits (at most 999,999,999) are guaranteed to parse, so the catch is gone.
        if (end - start > 9) {
            throw new PushCryptoException(
                    "malformed Vault 'latest_version' field — implausibly long number: " + logSafeExcerpt(json));
        }
        int version = Integer.parseInt(json.substring(start, end));
        if (version < 1) {
            // Transit numbers key versions from 1; a 0 would be pinned into every sign request and
            // rejected by Vault on each send, far from the response that caused it.
            throw new PushCryptoException("Vault reported key version " + version
                    + ", but Transit key versions start at 1: " + logSafeExcerpt(json));
        }
        return version;
    }

    /**
     * Whether the value ending at {@code end} is the whole of its member: the next non-whitespace character must close
     * the member ({@code ,}) or the enclosing object ({@code }}). Anything else — a {@code .}, a digit's worth of
     * exponent, a stray letter — means the digits read were only a prefix of some other value.
     */
    private static boolean endsMember(String json, int end) {
        int cursor = end;
        while (cursor < json.length() && Character.isWhitespace(json.charAt(cursor))) {
            cursor++;
        }
        return cursor < json.length() && (json.charAt(cursor) == ',' || json.charAt(cursor) == '}');
    }

    /**
     * Pull the {@code type} of the Transit key out of {@code transit/keys/<name>} (e.g. {@code "ecdsa-p256"}), anchored
     * the whole way: {@code data} as a direct member of the root object, {@code type} as a direct member of
     * {@code data} — a string value that merely looks like the label (or a {@code type} nested in some version entry)
     * can never hijack the lookup. Targeted extraction (fixed Vault response shape), not a general JSON parser.
     * Package-private for the extraction unit tests.
     */
    static String extractKeyType(String json) {
        int dataOpen = directMemberObjectStart(json, rootObjectStart(json), "data");
        int valueStart = directMemberValueStart(json, dataOpen, "type");
        if (valueStart < 0) {
            throw new PushCryptoException("Vault key response has no 'type' field, so the key cannot be "
                    + "confirmed as '" + REQUIRED_KEY_TYPE + "': " + logSafeExcerpt(json));
        }
        return stringValueAt(json, valueStart, "type");
    }

    /**
     * Pull the {@code public_key} PEM of the given key version out of {@code transit/keys/<name>}. The whole chain is
     * anchored, one direct-member hop at a time: root object → {@code data} → {@code keys} → the version entry →
     * {@code public_key} inside that entry's own {@code {...}}. No lookup ever scans the response at large, so neither
     * a string value that looks like a label (e.g. {@code "alias":"keys"}) nor a lookalike entry nested deeper or
     * elsewhere can hijack the extraction — the failure mode is always a loud {@link PushCryptoException}, never
     * another object's key. Whitespace between tokens is tolerated (valid JSON may be pretty-printed). The PEM's
     * {@code \n} are escaped in the JSON. Targeted extraction (fixed Vault response shape), not a general JSON parser.
     * Package-private for the extraction unit tests.
     */
    static String extractPublicKeyPem(String json, int version) {
        int dataOpen = directMemberObjectStart(json, rootObjectStart(json), "data");
        int keysOpen = directMemberObjectStart(json, dataOpen, "keys");

        int versionValue = directMemberValueStart(json, keysOpen, Integer.toString(version));
        if (versionValue < 0) {
            throw new PushCryptoException(
                    "Vault key response has no entry for key version " + version + ": " + logSafeExcerpt(json));
        }
        int versionOpen = versionValue;
        while (versionOpen < json.length() && Character.isWhitespace(json.charAt(versionOpen))) {
            versionOpen++;
        }
        if (versionOpen >= json.length() || json.charAt(versionOpen) != '{') {
            throw new PushCryptoException("Vault key response entry for key version " + version + " is not an object: "
                    + logSafeExcerpt(json));
        }
        String versionObject = json.substring(versionOpen, matchingCloseBrace(json, versionOpen) + 1);

        int pemStart = directMemberValueStart(versionObject, 0, "public_key");
        if (pemStart < 0) {
            throw new PushCryptoException(
                    "Vault key response has no 'public_key' for key version " + version + ": " + logSafeExcerpt(json));
        }
        return stringValueAt(versionObject, pemStart, "public_key").replace("\\n", "\n");
    }

    /** The index of the root object's opening brace (leading whitespace tolerated). */
    private static int rootObjectStart(String json) {
        int i = 0;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        if (i >= json.length() || json.charAt(i) != '{') {
            throw new PushCryptoException("Vault response is not a JSON object: " + logSafeExcerpt(json));
        }
        return i;
    }

    /**
     * The opening-brace index of the object-valued direct member {@code name} of the object opening at
     * {@code objectOpen}. A missing member or a non-object value (e.g. {@code "keys":null}) fails loudly instead of
     * letting the caller bind to some stray brace later in the response.
     */
    private static int directMemberObjectStart(String json, int objectOpen, String name) {
        int valueStart = directMemberValueStart(json, objectOpen, name);
        if (valueStart < 0) {
            throw new PushCryptoException("Vault key response has no '" + name + "' object: " + logSafeExcerpt(json));
        }
        int cursor = valueStart;
        while (cursor < json.length() && Character.isWhitespace(json.charAt(cursor))) {
            cursor++;
        }
        if (cursor >= json.length() || json.charAt(cursor) != '{') {
            throw new PushCryptoException(
                    "Vault key response '" + name + "' is not an object: " + logSafeExcerpt(json));
        }
        return cursor;
    }

    /**
     * The index just past the colon of the direct member named {@code name} in the object opening at
     * {@code objectOpen}, or {@code -1} if the object has no such member. Walks the object tracking nesting depth and
     * string state (honouring backslash escapes), so a lookalike nested inside a member's value — or sitting past the
     * object's closing brace — never matches; a quoted token not followed by a colon (i.e. a string <em>value</em> that
     * merely equals the member name, as in {@code "alias":"keys"}) is skipped whole. Whitespace before the colon is
     * tolerated.
     */
    private static int directMemberValueStart(String json, int objectOpen, String name) {
        String label = "\"" + name + "\"";
        int depth = 0;
        boolean inString = false;
        for (int i = objectOpen; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (depth == 1 && json.startsWith(label, i)) {
                int cursor = i + label.length();
                while (cursor < json.length() && Character.isWhitespace(json.charAt(cursor))) {
                    cursor++;
                }
                if (cursor < json.length() && json.charAt(cursor) == ':') {
                    return cursor + 1;
                }
                // A string value that merely equals the member name — skip the quoted token whole.
                i += label.length() - 1;
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return -1;
                }
            }
        }
        return -1;
    }

    /**
     * The content of the JSON string value at {@code valueStart} (the index just past a member's colon; leading
     * whitespace tolerated), without unescaping. Escaped characters inside the value are skipped when locating the
     * terminating quote; a non-string or unterminated value fails loudly.
     */
    private static String stringValueAt(String json, int valueStart, String fieldName) {
        int open = valueStart;
        while (open < json.length() && Character.isWhitespace(json.charAt(open))) {
            open++;
        }
        if (open >= json.length() || json.charAt(open) != '"') {
            throw new PushCryptoException("malformed Vault '" + fieldName + "' field: " + logSafeExcerpt(json));
        }
        int close = open + 1;
        while (close < json.length() && json.charAt(close) != '"') {
            close += json.charAt(close) == '\\' ? 2 : 1;
        }
        if (close >= json.length()) {
            throw new PushCryptoException("malformed Vault '" + fieldName + "' field: " + logSafeExcerpt(json));
        }
        return json.substring(open + 1, close);
    }

    /**
     * The index of the closing brace matching the opening brace at {@code openBrace}, skipping nested objects and brace
     * characters inside JSON strings (honouring backslash escapes).
     */
    private static int matchingCloseBrace(String json, int openBrace) {
        int depth = 0;
        boolean inString = false;
        for (int i = openBrace; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        throw new PushCryptoException("malformed Vault key response: unterminated object: " + logSafeExcerpt(json));
    }

    /**
     * Parse Vault's SubjectPublicKeyInfo PEM into an EC public key. The curve and the point are <em>not</em> checked
     * here — {@link #requireP256PublicKey} does that on the result.
     */
    private static ECPublicKey parsePublicKeyPem(String pem) throws GeneralSecurityException {
        String base64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            // Same convention as sign(): a malformed Vault payload is reported as this module's
            // exception, next to the cause — a raw IllegalArgumentException must not escape
            // FetchedPublicKeyBuilder.build(), whose documented failure mode for a bad response is
            // PushCryptoException. The payload itself is not echoed; it is not worth logging.
            throw new PushCryptoException("Vault Transit returned a public key PEM that is not valid base64", e);
        }
        PublicKey key = KeyFactory.getInstance(EC).generatePublic(new X509EncodedKeySpec(der));
        if (key == null) {
            // The parse runs in the provider's own KeyFactory implementation, and nothing in the
            // JDK stops a defective one answering null — refused by name here, before the non-EC
            // diagnostic below would ask the missing key for its algorithm name.
            throw new PushCryptoException("The EC KeyFactory answered the Vault Transit public key parse with no key"
                    + " at all, so there is no key to verify");
        }
        if (!(key instanceof ECPublicKey ecKey)) {
            // Defensive: an EC KeyFactory normally rejects foreign SPKIs outright, but a provider
            // returning some other key type must not blow up as a ClassCastException.
            throw new PushCryptoException(
                    "Vault Transit returned a " + key.getAlgorithm() + " public key, not an EC one");
        }
        return ecKey;
    }

    /**
     * Encode a P-256 public key as its 65-byte X9.62 uncompressed point ({@code 0x04 || X || Y}). Call only after
     * {@link #requireP256PublicKey}: that check has already refused a key reporting no point at all or the point at
     * infinity, so neither is re-checked here, and the fixed 32-byte coordinate fields are P-256's field size, so a
     * coordinate from a larger curve is rejected rather than truncated.
     */
    private static byte[] uncompressedPoint(ECPublicKey key) {
        byte[] out = new byte[UNCOMPRESSED_LENGTH];
        out[0] = UNCOMPRESSED_TAG;
        writeFixed(key.getW().getAffineX(), out, 1);
        writeFixed(key.getW().getAffineY(), out, 1 + COORDINATE_LENGTH);
        return out;
    }

    /**
     * Write {@code value} as a fixed 32-byte big-endian field at {@code offset} (right-aligned).
     * {@link BigInteger#toByteArray()} is two's complement, so a 256-bit coordinate with its top bit set carries a
     * leading {@code 0x00} sign byte — padding, dropped here. Anything wider than that is <em>significant</em> and
     * fails loudly: truncating it would publish a plausible-looking but bogus VAPID key whose only symptom is a much
     * later push-service rejection.
     */
    private static void writeFixed(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        int start = 0;
        while (start < bytes.length - COORDINATE_LENGTH && bytes[start] == 0) {
            start++;
        }
        int length = bytes.length - start;
        // Two distinct failures, reported apart: BigInteger.bitLength() is the length of the
        // MINIMAL two's-complement representation excluding the sign bit, so it is 0 for -1 and
        // would turn a negative coordinate into a nonsensical "0 bits" complaint.
        if (value.signum() < 0) {
            throw new PushCryptoException(
                    "Vault Transit public key has a negative coordinate, which is not a P-256 field element");
        }
        if (length > COORDINATE_LENGTH) {
            throw new PushCryptoException("Vault Transit public key has a coordinate that is not a P-256 field "
                    + "element: " + value.bitLength() + " bits, expected at most " + (COORDINATE_LENGTH * Byte.SIZE));
        }
        System.arraycopy(bytes, start, out, offset + COORDINATE_LENGTH - length, length);
    }

    /**
     * Response text as echoed into exception messages: one line, escaped, and bounded. What arrives here is whatever
     * answered on the Vault address — an intercepting proxy, or a service that is not Vault at all, can put anything in
     * a body, and the message built from it is handed to a logger. So two things are done to it, in this order.
     *
     * <p>First, every character that could end the line or steer a terminal is replaced by a printable form — a
     * backslash, a {@code u}, and four hex digits: the ISO control characters, which covers the carriage return and
     * line feed that would otherwise forge a second log entry, the tab, the escape that opens an ANSI sequence, the
     * NUL, and the C1 range with its next-line character — plus the Unicode line and paragraph separators, which are
     * not control characters but do end a line for a reader that follows the Unicode rules.
     *
     * <p>Second, the bound is applied to the <em>escaped</em> text, so a body of nothing but control characters cannot
     * inflate six-fold past it, and the truncation marker is counted inside the bound rather than appended past it: the
     * returned string is never longer than {@link #ERROR_ECHO_LIMIT} characters. The default transport caps responses
     * at 1 MiB, but a megabyte — or whatever a custom {@link VaultHttpTransport} lets through, where the cap holds only
     * by contract — is far too heavy for a log line. The count the marker names is the response's own length, before
     * escaping.
     *
     * <p>Package-private for the excerpt unit tests.
     */
    static String logSafeExcerpt(String text) {
        String marker = "... [truncated, " + text.length() + " chars total]";
        int budget = ERROR_ECHO_LIMIT - marker.length();
        StringBuilder excerpt = new StringBuilder(Math.min(text.length(), budget));
        boolean truncated = false;
        int index = 0;
        while (index < text.length()) {
            int codePoint = text.codePointAt(index);
            int width = Character.charCount(codePoint);
            boolean escape = breaksALogLine(codePoint);
            if (excerpt.length() + (escape ? ESCAPE_LENGTH : width) > budget) {
                truncated = true;
                break;
            }
            if (escape) {
                excerpt.append("\\u").append(HexFormat.of().toHexDigits((char) codePoint));
            } else {
                excerpt.appendCodePoint(codePoint);
            }
            index += width;
        }
        return truncated ? excerpt.append(marker).toString() : excerpt.toString();
    }

    /**
     * Whether {@code codePoint} must not reach a log line as itself. {@link Character#isISOControl} is the whole of the
     * C0 and C1 ranges — the line feed, the carriage return, the tab, the escape, the NUL and the next-line character
     * at {@code U+0085} among them. The two separators named beside it are ordinary punctuation by category and would
     * pass any control-character test, yet they end a line wherever the Unicode line-breaking rules are honoured.
     */
    private static boolean breaksALogLine(int codePoint) {
        return Character.isISOControl(codePoint) || codePoint == LINE_SEPARATOR || codePoint == PARAGRAPH_SEPARATOR;
    }

    /**
     * The failure a non-200 Vault answer produces, split by one question: does the status describe Vault's own
     * condition — or that of a service Vault itself called — or the request that was made? A condition of the cluster
     * ends on Vault's terms (an operator unseals, a replication catches up, a rate window closes, a third party comes
     * back) without this deployment changing anything it configured, so it is worth waiting out and leaves as
     * {@link VapidSignerUnavailableException}. An answer about the request is answered the same way until the
     * deployment changes what it supplied, so it recurs and stays {@link PushCryptoException}.
     *
     * <p>The custodian-unavailable side carries the status Vault answered with, and the retry hint where Vault declared
     * one — filled on a rate-limited answer alone, and only where an operator enabled the rate-limit response headers,
     * so absent is the ordinary case. Both are for whoever schedules the next attempt and for the operator reading a
     * log; the recurring side carries neither, because there is no next attempt to schedule.
     */
    private static RuntimeException answerFailure(String operation, VaultHttpResponse response) {
        int status = response.statusCode();
        if (custodianCannotServeNow(status)) {
            return new VapidSignerUnavailableException(
                    operation + " must wait — Vault cannot serve it now: HTTP " + status + " — "
                            + logSafeExcerpt(response.body()),
                    status,
                    response.retryAfter().orElse(null),
                    null);
        }
        return new PushCryptoException(operation + " failed: HTTP " + status + " — " + logSafeExcerpt(response.body()));
    }

    /**
     * Whether {@code status} names a condition of the Vault cluster rather than an answer about the request. The worked
     * rows are Vault's own published table (<a
     * href="https://developer.hashicorp.com/vault/api-docs#http-status-codes">Vault API: HTTP status codes</a>):
     * {@code 500} "an internal error has occurred, try again later"; {@code 503} sealed, down for maintenance or
     * overloaded; {@code 501} not initialized; {@code 502} an error from a third party Vault itself called; {@code 412}
     * eventually-consistent data not yet present, to be retried with a little backoff; {@code 429} a standby node's
     * health answer as well as "too many requests"; {@code 472} a disaster recovery replication secondary; {@code 473}
     * a performance standby. Every one of those names a state of the cluster or of a service it called, and none names
     * the request — so every one is the custodian unable to serve <em>now</em>.
     *
     * <p>A status the table does not name will arrive — from a Vault newer than this text, or from a proxy in front of
     * it — and falls to the classes RFC 9110 defines (<a
     * href="https://www.rfc-editor.org/rfc/rfc9110#section-15">§15</a>): a 5xx says the server is aware it has erred, a
     * statement about the custodian, so an unrecognised 5xx lands on the unavailable side with the four named ones; a
     * 4xx says the client seems to have erred, a statement about the request, so an unrecognised 4xx recurs — like the
     * answers Vault itself gives about a request: {@code 400} a malformed call, {@code 403} a token without the
     * capability, {@code 404} a key or mount that is not there, {@code 405} a method the path does not take. That is
     * why {@code 412}, {@code 429}, {@code 472} and {@code 473} are named here at all: they are 4xx numbers carrying a
     * statement about the cluster, and only the vendor's table says so. Anything outside both classes — a redirect from
     * a misconfigured or hijacked address, say — recurs the same way an unrecognised 4xx does.
     *
     * <p>This is deliberately not how a push service's statuses read: a push service answering {@code 501} says "not
     * implemented", an answer about the request that will not change, where Vault publishes {@code 501} as "not
     * initialized", a cluster state that ends the moment someone initializes it. Same number, opposite meaning, each
     * read off the specification that governs its own seam.
     */
    private static boolean custodianCannotServeNow(int status) {
        return status == 412 || status == 429 || status == 472 || status == 473 || (status >= 500 && status < 600);
    }

    /**
     * {@code vault:v1:<base64url>} → {@code <base64url>}, matching the prefix exactly rather than cutting at the last
     * colon. Vault's signature is always {@code vault:v<version>:<payload>}, so anything else is a response this signer
     * did not ask for — an error envelope, a wrapped token, a value from some other Vault API. Cutting at a colon would
     * hand whatever followed it to the base64url decoder, and the failure would then surface as "not valid base64url"
     * (or, worse, as a decoded 64-byte blob) instead of naming the real problem: the response is not a Transit
     * signature.
     *
     * <p>A pinned signer additionally requires the envelope's version to <em>be</em> the pin. The pin exists because
     * the advertised public key belongs to exactly one Transit key version — a signature from any other version can
     * never verify against it, and accepting one would surface only as an opaque push-service rejection, far from the
     * Vault response that caused it. The versions are compared as strings against the pin's canonical decimal form:
     * Vault never emits leading zeros or a version beyond an int, so an envelope shaped that way is not Vault's and
     * must not be normalised into matching.
     *
     * <p>The offending value is not echoed, for the same reason {@link #sign} keeps a corrupt payload out of its
     * message — and more so here: a value that failed the signature shape is, by definition, not known to be a
     * signature, and Vault dresses wrapped tokens and Transit ciphertext in the same {@code vault:v<n>:} clothing. The
     * mismatch message carries only the two version numbers ({@link #logSafeExcerpt} keeps a nonsense digit run
     * log-safe).
     */
    private static String stripVaultPrefix(String marshalled, @Nullable Integer keyVersion) {
        Matcher signature = VAULT_SIGNATURE.matcher(marshalled);
        if (!signature.matches()) {
            throw new PushCryptoException("unexpected Vault signature format: expected 'vault:v<version>:<base64url>'");
        }
        if (keyVersion != null && !signature.group(1).equals(Integer.toString(keyVersion))) {
            throw new PushCryptoException("Vault Transit signed with key version " + logSafeExcerpt(signature.group(1))
                    + ", but this signer is pinned to key version " + keyVersion + " — the advertised VAPID public"
                    + " key belongs to the pinned version, so this signature could never verify against it");
        }
        return signature.group(2);
    }

    /** The transport a builder was given, or a fresh default one — never shared between signers. */
    private static VaultHttpTransport orDefaultTransport(@Nullable VaultHttpTransport transport) {
        return transport == null ? new JdkVaultHttpTransport() : transport;
    }

    /**
     * The headers every Vault call carries: the token, plus the {@code X-Vault-Namespace} header when — and only when —
     * a namespace was set. Both values are safe for an HTTP header field by construction: a {@link VaultToken} is
     * visible ASCII by its own contract, and a namespace passed {@link #requireValidVaultPath}, whose allowed set is a
     * strict subset of visible ASCII with no CR/LF or other control characters — so neither can smuggle a header
     * terminator or a second header into the request.
     */
    private static Map<String, String> vaultHeaders(String token, @Nullable String namespace) {
        return namespace == null
                ? Map.of(TOKEN_HEADER, token)
                : Map.of(TOKEN_HEADER, token, NAMESPACE_HEADER, namespace);
    }

    /**
     * Validate the Vault base address where it is set — both factory methods, so an unusable address fails the call
     * that supplied it and {@code build()} never trips over it. The address must be absolute and carry a host (a
     * relative or opaque URI names no server to call), and must carry neither a query nor a fragment: the signer
     * appends {@code /v1/…} API paths to it, and RFC 3986 §5.3 gives a base's query and fragment no way into the joined
     * URI — a value that would be silently discarded is a misconfiguration worth naming. The scheme must be
     * {@code http} or {@code https} (case-insensitively — RFC 3986 §3.1 schemes are), because the signer speaks Vault's
     * HTTP API and no other protocol can carry these requests; anything else fails here, at the factory, since no later
     * builder step could rescue it. What this method deliberately does <em>not</em> decide is whether plain
     * {@code http} is acceptable towards the configured host — that depends on the builders' optional
     * {@code allowInsecureHttp()} step, which is called only after the factory has returned, so that rule lives in
     * {@code build()} ({@link #requirePlainHttpPermitted}).
     *
     * <p>The path — the reverse-proxy or ingress prefix the API paths are appended after — is validated by the same
     * per-segment rule as {@code mount}, for the same reasons ({@link #requireValidVaultPath}): it rides in front of
     * every token-bearing request path, so a {@code .}/{@code ..} segment (or a percent-encoded {@code %2e%2e}, which
     * the allowed set excludes wholesale) must fail loudly at configuration instead of reaching a hop that rewrites it.
     * A single trailing slash is legal — {@code https://gw.example/vault/} and {@code https://gw.example/vault} are the
     * same base, and the join drops it — but an empty interior segment ({@code //}) is refused: two operators cannot
     * agree on what it addresses, and a collapsing hop answers for neither.
     */
    private static URI requireValidVaultAddress(URI address) {
        Objects.requireNonNull(address, "address");
        if (!address.isAbsolute()
                || address.getHost() == null
                || address.getHost().isEmpty()) {
            throw new IllegalArgumentException(
                    "address must be an absolute URI with a host, e.g. https://vault.example:8200"
                            + " or https://gw.example/vault");
        }
        String scheme = address.getScheme();
        if (!HTTP_SCHEME.equalsIgnoreCase(scheme) && !HTTPS_SCHEME.equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("address scheme must be http or https, got '" + scheme
                    + "' — the signer speaks Vault's HTTP API, and no other protocol can carry these requests");
        }
        if (address.getRawQuery() != null) {
            throw new IllegalArgumentException("address must not carry a query — it is a base address the Vault API"
                    + " paths (/v1/…) are appended to, and a base's query has no way into the joined URI");
        }
        if (address.getRawFragment() != null) {
            throw new IllegalArgumentException("address must not carry a fragment — it is a base address the Vault API"
                    + " paths (/v1/…) are appended to, and a base's fragment has no way into the joined URI");
        }
        requireValidVaultAddressPath(address.getRawPath());
        return address;
    }

    /**
     * The path half of {@link #requireValidVaultAddress}: empty is the common case (no prefix), otherwise every segment
     * of the <em>raw</em> path — checked raw so percent-encoding cannot smuggle what the literal check refuses — must
     * be non-empty, not {@code .} or {@code ..}, and drawn from the {@link #allowedVaultPathCharacter same allowed set
     * as mount}, which contains no {@code %}. One trailing empty segment (a single trailing slash) is tolerated and
     * later dropped by {@link #vaultApiUri}.
     */
    private static void requireValidVaultAddressPath(@Nullable String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) {
            return;
        }
        String[] segments = rawPath.split("/", -1);
        // segments[0] is the empty run before the leading '/' (a URI with an authority can carry
        // no other path shape); a trailing '/' contributes one final empty segment, tolerated.
        for (int i = 1; i < segments.length; i++) {
            String segment = segments[i];
            if (segment.isEmpty()) {
                if (i == segments.length - 1) {
                    continue;
                }
                throw new IllegalArgumentException(
                        "address path must not contain an empty '//' segment — a Vault behind a path prefix is"
                                + " written like https://gw.example/vault, one non-empty segment per '/'");
            }
            if (".".equals(segment) || "..".equals(segment)) {
                throw new IllegalArgumentException("address path must not contain a '" + segment + "' segment — the"
                        + " path prefixes every token-bearing Vault request, and a normalizing proxy in front of"
                        + " Vault would collapse such a segment before Vault sees it, so the request's destination"
                        + " would depend on which hops are deployed");
            }
            for (int j = 0; j < segment.length(); j++) {
                if (!allowedVaultPathCharacter(segment.charAt(j))) {
                    throw new IllegalArgumentException("address path contains a character outside the allowed set"
                            + " [A-Za-z0-9_.-] and '/'. The set is deliberately narrower than URLs allow, for the"
                            + " same reason as the mount rule: a percent-encoded sequence would survive to a"
                            + " decoding hop that rewrites the request path, and the conservative set can be"
                            + " widened later without breaking compatibility");
                }
            }
        }
    }

    /**
     * The {@code build()}-time half of the scheme rule (the factory half is {@link #requireValidVaultAddress}): plain
     * {@code http} to a host that is not a literal loopback is refused unless the builder's {@code allowInsecureHttp()}
     * step opted in. This is the one address rule that cannot live at the factory, where every other
     * invalid-but-present value is rejected — the opt-in is a builder step and is called only after the factory has
     * returned — so both builders call this first thing in {@code build()}, before any other work; in the fetched mode
     * that means before the Vault read, so a refused address fails without contacting anything.
     *
     * <p>Loopback is decided from the literal host text, never by resolving the name: resolution would be a network
     * call inside validation, could disagree with whatever the transport's own resolver answers later, and would make
     * the rule depend on the environment instead of on the address. The literal set is essentially the one browsers
     * treat as a secure context — {@code localhost}, any name under {@code .localhost}, an IPv4 dotted-quad in
     * {@code 127.0.0.0/8} written in canonical decimal, and a bracketed IP literal denoting a loopback address, which
     * covers the IPv6 loopback in any spelling and the IPv4-mapped writings of {@code 127.0.0.0/8}
     * ({@link #isLoopbackLiteral}). A private name that merely <em>resolves</em> to a loopback ({@code http://my-vault}
     * through the hosts file) therefore needs the opt-in — the accepted price of a rule readable from the address
     * alone.
     */
    private static void requirePlainHttpPermitted(URI address, boolean allowInsecureHttp) {
        if (!HTTP_SCHEME.equalsIgnoreCase(address.getScheme())
                || allowInsecureHttp
                || isLoopbackLiteral(address.getHost())) {
            return;
        }
        throw new IllegalArgumentException("address uses plain http to a host that is not a literal loopback:"
                + " every Vault call carries the Vault token in the X-Vault-Token request header, so over http the"
                + " token would cross the network in clear text. Use an https address, or accept that risk"
                + " deliberately by calling allowInsecureHttp() on this builder. No opt-in is needed for a literal"
                + " loopback host — localhost, a name under .localhost, a four-octet 127.0.0.0/8 IPv4 literal in"
                + " canonical decimal (127.0.0.1, but neither the shorthand 127.1 nor the leading-zero 0177.0.0.1),"
                + " or a bracketed IP literal denoting a loopback address ([::1] in any spelling, and the IPv4-mapped"
                + " writings such as [::ffff:127.0.0.1]) — where a TLS-terminating Vault Agent or sidecar beside the"
                + " application keeps the token on the machine");
    }

    /**
     * Whether {@code host} — as {@link URI#getHost()} reports it — is a literal loopback, decided from the text alone
     * (the rationale lives on {@link #requirePlainHttpPermitted}): {@code localhost} or a name under
     * {@code .localhost}, compared ASCII case-insensitively because RFC 3986 §3.2.2 host names are; an IPv4 dotted-quad
     * in {@code 127.0.0.0/8} written in canonical decimal ({@link #isIpv4LoopbackLiteral}); or a bracketed IP literal
     * that denotes a loopback address.
     *
     * <p>The bracketed form is parsed rather than string-compared because one address has many legal spellings, and
     * because the question is which address the literal denotes rather than how it is written: {@code [::1]} and
     * {@code [0:0:0:0:0:0:0:1]} are the same IPv6 loopback, while the IPv4-mapped writings {@code [::ffff:127.0.0.1]}
     * and {@code [::ffff:7f00:1]} are a <em>different</em> 128-bit value that the platform resolves to the IPv4 address
     * it maps — {@code 127.0.0.1} here, so the traffic reaches the same place plain {@code 127.0.0.1} does and is
     * admitted for the same reason. A mapped form of anything else ({@code [::ffff:8.8.8.8]}) maps to a non-loopback
     * address and is refused, as is the deprecated IPv4-compatible form {@code [::127.0.0.1]}, which denotes an IPv6
     * address that is not the loopback. RFC 3986 §3.2.2 admits only an IP literal inside brackets, never a name, so
     * this parse can involve no name resolution.
     */
    private static boolean isLoopbackLiteral(String host) {
        String lowerCased = host.toLowerCase(Locale.ROOT);
        if ("localhost".equals(lowerCased) || lowerCased.endsWith(".localhost")) {
            return true;
        }
        if (host.startsWith("[")) {
            try {
                return InetAddress.getByName(host).isLoopbackAddress();
            } catch (UnknownHostException e) {
                // Not a parseable IP literal (an IPvFuture form, say) — not known to be loopback,
                // so plain http to it takes the explicit opt-in like any other host.
                return false;
            }
        }
        return isIpv4LoopbackLiteral(host);
    }

    /**
     * Whether {@code host} is an IPv4 dotted-quad literal in {@code 127.0.0.0/8}: exactly four {@code .}-separated
     * decimal octets, each 0–255 with no leading zeros, the first being {@code 127}. Leading zeros are refused rather
     * than read as decimal because {@code inet_aton}-style parsers read them as octal — {@code 0177.0.0.1} is loopback
     * to one parser and 177.0.0.1 to another, and a form whose meaning depends on the resolver is not a literal this
     * rule can vouch for. Shorthand forms ({@code 127.1}) are refused for the same reason.
     */
    private static boolean isIpv4LoopbackLiteral(String host) {
        String[] octets = host.split("\\.", -1);
        if (octets.length != 4 || !"127".equals(octets[0])) {
            return false;
        }
        for (String octet : octets) {
            if (!isDecimalOctet(octet)) {
                return false;
            }
        }
        return true;
    }

    /** Whether {@code octet} is a canonical decimal octet: 1–3 ASCII digits, no leading zero, value at most 255. */
    private static boolean isDecimalOctet(String octet) {
        if (octet.isEmpty() || octet.length() > 3 || (octet.length() > 1 && octet.charAt(0) == '0')) {
            return false;
        }
        int value = 0;
        for (int i = 0; i < octet.length(); i++) {
            char c = octet.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
            value = value * 10 + (c - '0');
        }
        return value <= 255;
    }

    /**
     * The URI of a Vault API path below the validated base address: scheme and authority verbatim, then the address's
     * path with any single trailing slash dropped, then {@code pathBelowRoot} (which starts with {@code /v1/}).
     *
     * <p>Assembled by concatenation, deliberately not {@link URI#resolve}: per RFC 3986 §5.3 an absolute-path reference
     * ({@code resolve("/v1/…")}) replaces the base's path <em>entirely</em>, silently discarding a reverse-proxy prefix
     * like {@code /vault} — and the relative form ({@code resolve("v1/…")}) is no fix, because merging drops everything
     * after the base path's last {@code /}, so a prefix without a trailing slash would lose its final segment, just
     * more quietly. The concatenation is exact because {@link #requireValidVaultAddress} already pinned the shape:
     * absolute, host present, no query or fragment, and a path of plain allowed-set segments, so scheme + authority +
     * path is the whole of the address.
     */
    private static URI vaultApiUri(URI address, String pathBelowRoot) {
        String prefix = address.getRawPath();
        if (prefix == null) {
            prefix = "";
        } else if (prefix.endsWith("/")) {
            // At most one: the per-segment rule refuses interior empty segments, so a validated
            // path can end in a single '/' only.
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        return URI.create(address.getScheme() + "://" + address.getRawAuthority() + prefix + pathBelowRoot);
    }

    /**
     * Validate a slash-separated Vault path value where it is set — both builders' {@code mount(...)} and
     * {@code namespace(...)} steps share this one rule, with {@code name} naming the offending value in the failure and
     * {@code nestedExample} showing the legal nested shape. The rule is looser than {@link TransitKeyName}'s because
     * nesting is legal — {@code secrets/transit} names a Transit engine mounted under a prefix, {@code team-a/sub} a
     * child namespace — and is applied per segment: split on {@code /}, every segment must be non-empty, not {@code .}
     * or {@code ..}, and drawn from {@code [A-Za-z0-9_.-]} only.
     *
     * <p>An explicit allowed set, not a blacklist, because a blacklist here is reopenable by encoding: a
     * percent-encoded {@code %2e%2e} or {@code %2F} passes any literal {@code ..}/{@code /} check and travels in the
     * raw request path — {@link URI#resolve} does <em>not</em> normalize dot segments in an absolute-path reference
     * such as the {@code /v1/…} this signer builds, so the path goes onto the wire exactly as written. What happens
     * next depends on the hops. Go's {@code net/url} decodes the path before Vault routes it, so a {@code %2F}
     * addresses a different mount inside Vault itself. A decoded dot segment makes Vault's own handler
     * ({@code cleanPath} in {@code http/handler.go}) answer a <em>307 redirect</em> to the collapsed path — the default
     * transport ({@code Redirect.NEVER}) refuses it loudly, but a redirect-following custom transport would execute it,
     * re-sending {@code X-Vault-Token} to the other path. And a normalizing proxy in front of Vault (nginx
     * {@code proxy_pass} with a URI part, HAProxy {@code normalize-uri}) collapses the path before Vault sees it at
     * all. The literal {@code .}/{@code ..} segments are refused for the same hops. A token-bearing request whose
     * destination depends on which of those hops is deployed must fail loudly at configuration instead.
     *
     * <p>A <em>namespace</em> travels differently — in the {@code X-Vault-Namespace} HTTP header, not the URL — so the
     * hops above do not act on it, and the same rule is applied for two other reasons. The first is definite: a header
     * value must be header-safe, and the allowed set is a strict subset of visible ASCII with no CR/LF or any other
     * control character, so a validated value cannot terminate the header or inject another one — no transport is
     * handed a value whose safety it would otherwise have to enforce itself.
     *
     * <p>The second is defence in depth rather than a known route. A {@code ..} cannot name a real namespace —
     * {@code namespace.Canonicalize} in Vault's {@code helper/namespace} only trims a leading slash and appends a
     * trailing one, with no dot-segment collapsing and no decoding, and the closed-source resolution that follows looks
     * the canonical value up rather than walking a path. So such a value is a configuration mistake either way, and
     * refusing it at construction costs nothing while removing the need to know what every future hop does with a
     * composite path. Do not read this as a described traversal: no such route through OSS Vault is established here.
     *
     * <p>The allowed set is deliberately narrower than either Vault or a URL requires — that is policy, not necessity.
     * Vault accepts any printable Unicode in a mount path ({@code validateMountPath} in
     * {@code vault/logical_system.go}: canonical per {@code path.Clean}, no unprintables), and fourteen further
     * characters ({@code ~ ! $ & ' ( ) * + , ; = : @}) are legal <em>raw</em> in a URI path segment — a mount like
     * {@code transit+prod} is real and was addressable through this signer before this rule existed. They are excluded
     * anyway: some of that punctuation is treated specially by intermediaries (a {@code ;} reads as a path parameter to
     * some hops), and a set admitting only what every hop treats literally can be widened later without breaking anyone
     * — the reverse is not true. Every common mount shape — {@code transit}, {@code transit-prod},
     * {@code team_a/secrets/transit} — and every common namespace shape — {@code team-a}, {@code team-a/sub} — fits the
     * set. For namespaces as for mounts the narrowness is policy, not a claim about what Vault accepts: Vault's
     * documentation forbids only spaces, a trailing {@code /} and a few reserved names in a namespace path, so a wider
     * name may exist in a deployment and be refused here until the set is widened.
     */
    private static String requireValidVaultPath(
            String value, String name, String nestedExample, String dotSegmentReason) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        for (int i = 0; i < value.length(); i++) {
            if (!allowedVaultPathCharacter(value.charAt(i))) {
                throw new IllegalArgumentException(name + " contains a character (at index " + i + ") outside the"
                        + " allowed set [A-Za-z0-9_.-] and '/'. The set is deliberately narrower than Vault and"
                        + " URLs allow: a percent-encoded sequence would survive to a decoding hop that rewrites"
                        + " the request path, and some URL-legal punctuation is treated specially by"
                        + " intermediaries — the conservative set can be widened later without breaking"
                        + " compatibility");
            }
        }
        for (String segment : value.split("/", -1)) {
            if (segment.isEmpty()) {
                throw new IllegalArgumentException(name + " must not begin or end with '/' or contain an empty '//'"
                        + " segment — a nested " + name + " is written like \"" + nestedExample + "\". Vault's CLI"
                        + " prints these paths with a trailing slash as a hierarchy marker (\"" + nestedExample
                        + "/\"); the configured value does not carry it");
            }
            if (".".equals(segment) || "..".equals(segment)) {
                throw new IllegalArgumentException(
                        name + " must not contain a '" + segment + "' segment — " + dotSegmentReason);
            }
        }
        return value;
    }

    /**
     * Whether {@code c} may appear in a Vault path value: the {@code [A-Za-z0-9_.-]} segment set plus the separator.
     */
    private static boolean allowedVaultPathCharacter(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '_'
                || c == '.'
                || c == '-'
                || c == '/';
    }

    /**
     * Builds a signer in the <b>fetched</b> mode, reading the public key and its key version from Vault. Obtained from
     * {@link VaultTransitVapidSigner#builderWithFetchedPublicKey(URI, TransitKeyName, VaultToken)}, which takes
     * everything required — this builder holds only the optional steps, so {@code build()} can never refuse over a
     * missing value.
     *
     * <p>{@link #mount(String)} defaults to {@code "transit"}, {@link #namespace(String)} to none (no
     * {@code X-Vault-Namespace} header is sent), {@link #transport(VaultHttpTransport)} to a fresh
     * {@link JdkVaultHttpTransport}, and {@link #allowInsecureHttp()} is off — plain {@code http} beyond a literal
     * loopback host is refused by {@code build()} without it, before the Vault read. There is deliberately no
     * {@code keyVersion} step: this mode takes the version from the same {@code transit/keys/<key>} response as the
     * public key, which is what keeps the two in step.
     */
    public static final class FetchedPublicKeyBuilder {

        private final URI address;
        private final TransitKeyName keyName;
        private final VaultToken token;

        private String mount = DEFAULT_MOUNT;

        @Nullable
        private String namespace;

        @Nullable
        private VaultHttpTransport transport;

        private boolean allowInsecureHttp;

        private FetchedPublicKeyBuilder(URI address, TransitKeyName keyName, VaultToken token) {
            // Validated here, so the failure points at the factory call that supplied the value
            // rather than at build() — which in this mode also performs I/O and must not be the
            // first place a bad address is noticed.
            this.address = requireValidVaultAddress(address);
            this.keyName = Objects.requireNonNull(keyName, "keyName");
            this.token = Objects.requireNonNull(token, "token");
        }

        /**
         * Sets the Transit mount path. Optional — defaults to {@code "transit"}, Vault's own default mount for the
         * Transit secrets engine. Nested mounts ({@code secrets/transit}) are legal; validated where it is set, per
         * segment: every {@code /}-separated segment must be non-empty, not {@code .} or {@code ..}, and drawn from
         * {@code [A-Za-z0-9_.-]} — an allowed set rather than a blacklist, because a percent-encoded {@code %2e%2e}
         * would otherwise reopen what the literal check closes. The rationale lives on the validator in
         * {@link VaultTransitVapidSigner}.
         *
         * @param mount the Transit mount path
         * @return this builder
         * @throws IllegalArgumentException if {@code mount} is blank or violates the per-segment rule
         */
        public FetchedPublicKeyBuilder mount(String mount) {
            this.mount = requireValidVaultPath(
                    mount,
                    "mount",
                    "secrets/transit",
                    "a normalizing proxy in front of Vault collapses it before Vault sees it, and Vault's own handler answers the decoded form with a 307 redirect to the collapsed path, which a redirect-following transport would re-send, X-Vault-Token header included, to a different Vault path");
            return this;
        }

        /**
         * Sets the Vault Enterprise/HCP namespace the Transit engine lives in, sent as the {@code X-Vault-Namespace}
         * header on <em>both</em> Vault calls — the one-time {@code transit/keys/<key>} read inside {@link #build()}
         * and every {@code sign}. Optional — when unset, no such header is sent at all, which is what Vault OSS (no
         * namespaces) expects. Nested namespaces ({@code team-a/sub}) are legal; validated where it is set, by the same
         * per-segment rule as {@link #mount(String)}: every {@code /}-separated segment must be non-empty, not
         * {@code .} or {@code ..}, and drawn from {@code [A-Za-z0-9_.-]}. The value travels in an HTTP <em>header</em>,
         * which the rule also keeps safe: the allowed set is a strict subset of visible ASCII with no control
         * characters, so a validated namespace can never terminate the header or inject another. The full rationale
         * lives on the validator in {@link VaultTransitVapidSigner}.
         *
         * @param namespace the Vault namespace path, e.g. {@code team-a} or {@code team-a/sub}
         * @return this builder
         * @throws IllegalArgumentException if {@code namespace} is blank or violates the per-segment rule
         */
        public FetchedPublicKeyBuilder namespace(String namespace) {
            this.namespace = requireValidVaultPath(
                    namespace,
                    "namespace",
                    "team-a/sub",
                    "a namespace travels in the X-Vault-Namespace header rather than the URL, so no path-collapsing hop acts on it and no such value can name a real namespace — it is a configuration mistake, refused here rather than sent");
            return this;
        }

        /**
         * Sets the transport used for <em>both</em> Vault calls — the one-time {@code transit/keys/<key>} read and
         * every {@code sign} — so custom mTLS/proxy configuration is never bypassed. Optional; a fresh
         * {@link JdkVaultHttpTransport} is used otherwise.
         *
         * @param transport the HTTP transport for the Vault API calls
         * @return this builder
         */
        public FetchedPublicKeyBuilder transport(VaultHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Permits plain {@code http} to a host that is not a literal loopback. Without this step {@link #build()}
         * refuses such an address, because every Vault call carries the Vault token in the {@code X-Vault-Token}
         * request header and plain HTTP to a remote host sends it across the network in clear text. Call it only where
         * that hop is genuinely acceptable — a physically isolated network, a test bench — and prefer {@code https}, or
         * a TLS-terminating Vault Agent or sidecar on the same host, which needs no opt-in at all: {@code http} to a
         * literal loopback host ({@code localhost}, a name under {@code .localhost}, a {@code 127.0.0.0/8} IPv4
         * dotted-quad in canonical decimal — so {@code 127.0.0.1}, but neither {@code 127.1} nor {@code 0177.0.0.1} —
         * or a bracketed IP literal denoting a loopback address, {@code [::1]} in any spelling and the IPv4-mapped
         * writings such as {@code [::ffff:127.0.0.1]}) is always accepted. The decision reads the host text literally,
         * never resolving it, so a hosts-file alias of {@code 127.0.0.1} still needs this step.
         *
         * <p>{@code https} addresses are unaffected — this step neither weakens TLS nor changes certificate validation.
         *
         * @return this builder
         */
        public FetchedPublicKeyBuilder allowInsecureHttp() {
            this.allowInsecureHttp = true;
            return this;
        }

        /**
         * Reads {@code transit/keys/<keyName>} once, then builds the signer pinned to the version that response
         * advertised as latest.
         *
         * <p><b>This is the {@code build()} that reads a key over a network, and what it throws is what a startup
         * supervisor branches on.</b> The order of the tests is part of the contract, and it begins with the interrupt,
         * not with the type:
         *
         * <ol>
         *   <li><b>Test the interruption first</b> — the current thread's interrupt status is set, <em>or</em> an
         *       {@link InterruptedException} is somewhere in the cause chain; neither half of that disjunction is sound
         *       alone. A boot interrupted while the key is being read raises the unavailable type below as well,
         *       because a transport does not sort an incomplete exchange by what made it incomplete — so a supervisor
         *       that reads the type first answers a shutdown by looping its own boot, with every backoff it sleeps
         *       failing instantly on an interrupt status nobody cleared. An interruption is a cancellation: propagate
         *       it, retry nothing, alert nobody.
         *   <li>{@link VapidSignerUnavailableException} is a custodian that cannot serve the read <em>now</em> —
         *       unreachable, sealed, not initialized, standing by, not caught up, rate-limited. That ends on Vault's
         *       own terms, so it is a boot worth retrying with backoff, not before any moment the exception's
         *       {@link VapidSignerUnavailableException#retryAfter() retryAfter()} names.
         *   <li>{@link PushCryptoException} recurs until a person changes something — a token without the capability, a
         *       key or mount that is not there, a key that is not on P-256, a response Vault could not have meant — so
         *       it fails the deployment, and retrying the boot over it only postpones the page.
         * </ol>
         *
         * @return the signer
         * @throws IllegalArgumentException if the address uses plain {@code http} to a host that is not a literal
         *     loopback and {@link #allowInsecureHttp()} was not called — checked before the Vault read, so a refused
         *     address fails without contacting anything
         * @throws VapidSignerUnavailableException if Vault cannot serve the key read now — nothing answered (a refused
         *     connection, a failed handshake, a timeout, an interrupted wait — the interrupt status then re-set), or
         *     Vault answered a status naming its own condition rather than the request's
         * @throws PushCryptoException if the key read fails for a reason that recurs, or the key is not a usable P-256
         *     key
         */
        public VaultTransitVapidSigner build() {
            // First thing, before the Vault read: a refused address must fail without any network
            // contact. This is the one address rule that cannot live at the factory — the opt-in
            // above is a builder step, called only after the factory has returned.
            requirePlainHttpPermitted(address, allowInsecureHttp);
            VaultHttpTransport resolvedTransport = orDefaultTransport(transport);
            VaultKeyMetadata metadata = fetchKeyMetadata(
                    vaultApiUri(address, "/v1/" + mount + "/keys/" + keyName.value()),
                    namespace,
                    token.value(),
                    resolvedTransport);
            return new VaultTransitVapidSigner(
                    address,
                    mount,
                    namespace,
                    keyName,
                    token,
                    metadata.version(),
                    metadata.publicKey(),
                    resolvedTransport);
        }
    }

    /**
     * Builds a signer in the <b>deferred fetch</b> mode: the public key and its version still come from Vault as one
     * atomic {@code transit/keys/<key>} pair, but the read happens at first use — the first {@code sign},
     * {@code publicKey} or {@code publicKeyBase64Url} call — instead of inside {@link #build()}. Obtained from
     * {@link VaultTransitVapidSigner#builderWithDeferredPublicKeyFetch(URI, TransitKeyName, VaultToken)}, which takes
     * everything required — this builder holds only the optional steps, so {@code build()} can never refuse over a
     * missing value.
     *
     * <p>{@link #mount(String)} defaults to {@code "transit"}, {@link #namespace(String)} to none (no
     * {@code X-Vault-Namespace} header is sent), {@link #transport(VaultHttpTransport)} to a fresh
     * {@link JdkVaultHttpTransport}, and {@link #allowInsecureHttp()} is off — plain {@code http} beyond a literal
     * loopback host is refused by {@code build()} without it. There is deliberately no {@code keyVersion} step: this
     * mode takes the version from the same {@code transit/keys/<key>} response as the public key, which is what keeps
     * the two in step.
     *
     * <p><b>What first use does, and how concurrent first uses behave.</b> The signer performs at most one metadata
     * read at a time: the first caller fetches, concurrent callers wait on that caller's read — bounded by the
     * transport's connect and request timeouts — and a successful pair is retained for the signer's lifetime, so no
     * later call reads it again. A failed read is never remembered: callers waiting on the failed read each receive
     * their own exception of the same contract type, carrying the read's own failure as its cause and, for the
     * unavailability, the status and any declared delay it reported — and the next caller after the failure simply
     * starts a new read. An interruption is never spread beyond the thread it belongs to: an interrupted fetching
     * caller keeps its own exception while the waiters retry the read among themselves, and an interrupted waiter
     * receives its own {@link VapidSignerUnavailableException} with the {@link InterruptedException} beneath it and the
     * interrupt flag re-set, while the read continues for everyone else.
     */
    public static final class DeferredPublicKeyFetchBuilder {

        private final URI address;
        private final TransitKeyName keyName;
        private final VaultToken token;

        private String mount = DEFAULT_MOUNT;

        @Nullable
        private String namespace;

        @Nullable
        private VaultHttpTransport transport;

        private boolean allowInsecureHttp;

        private DeferredPublicKeyFetchBuilder(URI address, TransitKeyName keyName, VaultToken token) {
            // Validated here, so the failure points at the factory call that supplied the value
            // rather than at build().
            this.address = requireValidVaultAddress(address);
            this.keyName = Objects.requireNonNull(keyName, "keyName");
            this.token = Objects.requireNonNull(token, "token");
        }

        /**
         * Sets the Transit mount path. Optional — defaults to {@code "transit"}, Vault's own default mount for the
         * Transit secrets engine. Nested mounts ({@code secrets/transit}) are legal; validated where it is set, per
         * segment: every {@code /}-separated segment must be non-empty, not {@code .} or {@code ..}, and drawn from
         * {@code [A-Za-z0-9_.-]} — an allowed set rather than a blacklist, because a percent-encoded {@code %2e%2e}
         * would otherwise reopen what the literal check closes. The rationale lives on the validator in
         * {@link VaultTransitVapidSigner}.
         *
         * @param mount the Transit mount path
         * @return this builder
         * @throws IllegalArgumentException if {@code mount} is blank or violates the per-segment rule
         */
        public DeferredPublicKeyFetchBuilder mount(String mount) {
            this.mount = requireValidVaultPath(
                    mount,
                    "mount",
                    "secrets/transit",
                    "a normalizing proxy in front of Vault collapses it before Vault sees it, and Vault's own handler answers the decoded form with a 307 redirect to the collapsed path, which a redirect-following transport would re-send, X-Vault-Token header included, to a different Vault path");
            return this;
        }

        /**
         * Sets the Vault Enterprise/HCP namespace the Transit engine lives in, sent as the {@code X-Vault-Namespace}
         * header on <em>both</em> Vault calls — the first-use {@code transit/keys/<key>} read and every {@code sign}.
         * Optional — when unset, no such header is sent at all, which is what Vault OSS (no namespaces) expects. Nested
         * namespaces ({@code team-a/sub}) are legal; validated where it is set, by the same per-segment rule as
         * {@link #mount(String)}: every {@code /}-separated segment must be non-empty, not {@code .} or {@code ..}, and
         * drawn from {@code [A-Za-z0-9_.-]}. The value travels in an HTTP <em>header</em>, which the rule also keeps
         * safe: the allowed set is a strict subset of visible ASCII with no control characters, so a validated
         * namespace can never terminate the header or inject another. The full rationale lives on the validator in
         * {@link VaultTransitVapidSigner}.
         *
         * @param namespace the Vault namespace path, e.g. {@code team-a} or {@code team-a/sub}
         * @return this builder
         * @throws IllegalArgumentException if {@code namespace} is blank or violates the per-segment rule
         */
        public DeferredPublicKeyFetchBuilder namespace(String namespace) {
            this.namespace = requireValidVaultPath(
                    namespace,
                    "namespace",
                    "team-a/sub",
                    "a namespace travels in the X-Vault-Namespace header rather than the URL, so no path-collapsing hop acts on it and no such value can name a real namespace — it is a configuration mistake, refused here rather than sent");
            return this;
        }

        /**
         * Sets the transport used for <em>both</em> Vault calls — the first-use {@code transit/keys/<key>} read and
         * every {@code sign} — so custom mTLS/proxy configuration is never bypassed. Optional; a fresh
         * {@link JdkVaultHttpTransport} is used otherwise.
         *
         * <p>Its request timeout carries one extra weight in this mode: a concurrent caller meeting an uninitialized
         * signer waits on the first caller's read, bounded by the transport's own connect and request timeouts and by
         * nothing this library adds — so a custom transport that sets no request timeout holds every waiting caller,
         * not only the one that started the read.
         *
         * @param transport the HTTP transport for the Vault API calls
         * @return this builder
         */
        public DeferredPublicKeyFetchBuilder transport(VaultHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Permits plain {@code http} to a host that is not a literal loopback. Without this step {@link #build()}
         * refuses such an address, because every Vault call carries the Vault token in the {@code X-Vault-Token}
         * request header and plain HTTP to a remote host sends it across the network in clear text. Call it only where
         * that hop is genuinely acceptable — a physically isolated network, a test bench — and prefer {@code https}, or
         * a TLS-terminating Vault Agent or sidecar on the same host, which needs no opt-in at all: {@code http} to a
         * literal loopback host ({@code localhost}, a name under {@code .localhost}, a {@code 127.0.0.0/8} IPv4
         * dotted-quad in canonical decimal — so {@code 127.0.0.1}, but neither {@code 127.1} nor {@code 0177.0.0.1} —
         * or a bracketed IP literal denoting a loopback address, {@code [::1]} in any spelling and the IPv4-mapped
         * writings such as {@code [::ffff:127.0.0.1]}) is always accepted. The decision reads the host text literally,
         * never resolving it, so a hosts-file alias of {@code 127.0.0.1} still needs this step.
         *
         * <p>{@code https} addresses are unaffected — this step neither weakens TLS nor changes certificate validation.
         *
         * @return this builder
         */
        public DeferredPublicKeyFetchBuilder allowInsecureHttp() {
            this.allowInsecureHttp = true;
            return this;
        }

        /**
         * Builds the signer. Contacts Vault not at all: the {@code transit/keys/<key>} read — and with it the Transit
         * {@code type} check, the P-256 domain-parameter check and the on-curve check, the three checks that read a
         * Vault response — happens on the first {@code sign}, {@code publicKey} or {@code publicKeyBase64Url} call
         * instead. Every check that does not need a Vault response still happens at construction, with the same types
         * as the other builders — the plain-{@code http} rule below in this method, everything else at the factory or
         * at the step that took the value.
         *
         * <p><b>This {@code build()} therefore throws neither {@link VapidSignerUnavailableException} nor
         * {@link PushCryptoException}.</b> The contract the eagerly fetching builder documents for a startup supervisor
         * — test the interruption, then the type — belongs to that builder alone, because it is about the read its
         * {@code build()} performs; here there is no read to supervise and nothing of that kind to catch. Those
         * failures surface at first use instead: inside a send, the sender reports an unavailable custodian as its
         * signer-unavailable <em>outcome</em> and lets {@link PushCryptoException} propagate as itself; outside a send
         * — a health probe, or an application asking for the key it publishes to browsers — the first call throws
         * exactly what the eager {@code build()} would have thrown, and whoever supervises that call reads it in the
         * same order, interruption first.
         *
         * @return the signer
         * @throws IllegalArgumentException if the address uses plain {@code http} to a host that is not a literal
         *     loopback and {@link #allowInsecureHttp()} was not called
         */
        public VaultTransitVapidSigner build() {
            // The one address rule that cannot live at the factory: the opt-in above is a builder
            // step, called only after the factory has returned.
            requirePlainHttpPermitted(address, allowInsecureHttp);
            return new VaultTransitVapidSigner(
                    address, mount, namespace, keyName, token, orDefaultTransport(transport));
        }
    }

    /**
     * Builds a signer in the <b>explicit</b> mode, from a public key the caller already holds — hence the name.
     * Obtained from {@link VaultTransitVapidSigner#builderWithSuppliedPublicKey(URI, TransitKeyName, VaultToken,
     * byte[])}, which takes everything required — this builder holds only the optional steps, so {@code build()} can
     * never refuse over a missing value.
     *
     * <p>{@link #mount(String)} defaults to {@code "transit"}, {@link #namespace(String)} to none (no
     * {@code X-Vault-Namespace} header is sent), {@link #transport(VaultHttpTransport)} to a fresh
     * {@link JdkVaultHttpTransport}, {@link #allowInsecureHttp()} is off — plain {@code http} beyond a literal loopback
     * host is refused by {@code build()} without it — and {@link #keyVersion(int)} is optional but strongly recommended
     * — see its own documentation. {@link #build()} makes no Vault call.
     */
    public static final class SuppliedPublicKeyBuilder {

        private final URI address;
        private final TransitKeyName keyName;
        private final VaultToken token;
        private final byte[] publicKey;

        private String mount = DEFAULT_MOUNT;

        @Nullable
        private String namespace;

        @Nullable
        private Integer keyVersion;

        @Nullable
        private VaultHttpTransport transport;

        private boolean allowInsecureHttp;

        // The key is copied at the factory method, not only in the constructor the builder
        // eventually calls: otherwise the caller's array stays live for as long as the builder
        // does, and a mutation between builderWithSuppliedPublicKey(...) and build() would change
        // the advertised key. It is also validated here — the full on-curve check — so an invalid
        // key fails at the factory call that supplied it (the canonical constructor re-checks the
        // same invariant for the fetched mode's array).
        private SuppliedPublicKeyBuilder(URI address, TransitKeyName keyName, VaultToken token, byte[] publicKey) {
            // Validated here, like the key below, so the failure points at the factory call that
            // supplied the value (build() must never refuse over it).
            this.address = requireValidVaultAddress(address);
            this.keyName = Objects.requireNonNull(keyName, "keyName");
            this.token = Objects.requireNonNull(token, "token");
            Objects.requireNonNull(publicKey, "publicKey");
            P256PublicKeys.requireOnCurve(publicKey, "publicKey");
            this.publicKey = publicKey.clone();
        }

        /**
         * Sets the Transit mount path. Optional — defaults to {@code "transit"}, Vault's own default mount for the
         * Transit secrets engine. Nested mounts ({@code secrets/transit}) are legal; validated where it is set, per
         * segment: every {@code /}-separated segment must be non-empty, not {@code .} or {@code ..}, and drawn from
         * {@code [A-Za-z0-9_.-]} — an allowed set rather than a blacklist, because a percent-encoded {@code %2e%2e}
         * would otherwise reopen what the literal check closes. The rationale lives on the validator in
         * {@link VaultTransitVapidSigner}.
         *
         * @param mount the Transit mount path
         * @return this builder
         * @throws IllegalArgumentException if {@code mount} is blank or violates the per-segment rule
         */
        public SuppliedPublicKeyBuilder mount(String mount) {
            this.mount = requireValidVaultPath(
                    mount,
                    "mount",
                    "secrets/transit",
                    "a normalizing proxy in front of Vault collapses it before Vault sees it, and Vault's own handler answers the decoded form with a 307 redirect to the collapsed path, which a redirect-following transport would re-send, X-Vault-Token header included, to a different Vault path");
            return this;
        }

        /**
         * Sets the Vault Enterprise/HCP namespace the Transit engine lives in, sent as the {@code X-Vault-Namespace}
         * header on every {@code sign} call (this mode makes no other Vault call). Optional — when unset, no such
         * header is sent at all, which is what Vault OSS (no namespaces) expects. Nested namespaces
         * ({@code team-a/sub}) are legal; validated where it is set, by the same per-segment rule as
         * {@link #mount(String)}: every {@code /}-separated segment must be non-empty, not {@code .} or {@code ..}, and
         * drawn from {@code [A-Za-z0-9_.-]}. The value travels in an HTTP <em>header</em>, which the rule also keeps
         * safe: the allowed set is a strict subset of visible ASCII with no control characters, so a validated
         * namespace can never terminate the header or inject another. The full rationale lives on the validator in
         * {@link VaultTransitVapidSigner}.
         *
         * @param namespace the Vault namespace path, e.g. {@code team-a} or {@code team-a/sub}
         * @return this builder
         * @throws IllegalArgumentException if {@code namespace} is blank or violates the per-segment rule
         */
        public SuppliedPublicKeyBuilder namespace(String namespace) {
            this.namespace = requireValidVaultPath(
                    namespace,
                    "namespace",
                    "team-a/sub",
                    "a namespace travels in the X-Vault-Namespace header rather than the URL, so no path-collapsing hop acts on it and no such value can name a real namespace — it is a configuration mistake, refused here rather than sent");
            return this;
        }

        /**
         * Pins the Transit key version the supplied public key belongs to, sent as {@code key_version} on every
         * {@code sign} request. Optional, and <b>omitting it is unsafe under key rotation</b>: without a pin Vault
         * signs with the key's latest version, so after a rotation it signs with the new private key while this signer
         * keeps advertising the supplied public key, and push services reject the mismatch. Leave it out only for a
         * Transit key that is guaranteed never to rotate.
         *
         * @param keyVersion the Transit key version the supplied public key belongs to ({@code >= 1})
         * @return this builder
         * @throws IllegalArgumentException if {@code keyVersion} is below 1
         */
        public SuppliedPublicKeyBuilder keyVersion(int keyVersion) {
            // Validated where it is set, so the failure points at the call that supplied the value
            // (the canonical constructor re-checks the same invariant).
            if (keyVersion < 1) {
                throw new IllegalArgumentException("keyVersion must be >= 1, got " + keyVersion);
            }
            this.keyVersion = keyVersion;
            return this;
        }

        /**
         * Sets the transport used for every {@code sign} call. Optional; a fresh {@link JdkVaultHttpTransport} is used
         * otherwise.
         *
         * @param transport the HTTP transport for the Vault API calls
         * @return this builder
         */
        public SuppliedPublicKeyBuilder transport(VaultHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Permits plain {@code http} to a host that is not a literal loopback. Without this step {@link #build()}
         * refuses such an address, because every Vault call carries the Vault token in the {@code X-Vault-Token}
         * request header and plain HTTP to a remote host sends it across the network in clear text. Call it only where
         * that hop is genuinely acceptable — a physically isolated network, a test bench — and prefer {@code https}, or
         * a TLS-terminating Vault Agent or sidecar on the same host, which needs no opt-in at all: {@code http} to a
         * literal loopback host ({@code localhost}, a name under {@code .localhost}, a {@code 127.0.0.0/8} IPv4
         * dotted-quad in canonical decimal — so {@code 127.0.0.1}, but neither {@code 127.1} nor {@code 0177.0.0.1} —
         * or a bracketed IP literal denoting a loopback address, {@code [::1]} in any spelling and the IPv4-mapped
         * writings such as {@code [::ffff:127.0.0.1]}) is always accepted. The decision reads the host text literally,
         * never resolving it, so a hosts-file alias of {@code 127.0.0.1} still needs this step.
         *
         * <p>{@code https} addresses are unaffected — this step neither weakens TLS nor changes certificate validation.
         *
         * @return this builder
         */
        public SuppliedPublicKeyBuilder allowInsecureHttp() {
            this.allowInsecureHttp = true;
            return this;
        }

        /**
         * Builds the signer. Contacts nothing.
         *
         * @return the signer
         * @throws IllegalArgumentException if the address uses plain {@code http} to a host that is not a literal
         *     loopback and {@link #allowInsecureHttp()} was not called
         */
        public VaultTransitVapidSigner build() {
            // The one address rule that cannot live at the factory: the opt-in above is a builder
            // step, called only after the factory has returned.
            requirePlainHttpPermitted(address, allowInsecureHttp);
            return new VaultTransitVapidSigner(
                    address, mount, namespace, keyName, token, keyVersion, publicKey, orDefaultTransport(transport));
        }
    }
}
