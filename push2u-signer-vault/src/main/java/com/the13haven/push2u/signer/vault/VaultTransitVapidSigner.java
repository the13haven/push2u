/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.math.BigInteger;
import java.net.URI;
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
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

import com.the13haven.push2u.PushCryptoException;
import com.the13haven.push2u.VapidSigner;

/**
 * A {@link VapidSigner} that signs the VAPID JWT via HashiCorp Vault Transit — the private key never leaves Vault. It
 * POSTs the signing input to {@code {vaultAddress}/v1/{mount}/sign/{keyName}} with {@code marshaling_algorithm=jws}, so
 * Vault returns the raw {@code r || s} pair JOSE wants, and decodes it.
 *
 * <p>The Vault key must be an {@code ecdsa-p256} Transit key. The VAPID public key is your published identity; Vault
 * holds only the private half. There are two ways to supply the public key, one builder each — the two differ in
 * contract, not merely in parameters, which is why neither is the default:
 *
 * <ul>
 *   <li><b>Explicit</b> ({@link #builderWithSuppliedPublicKey(URI, TransitKeyName, VaultToken, byte[])} — the builder
 *       is named for what the caller does, supply the key) — pass the 65-byte X9.62 uncompressed point. {@code build()}
 *       performs no I/O. The Vault token then needs only the {@code sign} capability ({@code update} on
 *       {@code transit/sign/<key>}); the public key is never read from Vault. Use this for a strict sign-only token or
 *       an air-gapped public key.
 *       <p>The supplied key is checked <em>structurally only</em> — 65 bytes with the {@code 0x04} uncompressed tag. It
 *       is not verified to be a point on P-256, and nothing here can check that it is the public half of the Transit
 *       key being signed with: that remains the caller's responsibility. The P-256 validation described below applies
 *       to the fetched mode alone.
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
 * </ul>
 *
 * <p>Both Vault calls — the Transit {@code sign} POST and the fetched mode's one-time {@code transit/keys} read — go
 * through this module's {@link VaultHttpTransport} seam (default {@link JdkVaultHttpTransport}), so an application's
 * mTLS, proxy, or observability transport applies to the startup metadata read as much as to signing. Deliberately
 * <em>not</em> push2u-core's {@code PushHttpClient}: push delivery talks to untrusted capability URLs and discards
 * response bodies, while Vault's responses must be read — buffered under the transport's size cap and per-request
 * timeout. The small Vault request/response JSON is built and parsed by hand — no JSON library.
 *
 * <p>Both factory methods take everything required — the Vault base address, the {@link TransitKeyName} and the
 * {@link VaultToken} — so an incomplete signer cannot be expressed and {@code build()} never refuses over a missing
 * value; the value types keep the arguments impossible to swap and carry their own validation. The builders hold only
 * the optional steps: {@code mount} (default {@code "transit"}), {@code namespace} (default none — see below) and
 * {@code transport} (default {@link JdkVaultHttpTransport}). Only the supplied-key builder has {@code keyVersion} — in
 * the fetched mode the version is Vault's to state, not the caller's.
 *
 * <p><b>Vault namespaces (Enterprise/HCP):</b> when the Transit engine lives inside a <a
 * href="https://developer.hashicorp.com/vault/docs/enterprise/namespaces">Vault Enterprise or HCP Vault namespace</a>,
 * set it with the builders' {@code namespace(...)} step. The signer then sends the {@code X-Vault-Namespace} header on
 * <em>both</em> Vault calls — every Transit {@code sign} POST and the fetched mode's one-time {@code transit/keys}
 * read. Without the step no such header is sent at all, which is what Vault OSS (which has no namespaces) expects.
 *
 * <p><b>Key rotation:</b> the fetched mode captures the key version together with its public key at construction and
 * pins that version on every {@code sign} call ({@code key_version} in the request body), so signatures always match
 * the advertised public key — rotating the Transit key in Vault does not break signing <em>by itself</em>. What the pin
 * does not survive is the operator raising the key's {@code min_encryption_version} above the pinned version: Vault
 * then rejects sign requests carrying that {@code key_version}, and every {@code sign} call fails loudly with a
 * {@link PushCryptoException}. Trimming old key versions (raising {@code min_available_version}) deletes the pinned
 * version outright and breaks signing the same way. Recover by recreating the signer (the fetched mode re-reads the
 * then-latest version and its public key) or, in the explicit mode, by supplying the new version's public key with the
 * matching {@code keyVersion}. The rotated key is also not picked up until the signer is recreated, which is the
 * behaviour VAPID wants: the public key is your published identity, and push subscriptions pin it at subscribe time.
 * The explicit mode pins whatever version {@link SuppliedPublicKeyBuilder#keyVersion(int)} was given. Omitting that
 * step sends no {@code key_version}, so Vault signs with the latest — that form is only safe if the Transit key is
 * never rotated; set {@code keyVersion} otherwise.
 */
// GodClass / complexity: the bulk of this class is the anchored JSON reader for Vault's responses
// (see extractSignature). Keeping it here is what keeps the module free of an implementation
// dependency — pulling a
// JSON library in would trade these metrics for a transitive surface the library exists to avoid.
@SuppressWarnings({"PMD.GodClass", "PMD.CyclomaticComplexity", "PMD.CognitiveComplexity"})
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
    /** Cap for response text echoed into exception messages — enough context, log-safe size. */
    private static final int ERROR_ECHO_LIMIT = 2048;

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
    /** The header carrying the Vault token on every Vault call. */
    private static final String TOKEN_HEADER = "X-Vault-Token";
    /** The header addressing a Vault Enterprise/HCP namespace — sent only when {@code namespace(...)} was set. */
    private static final String NAMESPACE_HEADER = "X-Vault-Namespace";

    private final VaultHttpTransport transport;
    private final URI signUri;
    private final String token;
    /** The Vault Enterprise/HCP namespace every call addresses; {@code null} sends no namespace header. */
    @Nullable
    private final String namespace;

    private final byte[] publicKey;
    /** The Transit key version every {@code sign} call pins; {@code null} sends no {@code key_version}. */
    @Nullable
    private final Integer keyVersion;

    /** The (version, public key) pair read atomically from one {@code transit/keys/<name>} response. */
    // ArrayRecordComponent: a private carrier that never escapes this class — the constructor copies
    // the array into the signer's own field, and nothing else ever reads it.
    @SuppressWarnings("ArrayRecordComponent")
    private record VaultKeyMetadata(int version, byte[] publicKey) {}

    /**
     * A builder for the <b>fetched</b> mode: {@link FetchedPublicKeyBuilder#build()} reads {@code transit/keys/<key>}
     * from Vault, so it performs I/O and can fail with a {@link PushCryptoException}. It has no {@code keyVersion} step
     * — the version comes from Vault together with the public key it belongs to, as one atomic pair.
     *
     * @param address the Vault base address, e.g. {@code https://vault.example:8200}
     * @param keyName the {@code ecdsa-p256} Transit key name
     * @param token the Vault token authorising {@code sign} on the key plus {@code read} on {@code transit/keys/<key>}
     *     (this mode reads the key metadata)
     * @return a new builder
     */
    public static FetchedPublicKeyBuilder builderWithFetchedPublicKey(
            URI address, TransitKeyName keyName, VaultToken token) {
        return new FetchedPublicKeyBuilder(address, keyName, token);
    }

    /**
     * A builder for the <b>explicit</b> mode: the caller supplies the published VAPID public key, and
     * {@link SuppliedPublicKeyBuilder#build()} contacts nothing. The Vault token then needs only {@code sign}.
     *
     * @param address the Vault base address, e.g. {@code https://vault.example:8200}
     * @param keyName the {@code ecdsa-p256} Transit key name
     * @param token the Vault token authorising {@code sign} on the key — this mode never reads the key metadata, so a
     *     sign-only token is enough
     * @param publicKey the VAPID public key — a 65-byte X9.62 uncompressed P-256 point
     * @return a new builder
     * @throws IllegalArgumentException if {@code publicKey} is not a 65-byte uncompressed point
     */
    public static SuppliedPublicKeyBuilder builderWithSuppliedPublicKey(
            URI address, TransitKeyName keyName, VaultToken token, byte[] publicKey) {
        return new SuppliedPublicKeyBuilder(address, keyName, token, publicKey);
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
        if (publicKey.length != UNCOMPRESSED_LENGTH || publicKey[0] != UNCOMPRESSED_TAG) {
            throw new IllegalArgumentException("publicKey must be a 65-byte uncompressed P-256 point (0x04 prefix)");
        }
        if (keyVersion != null && keyVersion < 1) {
            throw new IllegalArgumentException("keyVersion must be >= 1, got " + keyVersion);
        }
        this.signUri = vaultAddress.resolve("/v1/" + mount + "/sign/" + keyName.value());
        // Unwrapped once, here: a VaultToken is valid by construction (visible ASCII, hence
        // header-safe), so nothing downstream re-validates it — and the raw String never
        // reaches any toString() or exception message.
        this.token = Objects.requireNonNull(token, "token").value();
        // Validated at the namespace(...) step that set it (allowed set [A-Za-z0-9_.-] plus '/'),
        // so by construction the value is visible ASCII and header-safe — see requireValidVaultPath.
        this.namespace = namespace;
        this.publicKey = publicKey.clone();
        this.keyVersion = keyVersion;
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        String request = "{\"input\":\"" + Base64.getEncoder().encodeToString(signingInput)
                + "\",\"marshaling_algorithm\":\"jws\""
                + (keyVersion == null ? "" : ",\"key_version\":" + keyVersion) + "}";
        VaultHttpResponse response =
                transport.post(signUri, vaultHeaders(token, namespace), request.getBytes(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            throw new PushCryptoException(
                    "Vault Transit sign failed: HTTP " + response.statusCode() + " — " + abbreviated(response.body()));
        }
        String marshalled = extractSignature(response.body());
        byte[] signature;
        try {
            signature = Base64.getUrlDecoder().decode(stripVaultPrefix(marshalled));
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
        return publicKey.clone();
    }

    /**
     * Read the latest key version and <em>that version's</em> public key from {@code transit/keys/<keyName>} as one
     * atomic pair, reducing the key to the 65-byte uncompressed P-256 point. Taking both from a single response closes
     * the rotation race: even if the key is rotated right after this read, the signer keeps signing with the version
     * its advertised public key belongs to. A single startup {@code GET} over the same {@link VaultHttpTransport} the
     * {@code sign} calls use; the token needs {@code read} on the key.
     *
     * <p>The key is validated as P-256 before the signer exists, all fail-fast: the Transit {@code type}
     * ({@link #requireP256KeyType}), then the key's domain parameters and its point ({@link #requireP256PublicKey}). No
     * check subsumes another — the metadata is only Vault's claim, right parameters do not put the point on the curve,
     * and a key on another curve would otherwise be squeezed into 32-byte coordinates and published as a nonsense VAPID
     * key that fails much later, as an opaque push-service rejection.
     */
    private static VaultKeyMetadata fetchKeyMetadata(
            URI vaultAddress,
            String mount,
            @Nullable String namespace,
            TransitKeyName keyName,
            VaultToken token,
            VaultHttpTransport transport) {
        Objects.requireNonNull(vaultAddress, "vaultAddress");
        Objects.requireNonNull(mount, "mount");
        Objects.requireNonNull(keyName, "keyName");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(transport, "transport");
        URI keyUri = vaultAddress.resolve("/v1/" + mount + "/keys/" + keyName.value());
        // No token or namespace validation here: a VaultToken is valid by construction (visible
        // ASCII, hence header-safe), and the namespace was validated at the namespace(...) step
        // that set it — so this call, which in the fetched mode runs before the canonical
        // constructor, cannot offer an invalid value to the transport.
        VaultHttpResponse response = transport.get(keyUri, vaultHeaders(token.value(), namespace));
        if (response.statusCode() != 200) {
            throw new PushCryptoException("Vault Transit key read failed: HTTP " + response.statusCode() + " — "
                    + abbreviated(response.body()));
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
            throw new PushCryptoException("Vault Transit key type is '" + abbreviated(type) + "', but VAPID requires '"
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
     * {@link ECFieldFp}. Coordinates are public key material, but the message quotes none of it — the failure is
     * structural, and there is nothing an operator can do with the digits.
     */
    private static void requireOnCurve(ECPoint point, ECParameterSpec parameters) {
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

    /** The canonical NIST P-256 domain parameters, resolved from the platform JCE providers. */
    private static ECParameterSpec p256Parameters() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC);
            parameters.init(new ECGenParameterSpec(SECP256R1));
            return parameters.getParameterSpec(ECParameterSpec.class);
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
    private static String describe(ECParameterSpec parameters, ECParameterSpec expected) {
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
            throw new PushCryptoException("Vault response has no 'signature' field: " + abbreviated(json));
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
            throw new PushCryptoException("Vault key response has no 'latest_version' field: " + abbreviated(json));
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
                    "malformed Vault 'latest_version' field — expected a whole number: " + abbreviated(json));
        }
        // Bounded BEFORE Integer.parseInt sees it: parseInt's NumberFormatException carries the
        // ENTIRE digit run in its message, and attaching that as a cause would put a run as long
        // as the response body into every logged stack trace — defeating ERROR_ECHO_LIMIT. The
        // nine-digit bound is deliberately tighter than the int boundary (some ten-digit runs
        // still fit an int): no plausible Transit version comes near either limit, and nine
        // ASCII digits (at most 999,999,999) are guaranteed to parse, so the catch is gone.
        if (end - start > 9) {
            throw new PushCryptoException(
                    "malformed Vault 'latest_version' field — implausibly long number: " + abbreviated(json));
        }
        int version = Integer.parseInt(json.substring(start, end));
        if (version < 1) {
            // Transit numbers key versions from 1; a 0 would be pinned into every sign request and
            // rejected by Vault on each send, far from the response that caused it.
            throw new PushCryptoException("Vault reported key version " + version
                    + ", but Transit key versions start at 1: " + abbreviated(json));
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
                    + "confirmed as '" + REQUIRED_KEY_TYPE + "': " + abbreviated(json));
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
                    "Vault key response has no entry for key version " + version + ": " + abbreviated(json));
        }
        int versionOpen = versionValue;
        while (versionOpen < json.length() && Character.isWhitespace(json.charAt(versionOpen))) {
            versionOpen++;
        }
        if (versionOpen >= json.length() || json.charAt(versionOpen) != '{') {
            throw new PushCryptoException(
                    "Vault key response entry for key version " + version + " is not an object: " + abbreviated(json));
        }
        String versionObject = json.substring(versionOpen, matchingCloseBrace(json, versionOpen) + 1);

        int pemStart = directMemberValueStart(versionObject, 0, "public_key");
        if (pemStart < 0) {
            throw new PushCryptoException(
                    "Vault key response has no 'public_key' for key version " + version + ": " + abbreviated(json));
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
            throw new PushCryptoException("Vault response is not a JSON object: " + abbreviated(json));
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
            throw new PushCryptoException("Vault key response has no '" + name + "' object: " + abbreviated(json));
        }
        int cursor = valueStart;
        while (cursor < json.length() && Character.isWhitespace(json.charAt(cursor))) {
            cursor++;
        }
        if (cursor >= json.length() || json.charAt(cursor) != '{') {
            throw new PushCryptoException("Vault key response '" + name + "' is not an object: " + abbreviated(json));
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
            throw new PushCryptoException("malformed Vault '" + fieldName + "' field: " + abbreviated(json));
        }
        int close = open + 1;
        while (close < json.length() && json.charAt(close) != '"') {
            close += json.charAt(close) == '\\' ? 2 : 1;
        }
        if (close >= json.length()) {
            throw new PushCryptoException("malformed Vault '" + fieldName + "' field: " + abbreviated(json));
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
        throw new PushCryptoException("malformed Vault key response: unterminated object: " + abbreviated(json));
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
     * {@link #requireP256PublicKey}: the fixed 32-byte coordinate fields are P-256's field size, and a coordinate from
     * a larger curve is rejected rather than truncated.
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
     * Response text as echoed into exception messages, truncated to {@link #ERROR_ECHO_LIMIT} characters with an
     * explicit marker. The default transport caps responses at 1 MiB, but a megabyte — or whatever a custom
     * {@link VaultHttpTransport} lets through, where the cap holds only by contract — is far too heavy for a log line.
     */
    private static String abbreviated(String text) {
        if (text.length() <= ERROR_ECHO_LIMIT) {
            return text;
        }
        return text.substring(0, ERROR_ECHO_LIMIT) + "... [truncated, " + text.length() + " chars total]";
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
     * mismatch message carries only the two version numbers ({@link #abbreviated} keeps a nonsense digit run log-safe).
     */
    private String stripVaultPrefix(String marshalled) {
        Matcher signature = VAULT_SIGNATURE.matcher(marshalled);
        if (!signature.matches()) {
            throw new PushCryptoException("unexpected Vault signature format: expected 'vault:v<version>:<base64url>'");
        }
        if (keyVersion != null && !signature.group(1).equals(Integer.toString(keyVersion))) {
            throw new PushCryptoException("Vault Transit signed with key version " + abbreviated(signature.group(1))
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
     * <p>A <em>namespace</em> travels differently — in the {@code X-Vault-Namespace} HTTP header, not the URL — and the
     * same rule still holds on both of that route's counts. First, Vault prepends the header's value to the request
     * path before routing ({@code namespace.Canonicalize}), so a {@code ..} or percent-encoded segment in it steers the
     * request between namespaces exactly the way a mount segment steers it between mounts. Second, a header value must
     * be header-safe: the allowed set is a strict subset of visible ASCII with no CR/LF or any other control character,
     * so a validated value cannot terminate the header or inject another one — and no transport is handed a value whose
     * safety it would otherwise have to enforce itself.
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
    private static String requireValidVaultPath(String value, String name, String nestedExample) {
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
                        + " segment — a nested " + name + " is written like \"" + nestedExample + "\"");
            }
            if (".".equals(segment) || "..".equals(segment)) {
                throw new IllegalArgumentException(name + " must not contain a '" + segment + "' segment — a"
                        + " normalizing proxy in front of Vault collapses it before Vault sees it, and Vault's own"
                        + " handler answers the decoded form with a 307 redirect to the collapsed path, which a"
                        + " redirect-following transport would re-send, X-Vault-Token header included, to a"
                        + " different Vault path");
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
     * {@code X-Vault-Namespace} header is sent) and {@link #transport(VaultHttpTransport)} to a fresh
     * {@link JdkVaultHttpTransport}. There is deliberately no {@code keyVersion} step: this mode takes the version from
     * the same {@code transit/keys/<key>} response as the public key, which is what keeps the two in step.
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

        private FetchedPublicKeyBuilder(URI address, TransitKeyName keyName, VaultToken token) {
            this.address = Objects.requireNonNull(address, "address");
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
            this.mount = requireValidVaultPath(mount, "mount", "secrets/transit");
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
            this.namespace = requireValidVaultPath(namespace, "namespace", "team-a/sub");
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
         * Reads {@code transit/keys/<keyName>} once, then builds the signer pinned to the version that response
         * advertised as latest.
         *
         * @return the signer
         * @throws PushCryptoException if the key read fails or the key is not a usable P-256 key
         */
        public VaultTransitVapidSigner build() {
            VaultHttpTransport resolvedTransport = orDefaultTransport(transport);
            VaultKeyMetadata metadata = fetchKeyMetadata(address, mount, namespace, keyName, token, resolvedTransport);
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
     * Builds a signer in the <b>explicit</b> mode, from a public key the caller already holds — hence the name.
     * Obtained from {@link VaultTransitVapidSigner#builderWithSuppliedPublicKey(URI, TransitKeyName, VaultToken,
     * byte[])}, which takes everything required — this builder holds only the optional steps, so {@code build()} can
     * never refuse over a missing value.
     *
     * <p>{@link #mount(String)} defaults to {@code "transit"}, {@link #namespace(String)} to none (no
     * {@code X-Vault-Namespace} header is sent), {@link #transport(VaultHttpTransport)} to a fresh
     * {@link JdkVaultHttpTransport}, and {@link #keyVersion(int)} is optional but strongly recommended — see its own
     * documentation. {@link #build()} makes no Vault call.
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

        // The key is copied at the factory method, not only in the constructor the builder
        // eventually calls: otherwise the caller's array stays live for as long as the builder
        // does, and a mutation between builderWithSuppliedPublicKey(...) and build() would change
        // the advertised key. Its shape is also checked here, so an invalid key fails at the
        // factory call that supplied it (the canonical constructor re-checks the same invariant
        // for the fetched mode's array).
        private SuppliedPublicKeyBuilder(URI address, TransitKeyName keyName, VaultToken token, byte[] publicKey) {
            this.address = Objects.requireNonNull(address, "address");
            this.keyName = Objects.requireNonNull(keyName, "keyName");
            this.token = Objects.requireNonNull(token, "token");
            Objects.requireNonNull(publicKey, "publicKey");
            if (publicKey.length != UNCOMPRESSED_LENGTH || publicKey[0] != UNCOMPRESSED_TAG) {
                throw new IllegalArgumentException(
                        "publicKey must be a 65-byte uncompressed P-256 point (0x04 prefix)");
            }
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
            this.mount = requireValidVaultPath(mount, "mount", "secrets/transit");
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
            this.namespace = requireValidVaultPath(namespace, "namespace", "team-a/sub");
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
         * Builds the signer. Contacts nothing.
         *
         * @return the signer
         */
        public VaultTransitVapidSigner build() {
            return new VaultTransitVapidSigner(
                    address, mount, namespace, keyName, token, keyVersion, publicKey, orDefaultTransport(transport));
        }
    }
}
