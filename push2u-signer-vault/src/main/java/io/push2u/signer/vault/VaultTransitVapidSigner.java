package io.push2u.signer.vault;

import io.push2u.PushCryptoException;
import io.push2u.VapidSigner;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link VapidSigner} that signs the VAPID JWT via HashiCorp Vault Transit — the private key
 * never leaves Vault. It POSTs the signing input to
 * {@code {vaultAddress}/v1/{mount}/sign/{keyName}} with {@code marshaling_algorithm=jws}, so
 * Vault returns the raw {@code r || s} pair JOSE wants, and decodes it.
 *
 * <p>The Vault key must be an {@code ecdsa-p256} Transit key. The VAPID public key is your published
 * identity; Vault holds only the private half. There are two ways to supply the public key:
 * <ul>
 *   <li><b>Explicit</b> — pass the 65-byte X9.62 uncompressed point. The Vault token then needs only
 *       the {@code sign} capability ({@code update} on {@code transit/sign/<key>}); the public key is
 *       never read from Vault. Use this for a strict sign-only token or an air-gapped public key.</li>
 *   <li><b>Fetched</b> — omit the public key. The signer reads {@code transit/keys/<key>} once at
 *       construction (a {@code GET}), takes the {@code latest_version} and <em>that version's</em>
 *       public key as an atomic pair, and reduces the PEM to the uncompressed point. This keeps a
 *       <em>single source of truth</em> — the Transit key — so the published key can never drift
 *       from the signing key. The token additionally needs {@code read} on
 *       {@code transit/keys/<key>} (which exposes only the public keys + metadata, never private
 *       material). This is the recommended mode.</li>
 * </ul>
 *
 * <p>Both Vault calls — the Transit {@code sign} POST and the fetched mode's one-time
 * {@code transit/keys} read — go through this module's {@link VaultHttpTransport} seam (default
 * {@link JdkVaultHttpTransport}), so an application's mTLS, proxy, or observability transport
 * applies to the startup metadata read as much as to signing. Deliberately <em>not</em>
 * push2u-core's {@code PushHttpClient}: push delivery talks to untrusted capability URLs and
 * discards response bodies, while Vault's responses must be read — buffered under the transport's
 * size cap and per-request timeout. The small Vault request/response JSON is built and parsed by
 * hand — no JSON library.
 *
 * <p><b>Key rotation:</b> the fetched mode captures the key version together with its public key at
 * construction and pins that version on every {@code sign} call ({@code key_version} in the request
 * body), so signatures always match the advertised public key — rotating the Transit key in Vault
 * does not break signing <em>by itself</em>. What the pin does not survive is the operator raising
 * the key's {@code min_encryption_version} above the pinned version: Vault then rejects sign
 * requests carrying that {@code key_version}, and every {@code sign} call fails loudly with a
 * {@link PushCryptoException}. Trimming old key versions (raising {@code min_available_version})
 * deletes the pinned version outright and breaks signing the same way. Recover by recreating the
 * signer (the fetched mode re-reads the
 * then-latest version and its public key) or, in the explicit mode, by supplying the new version's
 * public key with the matching {@code keyVersion}. The rotated key is also not picked up until the
 * signer is recreated, which is the behaviour VAPID wants: the public key is your published
 * identity, and push subscriptions pin it at subscribe time. The explicit mode pins whatever
 * version is passed to the constructor. The explicit overloads <em>without</em> a version send no
 * {@code key_version}, so Vault signs with the latest — that form is only safe if the Transit key
 * is never rotated; prefer the {@code keyVersion} overloads otherwise.
 */
public final class VaultTransitVapidSigner implements VapidSigner {

    private static final String VAULT_PREFIX_END = ":";
    private static final int UNCOMPRESSED_LENGTH = 65;
    private static final int COORDINATE_LENGTH = 32;
    private static final byte UNCOMPRESSED_TAG = 0x04;
    /** An ES256 signature is exactly {@code r || s}, two 32-byte big-endian scalars. */
    private static final int SIGNATURE_LENGTH = 2 * COORDINATE_LENGTH;

    private final VaultHttpTransport transport;
    private final URI signUri;
    private final String token;
    private final byte[] publicKey;
    /** The Transit key version every {@code sign} call pins; {@code null} sends no {@code key_version}. */
    private final Integer keyVersion;

    /** The (version, public key) pair read atomically from one {@code transit/keys/<name>} response. */
    private record VaultKeyMetadata(int version, byte[] publicKey) {
    }

    /**
     * Fetched mode with the default {@link JdkVaultHttpTransport} — reads the latest key
     * version and its public key from {@code transit/keys/<keyName>} at construction and pins that
     * version for signing.
     *
     * @param vaultAddress the Vault base address, e.g. {@code https://vault.example:8200}
     * @param mount        the Transit mount path (commonly {@code "transit"})
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} + {@code read} on the key
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token) {
        this(vaultAddress, mount, keyName, token, new JdkVaultHttpTransport());
    }

    /**
     * Fetched mode with the given transport, used for <em>both</em> Vault calls — the construction
     * time {@code transit/keys/<keyName>} read and every {@code sign} — so custom mTLS/proxy
     * configuration is never bypassed. Reads the latest key version and its public key at
     * construction and pins that version for signing.
     *
     * @param vaultAddress the Vault base address
     * @param mount        the Transit mount path
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} + {@code read} on the key
     * @param transport    the HTTP transport for the Vault API calls
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token,
                                   VaultHttpTransport transport) {
        this(vaultAddress, mount, keyName, token,
            fetchKeyMetadata(vaultAddress, mount, keyName, token, transport), transport);
    }

    private VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token,
                                    VaultKeyMetadata metadata, VaultHttpTransport transport) {
        this(vaultAddress, mount, keyName, token, metadata.version(), metadata.publicKey(), transport);
    }

    /**
     * Explicit mode with the default {@link JdkVaultHttpTransport} and <b>no pinned key
     * version</b>: every {@code sign} request lets Vault use the key's latest version. This form is
     * incompatible with key rotation — after a rotation Vault signs with the new private key while
     * this signer keeps advertising the supplied public key, and push services reject the mismatch.
     * Either never rotate the Transit key, or use the overload that takes a {@code keyVersion}.
     *
     * @param vaultAddress the Vault base address
     * @param mount        the Transit mount path
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} on the key
     * @param publicKey    the VAPID public key — a 65-byte X9.62 uncompressed P-256 point
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token, byte[] publicKey) {
        this(vaultAddress, mount, keyName, token, publicKey, new JdkVaultHttpTransport());
    }

    /**
     * Explicit mode with the given transport and <b>no pinned key version</b>: every {@code sign}
     * request lets Vault use the key's latest version. This form is incompatible with key rotation —
     * after a rotation Vault signs with the new private key while this signer keeps advertising the
     * supplied public key, and push services reject the mismatch. Either never rotate the Transit
     * key, or use the overload that takes a {@code keyVersion}.
     *
     * @param vaultAddress the Vault base address
     * @param mount        the Transit mount path
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} on the key
     * @param publicKey    the VAPID public key — a 65-byte X9.62 uncompressed P-256 point
     * @param transport    the HTTP transport for the Vault API calls
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token, byte[] publicKey,
                                   VaultHttpTransport transport) {
        this(vaultAddress, mount, keyName, token, (Integer) null, publicKey, transport);
    }

    /**
     * Explicit mode with the default {@link JdkVaultHttpTransport}, pinning {@code keyVersion}
     * on every {@code sign} request — the supplied public key must be that version's public half.
     * Rotating the Transit key does not affect this signer, but raising the key's
     * {@code min_encryption_version} above {@code keyVersion} makes Vault reject its sign requests
     * (see the key-rotation notes on the class).
     *
     * @param vaultAddress the Vault base address
     * @param mount        the Transit mount path
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} on the key
     * @param publicKey    the VAPID public key — a 65-byte X9.62 uncompressed P-256 point
     * @param keyVersion   the Transit key version {@code publicKey} belongs to (>= 1)
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token, byte[] publicKey,
                                   int keyVersion) {
        this(vaultAddress, mount, keyName, token, publicKey, keyVersion, new JdkVaultHttpTransport());
    }

    /**
     * Explicit mode with the given transport, pinning {@code keyVersion} on every {@code sign}
     * request — the supplied public key must be that version's public half. Rotating the Transit key
     * does not affect this signer, but raising the key's {@code min_encryption_version} above
     * {@code keyVersion} makes Vault reject its sign requests (see the key-rotation notes on the
     * class).
     *
     * @param vaultAddress the Vault base address
     * @param mount        the Transit mount path
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} on the key
     * @param publicKey    the VAPID public key — a 65-byte X9.62 uncompressed P-256 point
     * @param keyVersion   the Transit key version {@code publicKey} belongs to (>= 1)
     * @param transport    the HTTP transport for the Vault API calls
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token, byte[] publicKey,
                                   int keyVersion, VaultHttpTransport transport) {
        this(vaultAddress, mount, keyName, token, Integer.valueOf(keyVersion), publicKey, transport);
    }

    private VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token, Integer keyVersion,
                                    byte[] publicKey, VaultHttpTransport transport) {
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
        this.signUri = vaultAddress.resolve("/v1/" + mount + "/sign/" + keyName);
        this.token = Objects.requireNonNull(token, "token");
        this.publicKey = publicKey.clone();
        this.keyVersion = keyVersion;
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        String request = "{\"input\":\"" + Base64.getEncoder().encodeToString(signingInput)
            + "\",\"marshaling_algorithm\":\"jws\""
            + (keyVersion == null ? "" : ",\"key_version\":" + keyVersion) + "}";
        VaultHttpResponse response = transport.post(
            signUri, Map.of("X-Vault-Token", token), request.getBytes(StandardCharsets.UTF_8));
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
     * Read the latest key version and <em>that version's</em> public key from
     * {@code transit/keys/<keyName>} as one atomic pair, reducing the key to the 65-byte
     * uncompressed P-256 point. Taking both from a single response closes the rotation race: even if
     * the key is rotated right after this read, the signer keeps signing with the version its
     * advertised public key belongs to. A single startup {@code GET} over the same
     * {@link VaultHttpTransport} the {@code sign} calls use; the token needs {@code read} on the key.
     */
    private static VaultKeyMetadata fetchKeyMetadata(URI vaultAddress, String mount, String keyName, String token,
                                                     VaultHttpTransport transport) {
        Objects.requireNonNull(vaultAddress, "vaultAddress");
        Objects.requireNonNull(mount, "mount");
        Objects.requireNonNull(keyName, "keyName");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(transport, "transport");
        URI keyUri = vaultAddress.resolve("/v1/" + mount + "/keys/" + keyName);
        VaultHttpResponse response = transport.get(keyUri, Map.of("X-Vault-Token", token));
        if (response.statusCode() != 200) {
            throw new PushCryptoException(
                "Vault Transit key read failed: HTTP " + response.statusCode() + " — " + abbreviated(response.body()));
        }
        String body = response.body();
        int latestVersion = extractLatestVersion(body);
        try {
            byte[] point = uncompressedPoint(parsePublicKeyPem(extractPublicKeyPem(body, latestVersion)));
            return new VaultKeyMetadata(latestVersion, point);
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("Vault Transit returned an unparseable public key", e);
        }
    }

    /**
     * Pull the {@code signature} value out of Vault's {@code {"data":{"signature":"vault:v1:..."}}}
     * response, anchored the whole way: {@code data} as a direct member of the root object,
     * {@code signature} as a direct member of {@code data} — a string value that merely looks like
     * one of those labels can never hijack the lookup. Targeted extraction (fixed Vault response
     * shape), not a general JSON parser.
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
     * Pull the integer {@code latest_version} out of {@code transit/keys/<name>}, anchored the whole
     * way: {@code data} as a direct member of the root object, {@code latest_version} as a direct
     * member of {@code data} — a string value that merely looks like the label can never hijack the
     * lookup. Targeted extraction (fixed Vault response shape), not a general JSON parser.
     * Package-private for the extraction unit tests.
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
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        if (end == start) {
            throw new PushCryptoException("malformed Vault 'latest_version' field: " + abbreviated(json));
        }
        return Integer.parseInt(json.substring(start, end));
    }

    /**
     * Pull the {@code public_key} PEM of the given key version out of {@code transit/keys/<name>}.
     * The whole chain is anchored, one direct-member hop at a time: root object → {@code data} →
     * {@code keys} → the version entry → {@code public_key} inside that entry's own {@code {...}}.
     * No lookup ever scans the response at large, so neither a string value that looks like a label
     * (e.g. {@code "alias":"keys"}) nor a lookalike entry nested deeper or elsewhere can hijack the
     * extraction — the failure mode is always a loud {@link PushCryptoException}, never another
     * object's key. Whitespace between tokens is tolerated (valid JSON may be pretty-printed). The
     * PEM's {@code \n} are escaped in the JSON. Targeted extraction (fixed Vault response shape),
     * not a general JSON parser. Package-private for the extraction unit tests.
     */
    static String extractPublicKeyPem(String json, int version) {
        int dataOpen = directMemberObjectStart(json, rootObjectStart(json), "data");
        int keysOpen = directMemberObjectStart(json, dataOpen, "keys");

        int versionValue = directMemberValueStart(json, keysOpen, Integer.toString(version));
        if (versionValue < 0) {
            throw new PushCryptoException("Vault key response has no entry for key version " + version + ": " + abbreviated(json));
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
     * The opening-brace index of the object-valued direct member {@code name} of the object opening
     * at {@code objectOpen}. A missing member or a non-object value (e.g. {@code "keys":null}) fails
     * loudly instead of letting the caller bind to some stray brace later in the response.
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
     * {@code objectOpen}, or {@code -1} if the object has no such member. Walks the object tracking
     * nesting depth and string state (honouring backslash escapes), so a lookalike nested inside a
     * member's value — or sitting past the object's closing brace — never matches; a quoted token
     * not followed by a colon (i.e. a string <em>value</em> that merely equals the member name, as
     * in {@code "alias":"keys"}) is skipped whole. Whitespace before the colon is tolerated.
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
     * The content of the JSON string value at {@code valueStart} (the index just past a member's
     * colon; leading whitespace tolerated), without unescaping. Escaped characters inside the value
     * are skipped when locating the terminating quote; a non-string or unterminated value fails
     * loudly.
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
     * The index of the closing brace matching the opening brace at {@code openBrace}, skipping
     * nested objects and brace characters inside JSON strings (honouring backslash escapes).
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

    private static ECPublicKey parsePublicKeyPem(String pem) throws GeneralSecurityException {
        String base64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    /** Encode a P-256 public key as its 65-byte X9.62 uncompressed point ({@code 0x04 || X || Y}). */
    private static byte[] uncompressedPoint(ECPublicKey key) {
        byte[] out = new byte[UNCOMPRESSED_LENGTH];
        out[0] = UNCOMPRESSED_TAG;
        writeFixed(key.getW().getAffineX(), out, 1);
        writeFixed(key.getW().getAffineY(), out, 1 + COORDINATE_LENGTH);
        return out;
    }

    /** Write {@code value} as a fixed 32-byte big-endian field at {@code offset} (right-aligned). */
    private static void writeFixed(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        if (bytes.length >= COORDINATE_LENGTH) {
            System.arraycopy(bytes, bytes.length - COORDINATE_LENGTH, out, offset, COORDINATE_LENGTH);
        } else {
            System.arraycopy(bytes, 0, out, offset + COORDINATE_LENGTH - bytes.length, bytes.length);
        }
    }

    /** Cap for response text echoed into exception messages — enough context, log-safe size. */
    private static final int ERROR_ECHO_LIMIT = 2048;

    /**
     * Response text as echoed into exception messages, truncated to {@link #ERROR_ECHO_LIMIT}
     * characters with an explicit marker. The default transport caps responses at 1 MiB, but a
     * megabyte — or whatever a custom {@link VaultHttpTransport} lets through, where the cap holds
     * only by contract — is far too heavy for a log line.
     */
    private static String abbreviated(String text) {
        if (text.length() <= ERROR_ECHO_LIMIT) {
            return text;
        }
        return text.substring(0, ERROR_ECHO_LIMIT) + "... [truncated, " + text.length() + " chars total]";
    }

    /** {@code vault:v1:<base64url>} → {@code <base64url>}. */
    private static String stripVaultPrefix(String marshalled) {
        int marker = marshalled.lastIndexOf(VAULT_PREFIX_END);
        if (marker < 0) {
            throw new PushCryptoException("unexpected Vault signature format: " + abbreviated(marshalled));
        }
        return marshalled.substring(marker + 1);
    }
}
