package io.push2u.signer.vault;

import io.push2u.JdkHttpPushClient;
import io.push2u.PushCryptoException;
import io.push2u.PushHttpClient;
import io.push2u.PushResponse;
import io.push2u.VapidSigner;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link VapidSigner} that signs the VAPID JWT via HashiCorp Vault Transit — the private key
 * never leaves Vault (DESIGN.md ADR-010). It POSTs the signing input to
 * {@code {vaultAddress}/v1/{mount}/sign/{keyName}} with {@code marshaling_algorithm=jws}, so
 * Vault returns the raw {@code r || s} pair JOSE wants, and decodes it.
 *
 * <p>The Vault key must be an {@code ecdsa-p256} Transit key. The VAPID public key is your published
 * identity; Vault holds only the private half. There are two ways to supply the public key:
 * <ul>
 *   <li><b>Explicit</b> — pass the 65-byte X9.62 uncompressed point. The Vault token then needs only
 *       the {@code sign} capability ({@code update} on {@code transit/sign/<key>}); the public key is
 *       never read from Vault. Use this for a strict sign-only token or an air-gapped public key.</li>
 *   <li><b>Fetched</b> — omit the public key. The signer reads it once at construction from
 *       {@code transit/keys/<key>} (a {@code GET}) and reduces the returned PEM to the uncompressed
 *       point. This keeps a <em>single source of truth</em> — the Transit key — so the published key
 *       can never drift from the signing key. The token additionally needs {@code read} on
 *       {@code transit/keys/<key>} (which exposes only the public key + metadata, never private
 *       material). This is the recommended mode.</li>
 * </ul>
 *
 * <p>The signing round-trip goes through push2u-core's {@link PushHttpClient} seam (default
 * {@link JdkHttpPushClient}), so an alternate transport adapter swaps the client for both push
 * delivery and the Vault {@code sign} calls. The one-time {@code transit/keys} read in the fetched
 * mode uses the JDK {@link HttpClient} directly — {@link PushHttpClient} is POST-only and the read is
 * a single startup call off the hot path. The small Vault request/response JSON is built and parsed
 * by hand — no JSON library.
 *
 * <p><b>Key rotation:</b> the fetched mode reads the public key Vault returns for the key, matching
 * the version {@code transit/sign} signs with by default (the latest), so a single-version key is
 * always self-consistent. Pinning a specific version on both {@code sign} and the read — the full
 * VAPID rotation lifecycle — is a separate concern (subscriptions pin the public key at subscribe
 * time) and is not handled here.
 */
public final class VaultTransitVapidSigner implements VapidSigner {

    private static final String VAULT_PREFIX_END = ":";
    private static final int UNCOMPRESSED_LENGTH = 65;
    private static final int COORDINATE_LENGTH = 32;
    private static final byte UNCOMPRESSED_TAG = 0x04;

    private final PushHttpClient httpClient;
    private final URI signUri;
    private final String token;
    private final byte[] publicKey;

    /**
     * Fetched mode with the default {@link JdkHttpPushClient} transport — reads the public key from
     * {@code transit/keys/<keyName>} at construction.
     *
     * @param vaultAddress the Vault base address, e.g. {@code https://vault.example:8200}
     * @param mount        the Transit mount path (commonly {@code "transit"})
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} + {@code read} on the key
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token) {
        this(vaultAddress, mount, keyName, token, new JdkHttpPushClient());
    }

    /**
     * Fetched mode with the given transport for the {@code sign} calls — reads the public key from
     * {@code transit/keys/<keyName>} at construction (via the JDK HTTP client, see the class doc).
     *
     * @param vaultAddress the Vault base address
     * @param mount        the Transit mount path
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} + {@code read} on the key
     * @param httpClient   the HTTP transport for the {@code sign} round-trip
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token,
                                   PushHttpClient httpClient) {
        this(vaultAddress, mount, keyName, token,
            fetchPublicKey(vaultAddress, mount, keyName, token), httpClient);
    }

    /**
     * Explicit mode with the default {@link JdkHttpPushClient} transport.
     *
     * @param vaultAddress the Vault base address
     * @param mount        the Transit mount path
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} on the key
     * @param publicKey    the VAPID public key — a 65-byte X9.62 uncompressed P-256 point
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token, byte[] publicKey) {
        this(vaultAddress, mount, keyName, token, publicKey, new JdkHttpPushClient());
    }

    /**
     * Explicit mode with the given transport.
     *
     * @param vaultAddress the Vault base address
     * @param mount        the Transit mount path
     * @param keyName      the {@code ecdsa-p256} Transit key name
     * @param token        the Vault token authorising {@code sign} on the key
     * @param publicKey    the VAPID public key — a 65-byte X9.62 uncompressed P-256 point
     * @param httpClient   the HTTP transport to reach Vault with
     */
    public VaultTransitVapidSigner(URI vaultAddress, String mount, String keyName, String token, byte[] publicKey,
                                   PushHttpClient httpClient) {
        Objects.requireNonNull(vaultAddress, "vaultAddress");
        Objects.requireNonNull(mount, "mount");
        Objects.requireNonNull(keyName, "keyName");
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length != UNCOMPRESSED_LENGTH || publicKey[0] != UNCOMPRESSED_TAG) {
            throw new IllegalArgumentException("publicKey must be a 65-byte uncompressed P-256 point (0x04 prefix)");
        }
        this.signUri = vaultAddress.resolve("/v1/" + mount + "/sign/" + keyName);
        this.token = Objects.requireNonNull(token, "token");
        this.publicKey = publicKey.clone();
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        String request = "{\"input\":\"" + Base64.getEncoder().encodeToString(signingInput)
            + "\",\"marshaling_algorithm\":\"jws\"}";
        PushResponse response = httpClient.post(
            signUri, Map.of("X-Vault-Token", token), request.getBytes(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            throw new PushCryptoException(
                "Vault Transit sign failed: HTTP " + response.statusCode() + " — " + response.body());
        }
        String marshalled = extractSignature(response.body());
        return Base64.getUrlDecoder().decode(stripVaultPrefix(marshalled));
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    /**
     * Read the public key from {@code transit/keys/<keyName>} and reduce it to the 65-byte
     * uncompressed P-256 point. A single startup {@code GET} via the JDK HTTP client (the
     * {@link PushHttpClient} seam is POST-only); the token needs {@code read} on the key.
     */
    private static byte[] fetchPublicKey(URI vaultAddress, String mount, String keyName, String token) {
        Objects.requireNonNull(vaultAddress, "vaultAddress");
        Objects.requireNonNull(mount, "mount");
        Objects.requireNonNull(keyName, "keyName");
        Objects.requireNonNull(token, "token");
        URI keyUri = vaultAddress.resolve("/v1/" + mount + "/keys/" + keyName);
        HttpRequest request = HttpRequest.newBuilder(keyUri)
            .header("X-Vault-Token", token)
            .GET()
            .build();
        try (HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()) {
            HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                throw new PushCryptoException(
                    "Vault Transit key read failed: HTTP " + response.statusCode() + " — " + response.body());
            }
            return uncompressedPoint(parsePublicKeyPem(extractPublicKeyPem(response.body())));
        } catch (IOException e) {
            throw new PushCryptoException("Vault Transit key read failed for " + keyUri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PushCryptoException("Vault Transit key read interrupted", e);
        } catch (GeneralSecurityException e) {
            throw new PushCryptoException("Vault Transit returned an unparseable public key", e);
        }
    }

    /**
     * Pull the {@code signature} value out of Vault's {@code {"data":{"signature":"vault:v1:..."}}}
     * response. Targeted extraction (the value is quote-free base64url with colons), not a general
     * JSON parser — the response shape is fixed by Vault's Transit API.
     */
    private static String extractSignature(String json) {
        int key = json.indexOf("\"signature\"");
        if (key < 0) {
            throw new PushCryptoException("Vault response has no 'signature' field: " + json);
        }
        int colon = json.indexOf(':', key + "\"signature\"".length());
        int open = colon < 0 ? -1 : json.indexOf('"', colon + 1);
        int close = open < 0 ? -1 : json.indexOf('"', open + 1);
        if (close < 0) {
            throw new PushCryptoException("malformed Vault 'signature' field: " + json);
        }
        return json.substring(open + 1, close);
    }

    /**
     * Pull the {@code public_key} PEM out of {@code transit/keys/<name>} — its {@code \n} are escaped
     * in the JSON. Targeted extraction (fixed Vault response shape), not a general JSON parser.
     */
    private static String extractPublicKeyPem(String json) {
        int key = json.indexOf("\"public_key\"");
        if (key < 0) {
            throw new PushCryptoException("Vault key response has no 'public_key' field: " + json);
        }
        int colon = json.indexOf(':', key + "\"public_key\"".length());
        int open = colon < 0 ? -1 : json.indexOf('"', colon + 1);
        int close = open < 0 ? -1 : json.indexOf('"', open + 1);
        if (close < 0) {
            throw new PushCryptoException("malformed Vault 'public_key' field: " + json);
        }
        return json.substring(open + 1, close).replace("\\n", "\n");
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

    /** {@code vault:v1:<base64url>} → {@code <base64url>}. */
    private static String stripVaultPrefix(String marshalled) {
        int marker = marshalled.lastIndexOf(VAULT_PREFIX_END);
        if (marker < 0) {
            throw new PushCryptoException("unexpected Vault signature format: " + marshalled);
        }
        return marshalled.substring(marker + 1);
    }
}
