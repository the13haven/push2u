package io.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.push2u.PushCryptoException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Version-addressed extraction from {@code transit/keys/<name>} response bodies. Synthetic bodies,
 * no Vault: the point is the adversarial layouts a real dev-mode Vault rarely produces — Go-map key
 * ordering where {@code "10"} and {@code "11"} sort between {@code "1"} and {@code "2"}, a version
 * whose object lacks {@code public_key} while a neighbour has one, and lookalike entries outside
 * the {@code keys} object. Every lookup must stay inside the requested version's own object;
 * anything else must fail loudly, never silently return another version's key.
 */
class VaultTransitVapidSignerExtractionTest {

    /**
     * Go maps marshal keys in lexicographic order, so multi-digit versions interleave:
     * "1","10","11","2","21","9". The extraction must address the exact version entry — a substring
     * or first-occurrence search returns version 1's key for almost every request here.
     */
    private static final String GO_MAP_ORDERED_BODY =
        "{\"request_id\":\"11111111-2222-3333-4444-555555555555\",\"data\":{"
            + "\"allow_plaintext_backup\":false,\"deletion_allowed\":false,\"exportable\":false,"
            + "\"keys\":{"
            + entry(1) + "," + entry(10) + "," + entry(11) + "," + entry(2) + "," + entry(21) + "," + entry(9)
            + "},\"latest_version\":21,\"min_decryption_version\":1,\"name\":\"vapid\","
            + "\"supports_signing\":true,\"type\":\"ecdsa-p256\"}}";

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 9, 10, 11, 21})
    void extractsExactlyTheRequestedVersionFromGoMapOrderedKeys(int version) {
        assertThat(VaultTransitVapidSigner.extractPublicKeyPem(GO_MAP_ORDERED_BODY, version))
            .isEqualTo(pem(version));
    }

    @Test
    void latestVersionIsReadAsAWholeInteger() {
        assertThat(VaultTransitVapidSigner.extractLatestVersion(GO_MAP_ORDERED_BODY)).isEqualTo(21);
    }

    @Test
    void versionWithoutPublicKeyFailsInsteadOfReturningANeighbours() {
        // Version 2 has creation_time but no public_key; versions 1 and 3 around it both have one.
        // An unbounded forward search from the "2": label would land on version 3's public_key.
        String body = "{\"data\":{\"keys\":{"
            + entry(1) + ","
            + "\"2\":{\"creation_time\":\"2026-08-01T00:00:00Z\",\"name\":\"P-256\"},"
            + entry(3)
            + "},\"latest_version\":3,\"name\":\"vapid\",\"type\":\"ecdsa-p256\"}}";

        assertThatThrownBy(() -> VaultTransitVapidSigner.extractPublicKeyPem(body, 2))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no 'public_key' for key version 2");
    }

    @Test
    void versionAbsentFromKeysFailsEvenIfALookalikeEntryExistsOutsideKeys() {
        // "7" exists as a key of a sibling object after "keys", complete with a public_key. The
        // version lookup must be bounded to the keys object and fail, not pick up the impostor.
        String body = "{\"data\":{\"keys\":{" + entry(1)
            + "},\"latest_version\":1,\"unrelated\":{" + entry(7) + "},\"name\":\"vapid\"}}";

        assertThatThrownBy(() -> VaultTransitVapidSigner.extractPublicKeyPem(body, 7))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no entry for key version 7");
    }

    @Test
    void missingRequestedVersionFails() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.extractPublicKeyPem(GO_MAP_ORDERED_BODY, 5))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no entry for key version 5");
    }

    @Test
    void nonObjectVersionEntryFails() {
        // Symmetric Transit keys serialise versions as plain creation timestamps, not objects.
        // Such an entry must be rejected, not skipped over into the next version's object.
        String body = "{\"data\":{\"keys\":{\"1\":1754006400," + entry(2)
            + "},\"latest_version\":2,\"name\":\"aes\",\"type\":\"aes256-gcm96\"}}";

        assertThatThrownBy(() -> VaultTransitVapidSigner.extractPublicKeyPem(body, 1))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("key version 1 is not an object");
    }

    @Test
    void nullKeysValueDoesNotBindToAStrayObjectLater() {
        // "keys" is null and a later, unrelated object carries a complete-looking version entry.
        // An unanchored indexOf('{') after "keys": binds to that stray brace and returns its
        // public_key; the value after "keys": must itself be an object, or the extraction fails.
        String body = "{\"data\":{\"keys\":null,\"unrelated\":{" + entry(1)
            + "},\"latest_version\":1,\"name\":\"vapid\",\"type\":\"ecdsa-p256\"}}";

        assertThatThrownBy(() -> VaultTransitVapidSigner.extractPublicKeyPem(body, 1))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("'keys' is not an object");
    }

    @Test
    void versionLabelNestedInsideAMemberValueIsNotADirectEntry() {
        // Version 1's object carries a nested "meta" object whose member is labelled "2" and holds
        // an impostor public_key. The requested version must be a DIRECT member of "keys" — a
        // depth-blind label search finds the nested "2" and returns the impostor.
        String body = "{\"data\":{\"keys\":{"
            + "\"1\":{\"meta\":{\"2\":{\"public_key\":\"IMPOSTOR\"}},"
            + "\"creation_time\":\"2026-08-01T00:00:00Z\",\"name\":\"P-256\","
            + "\"public_key\":\"-----BEGIN PUBLIC KEY-----\\nKEY-V1\\n-----END PUBLIC KEY-----\\n\"}"
            + "},\"latest_version\":1,\"name\":\"vapid\",\"type\":\"ecdsa-p256\"}}";

        assertThatThrownBy(() -> VaultTransitVapidSigner.extractPublicKeyPem(body, 2))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no entry for key version 2");
    }

    @Test
    void stringValueEqualToKeysDoesNotHijackTheLookup() {
        // A member whose string VALUE is "keys", followed by a "meta" object holding an impostor
        // "2" entry — all BEFORE the real keys object. An unanchored search for the "keys" label
        // binds to the string value, takes "meta" as the keys object and returns the impostor. The
        // lookup must bind to the direct member "keys" of data and return the real key.
        String body = "{\"data\":{\"alias\":\"keys\",\"meta\":{\"2\":{\"public_key\":\"IMPOSTOR\"}},"
            + "\"keys\":{" + entry(1) + "," + entry(2)
            + "},\"latest_version\":2,\"name\":\"vapid\",\"type\":\"ecdsa-p256\"}}";

        assertThat(VaultTransitVapidSigner.extractPublicKeyPem(body, 2)).isEqualTo(pem(2));
    }

    @Test
    void stringValueEqualToLatestVersionDoesNotHijackTheLookup() {
        // "note" carries the string value "latest_version" and the member right after it has a
        // numeric value: an unanchored search binds to the string value, takes the next colon and
        // silently reads 9. The real latest_version field says 2.
        String body = "{\"data\":{\"note\":\"latest_version\",\"min_decryption_version\":9,"
            + "\"keys\":{" + entry(1) + "," + entry(2) + "},\"latest_version\":2}}";

        assertThat(VaultTransitVapidSigner.extractLatestVersion(body)).isEqualTo(2);
    }

    @Test
    void whitespaceBetweenStructuralTokensIsTolerated() {
        // Pretty-printed JSON is valid JSON: newlines, tabs and CR between "data"/"keys"/version
        // labels, their colons and their values must not derail the extraction.
        String body = "{\r\n  \"data\" :\n\t{\n  \"keys\" :\r\n{ \"1\" :\t{"
            + "\"creation_time\":\"2026-08-01T00:00:00Z\",\n\"public_key\" :\n"
            + "\"-----BEGIN PUBLIC KEY-----\\nKEY-V1\\n-----END PUBLIC KEY-----\\n\"}\n},"
            + "\r\n  \"latest_version\" :\n1\n}\n}";

        assertThat(VaultTransitVapidSigner.extractPublicKeyPem(body, 1)).isEqualTo(pem(1));
        assertThat(VaultTransitVapidSigner.extractLatestVersion(body)).isEqualTo(1);
    }

    @Test
    void missingDataObjectFails() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.extractPublicKeyPem("{\"foo\":{}}", 1))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no 'data' object");
    }

    @Test
    void missingKeysObjectFails() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.extractPublicKeyPem("{\"data\":{}}", 1))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("no 'keys' object");
    }

    @Test
    void missingLatestVersionFails() {
        assertThatThrownBy(() -> VaultTransitVapidSigner.extractLatestVersion("{\"data\":{\"keys\":{}}}"))
            .isInstanceOf(PushCryptoException.class)
            .hasMessageContaining("latest_version");
    }

    /** A realistic per-version entry: creation_time first, then name, then the version-tagged PEM. */
    private static String entry(int version) {
        return "\"" + version + "\":{\"creation_time\":\"2026-08-01T00:00:00Z\",\"name\":\"P-256\","
            + "\"public_key\":\"-----BEGIN PUBLIC KEY-----\\nKEY-V" + version
            + "\\n-----END PUBLIC KEY-----\\n\"}";
    }

    /** The PEM {@link #entry} embeds for {@code version}, with the JSON escaping undone. */
    private static String pem(int version) {
        return "-----BEGIN PUBLIC KEY-----\nKEY-V" + version + "\n-----END PUBLIC KEY-----\n";
    }
}
