/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.the13haven.push2u.PushCryptoException;

/**
 * Mechanical fuzzing of the handwritten JSON extractor in {@link VaultTransitVapidSigner}. The extractor reads bytes
 * off the network with no JSON library behind it, so the invariant this suite pins is the extractor's whole safety
 * story: <em>no</em> response body — however corrupted — may make it do anything except return a correct result or
 * throw {@link PushCryptoException}. Concretely: no {@code IndexOutOfBoundsException} from a scan running past a
 * truncated buffer, no {@code NumberFormatException} escaping {@code parseInt}, no {@code StackOverflowError} from a
 * rewrite to recursive descent, no unbounded loop on an unterminated token, and no echo of an oversized body into the
 * exception message past the deliberate truncation cap.
 *
 * <p>The corpus is derived mechanically from realistic Vault responses (a {@code transit/keys/<name>} body with real
 * P-256 PEMs, a {@code transit/sign/<name>} body with a {@code vault:v1:<base64url>} envelope): every truncation, every
 * single-character deletion, every structural character ({@code { } " : , \}) replaced by every other one, plus hostile
 * suffixes and pathologically deep nesting. Mutation is exhaustive and deterministic — no randomness — so a failure
 * names the exact mutant and reproduces on every run. All corpus fixtures are fixed constants for the same reason.
 *
 * <p>The injection tests are the complement: <em>valid</em> JSON whose string values contain the very labels and
 * structural characters the extractor anchors on ({@code "data"}, whole spelled-out members, escaped quotes, braces,
 * trailing backslashes). A naive extractor that scans for a substring instead of tracking string state reads a value
 * out of a string literal — the most likely real bug in hand-rolled code like this — and these tests fail on the wrong
 * <em>result</em>, not just on a wrong exception. The hostile payloads are planted in <em>sibling</em> decoy members,
 * so they pin the lookup scanner's string-state tracking; the value scanner's own escape skip is pinned separately, by
 * extracting a target value that itself contains escaped quotes and demanding it whole. They extend
 * {@link VaultTransitVapidSignerExtractionTest}'s anchoring cases (decoy members whose string value merely equals a
 * label) to hostile content <em>inside</em> string literals, which that suite does not cover.
 */
class VaultTransitVapidSignerParserFuzzTest {

    private static final URI VAULT = URI.create("https://vault.test:8200");
    private static final String TOKEN = "s.push2u-test-vault-token";
    private static final byte[] PROBE = "probe".getBytes(StandardCharsets.UTF_8);
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    /**
     * Bound on any {@link PushCryptoException} message the extractor produces: the production echo cap
     * ({@code ERROR_ECHO_LIMIT} = 2048) plus headroom for the message prefix and the {@code [truncated, ...]} marker.
     * Kept as a literal because the production constant is private on purpose; if the cap ever changes, this bound is
     * the one place to follow it.
     */
    private static final int MESSAGE_LENGTH_BOUND = 2048 + 256;

    /** Characters the extractor treats as structure; every occurrence is replaced by every other one. */
    private static final String STRUCTURAL = "{}\":,\\";

    /** Replacements: the other structural characters, a letter, whitespace variants, and a NUL byte. */
    private static final String REPLACEMENTS = "{}\":,\\x \n\u0000";

    /** Planted past the echo cap in the oversized body; it must never surface in any throwable of the chain. */
    private static final String OVERSIZED_SENTINEL = "END-OF-OVERSIZED-FILLER-4ef1";

    /** Fixed (not generated) P-256 key so every mutant body is byte-identical on every run. */
    private static final String PEM_V1 = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuKsiTqV4k5UT0nho1xxTq12vU1zi
            zFPU+0XuIWNwVwd5DelBF3Qp25b9UZyCpLCn+ZdqV+EI5sjDPSS2XQV0AQ==
            -----END PUBLIC KEY-----
            """;

    private static final String PEM_V2 = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElqSm3sBbvbxiK5RzsuTQKCuy5gFr
            qazSHI0BGhN+R8clDalV8xkJxUzLAxYw3XvgzVQx+NisYKU16e0pQznR2g==
            -----END PUBLIC KEY-----
            """;

    private static final String KEYS_BODY = keysBody("");
    private static final String SIGN_BODY = signBody("");

    /** One corrupted input: what was done to which corpus, and the resulting body. */
    private record Mutant(String description, String body) {}

    /** One way into the parser; every mutant is pushed through every target. */
    @FunctionalInterface
    private interface ParserCall {
        void run(String body);
    }

    private record ParserTarget(String name, ParserCall call) {}

    private static final List<ParserTarget> TARGETS = List.of(
            new ParserTarget("extractLatestVersion", VaultTransitVapidSigner::extractLatestVersion),
            new ParserTarget("extractKeyType", VaultTransitVapidSigner::extractKeyType),
            new ParserTarget(
                    "extractPublicKeyPem(version 1)", body -> VaultTransitVapidSigner.extractPublicKeyPem(body, 1)),
            new ParserTarget(
                    "extractPublicKeyPem(version 2)", body -> VaultTransitVapidSigner.extractPublicKeyPem(body, 2)),
            new ParserTarget("sign()", VaultTransitVapidSignerParserFuzzTest::signAgainst),
            new ParserTarget("fetched-mode constructor", VaultTransitVapidSignerParserFuzzTest::constructAgainst));

    // ---- the corpus is real before it is corrupted ------------------------------------------------

    /**
     * Every fuzz sweep below accepts "throws PushCryptoException" as a pass, so a corpus typo would make the whole
     * suite vacuously green — every mutant would fail at the root object and nothing deeper would ever run. This test
     * pins that the pristine corpus drives every target to its full, correct result.
     */
    @Test
    void theCorpusIsValidBeforeMutation() {
        assertThat(VaultTransitVapidSigner.extractLatestVersion(KEYS_BODY)).isEqualTo(2);
        assertThat(VaultTransitVapidSigner.extractKeyType(KEYS_BODY)).isEqualTo("ecdsa-p256");
        assertThat(VaultTransitVapidSigner.extractPublicKeyPem(KEYS_BODY, 1)).isEqualTo(PEM_V1);
        assertThat(VaultTransitVapidSigner.extractPublicKeyPem(KEYS_BODY, 2)).isEqualTo(PEM_V2);
        assertThat(signAgainst(SIGN_BODY)).isEqualTo(realSignature());
        byte[] publicKey = constructAgainst(KEYS_BODY).publicKey();
        assertThat(publicKey).hasSize(65);
        assertThat(publicKey[0]).isEqualTo((byte) 0x04);
    }

    // ---- systematic mutation: exception discipline ------------------------------------------------

    @Test
    void mutatedKeyMetadataResponsesNeverEscapeTheExceptionContract() {
        sweep(systematicMutants("keys response", KEYS_BODY), "");
    }

    @Test
    void mutatedSignResponsesNeverEscapeTheExceptionContract() {
        sweep(systematicMutants("sign response", SIGN_BODY), "");
    }

    /**
     * The extractor is iterative today, which is the only reason 100k-deep nesting terminates quietly. A rewrite to
     * recursive descent — the natural shape for this code — would blow the stack here, and a scan that stops tracking
     * depth would hang or mis-bind. Inputs this size still complete in microseconds, so the sweep timeout doubles as
     * the hang detector.
     */
    @Test
    void pathologicallyDeepNestingNeitherOverflowsTheStackNorHangs() {
        sweep(
                List.of(
                        new Mutant("100k unclosed opening braces", "{".repeat(100_000)),
                        new Mutant("100k unclosed opening brackets", "[".repeat(100_000)),
                        new Mutant("100k alternating brace pairs", "{}".repeat(50_000)),
                        new Mutant(
                                "20k-deep nested data objects", "{\"data\":".repeat(20_000) + "1" + "}".repeat(20_000)),
                        new Mutant(
                                "10k-deep nested version-1 entries",
                                "{\"data\":{\"keys\":" + "{\"1\":".repeat(10_000) + "\"x\"" + "}".repeat(10_000)
                                        + "}}"),
                        new Mutant("an unterminated string opened at the end", KEYS_BODY + ",\"x\":\"never closed"),
                        new Mutant("an unterminated escape at the very end", KEYS_BODY + "\\")),
                "");
    }

    /**
     * The overshoot the string scanners' post-loop bounds checks exist for, pinned by fixed bodies as well as by the
     * truncation-plus-trailing-backslash mutants in the systematic sweeps: while locating a value's closing quote the
     * scanner steps two characters over a backslash, so a string that is unterminated <em>and</em> ends in a backslash
     * at the final index pushes the cursor past the end of the input. Only the bounds check after the scan loop turns
     * that into {@link PushCryptoException} — deleting it (in {@code stringValueAt}) makes {@code sign()} on the first
     * body below throw a raw {@code StringIndexOutOfBoundsException}, which this test must catch. The string has to be
     * one the extractor actually scans for a terminator: the earlier {@code KEYS_BODY + "\\"} mutants never reach that
     * code because every string a lookup walks through has already terminated by then.
     */
    @Test
    void anUnterminatedStringEndingInABackslashFailsInsideTheContract() {
        sweep(
                List.of(
                        new Mutant(
                                "sign body whose signature value is unterminated and ends in a backslash",
                                "{\"data\":{\"key_version\":2,\"signature\":\"abc\\"),
                        new Mutant(
                                "keys body whose type value is unterminated and ends in a backslash",
                                "{\"data\":{\"keys\":{\"1\":{\"public_key\":\"x\"}},\"latest_version\":1,"
                                        + "\"type\":\"ecdsa\\"),
                        new Mutant(
                                "keys body whose public_key value is unterminated and ends in a backslash",
                                "{\"data\":{\"keys\":{\"1\":{\"public_key\":\"-----BEGIN\\"),
                        new Mutant(
                                "sign body whose signature value ends in an escaped-quote-then-backslash tail",
                                "{\"data\":{\"signature\":\"abc\\\"\\")),
                "");
    }

    /**
     * The production echo cap ({@code ERROR_ECHO_LIMIT}) holds only if <em>every</em> throw site routes the body
     * through {@code abbreviated}. A sentinel planted ~30k characters in must never surface anywhere in the throwable
     * chain, and no message may exceed the cap plus headroom — for the pristine body and for its mutants alike.
     * Truncation/deletion are sampled on a fixed stride here (the body is 30k+ characters; exhaustive mutation of it
     * would dominate the build for no extra coverage), structural replacement stays exhaustive.
     */
    @Test
    void anOversizedBodyStaysOutOfExceptionMessagesEvenUnderMutation() {
        String body = oversizedBody();
        // Prove the sweep is not vacuous: the pristine oversized body is a valid response.
        assertThat(VaultTransitVapidSigner.extractLatestVersion(body)).isEqualTo(2);

        exercise("pristine oversized body", body, OVERSIZED_SENTINEL);
        sweep(sampledMutants("oversized body", body, 293), OVERSIZED_SENTINEL);
    }

    /**
     * A digit run far too long for an {@code int} must fail as {@link PushCryptoException} with the body echo still
     * capped — the run <em>is</em> the body here, so an uncapped echo would paste all 30k digits into the log line.
     *
     * <p>Known caveat, reported rather than asserted: {@link Integer#parseInt} puts the <em>full</em> digit run into
     * the {@link NumberFormatException} it throws, and production attaches that exception as the cause — so a logged
     * stack trace ("Caused by: ... For input string: 999…") still carries the whole run past the cap. Fixing it means
     * not attaching the raw cause (or rejecting over-long runs before parsing); this test only pins the message of the
     * module's own exception.
     */
    @Test
    void aHugeDigitRunInLatestVersionFailsInsideTheContract() {
        String body = "{\"data\":{\"latest_version\":" + "9".repeat(30_000) + ",\"keys\":{\"1\":{}},"
                + "\"type\":\"ecdsa-p256\"}}";

        assertThatThrownBy(() -> VaultTransitVapidSigner.extractLatestVersion(body))
                .isInstanceOf(PushCryptoException.class)
                .satisfies(
                        thrown -> assertThat(String.valueOf(thrown.getMessage()).length())
                                .as("the digit run must not be echoed whole into the module's own message")
                                .isLessThan(MESSAGE_LENGTH_BOUND));
    }

    // ---- injection: hostile content inside valid string literals ----------------------------------

    /**
     * Valid responses whose string values spell out the labels, members and structural characters the extractor anchors
     * on. Every lookup must still land on the real member: a wrong result here means a value was read out of a string
     * literal — the substring-scanner bug class — and unlike the mutation sweeps this test knows the one correct answer
     * and demands it.
     */
    @ParameterizedTest
    @MethodSource("hostilePayloads")
    void hostileStringContentCannotHijackKeyMetadataExtraction(String payload) {
        String body = keysBody(jsonEscape(payload));

        assertThat(VaultTransitVapidSigner.extractLatestVersion(body)).isEqualTo(2);
        assertThat(VaultTransitVapidSigner.extractKeyType(body)).isEqualTo("ecdsa-p256");
        assertThat(VaultTransitVapidSigner.extractPublicKeyPem(body, 1)).isEqualTo(PEM_V1);
        assertThat(VaultTransitVapidSigner.extractPublicKeyPem(body, 2)).isEqualTo(PEM_V2);
        assertThat(constructAgainst(body).publicKey())
                .as("the fetched-mode constructor must still bind to version 2's real key")
                .isEqualTo(constructAgainst(KEYS_BODY).publicKey());
    }

    @ParameterizedTest
    @MethodSource("hostilePayloads")
    void hostileStringContentCannotHijackSignatureExtraction(String payload) {
        assertThat(signAgainst(signBody(jsonEscape(payload)))).isEqualTo(realSignature());
    }

    /**
     * Raw (unescaped) hostile content. Not included: bare
     * {@code keys}/{@code latest_version}/{@code type}/{@code signature} string values —
     * {@link VaultTransitVapidSignerExtractionTest} and {@link VaultTransitVapidSignerSignResponseTest} already own
     * those decoys as sibling members.
     */
    static Stream<String> hostilePayloads() {
        String impostor = impostorEnvelope();
        return Stream.of(
                // The one anchor label the existing suites never plant as a decoy value.
                "data",
                // Whole members spelled out inside a string: the substring-scanner jackpot.
                "\"data\":{\"signature\":\"" + impostor + "\"}",
                "\"signature\":\"" + impostor + "\"",
                "\"latest_version\":9,",
                "\"keys\":{\"1\":{\"public_key\":\"IMPOSTOR\"}}",
                "\"type\":\"impostor\"",
                "\"public_key\":\"IMPOSTOR\"",
                "\"1\":{\"public_key\":\"IMPOSTOR\"}",
                // An entire fake response nested in a string value.
                "{\"data\":{\"keys\":{\"2\":{\"public_key\":\"IMPOSTOR\"}},\"latest_version\":9,"
                        + "\"type\":\"impostor\",\"signature\":\"" + impostor + "\"}}",
                // Structural characters that desync a scanner not tracking string state.
                "}",
                "{",
                "}},\"latest_version\":9",
                "{{{{{{",
                "}}}}}}",
                ":",
                ",",
                // Backslash traps: content ending in a backslash becomes \\" in the JSON — a scanner
                // that treats every backslash-quote pair as an escaped quote overruns the value.
                "\\",
                "ends with a backslash \\",
                "\"",
                // Content that itself contains \" sequences, i.e. double-escaped members.
                "\\\"signature\\\":\\\"" + impostor + "\\\"",
                // A well-formed envelope as a plain value.
                impostor);
    }

    /**
     * Escaped quotes inside the very string literal being extracted — the one place the sweeps above never put them.
     * The hostile payloads plant {@code \"} only in sibling decoy members (pinning the lookup scanner's string-state
     * tracking) and in unterminated strings (pinning the value scanner's post-loop bounds check), so a value scanner
     * that stops at the first quote character — its escape skip dropped — returns a silently <em>truncated</em> value
     * while still honouring the exception contract, invisible to every sweep. Only extracting a target value that
     * itself contains {@code \"} and demanding the full raw content pins the skip. The whole-flow targets cannot
     * discriminate here — a signature envelope or PEM containing an escaped quote is rejected downstream of extraction
     * whether truncated or whole — so this pins the package-private extractors directly. Expected values are the raw
     * (unescaped) content, exactly as {@code stringValueAt} contracts to return it; only {@code extractPublicKeyPem}'s
     * documented {@code \n} unescaping is applied.
     */
    @Test
    void anEscapedQuoteInsideAnExtractedValueDoesNotTruncateIt() {
        String body = "{\"data\":{\"keys\":{\"1\":{\"public_key\":\"PEM\\\"WITH\\\"QUOTES\\nEND\"}},"
                + "\"latest_version\":1,\"type\":\"ecdsa\\\"p256\\\"tail\"}}";

        assertThat(VaultTransitVapidSigner.extractKeyType(body))
                .as("the full raw type value, escaped quotes and the content after them included")
                .isEqualTo("ecdsa\\\"p256\\\"tail");
        assertThat(VaultTransitVapidSigner.extractPublicKeyPem(body, 1))
                .as("the full raw PEM value, with only the documented \\n unescaping applied")
                .isEqualTo("PEM\\\"WITH\\\"QUOTES\nEND");
        assertThat(VaultTransitVapidSigner.extractLatestVersion(body))
                .as("the lookups around the escape-laden values must still bind to the real members")
                .isEqualTo(1);
    }

    // ---- harness ----------------------------------------------------------------------------------

    /**
     * Run every target over every mutant under a preemptive timeout. The timeout is the hang detector — each case is
     * microseconds, so 30 s means a loop stopped advancing — and on timeout the failure names the case that was
     * running, otherwise it would be undiagnosable in CI.
     */
    private static void sweep(List<Mutant> mutants, String sentinel) {
        AtomicReference<String> current = new AtomicReference<>("(before the first case)");
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
                for (Mutant mutant : mutants) {
                    current.set(mutant.description());
                    exercise(mutant.description(), mutant.body(), sentinel);
                }
            });
        } catch (AssertionError e) {
            // Failures raised by exercise() always START with the case description, so only JUnit's
            // own timeout error can match this prefix — a case description merely containing the
            // words must not be relabelled as a hang.
            if (String.valueOf(e.getMessage()).startsWith("execution timed out")) {
                throw new AssertionError("the parser hung while fuzzing case: " + current.get(), e);
            }
            throw e;
        }
    }

    /**
     * The per-case contract: each target either returns or throws {@link PushCryptoException} whose message respects
     * the echo cap, never contains the Vault token, and — like every other message in the throwable chain — never
     * contains {@code sentinel}. Anything else fails naming the case, the target, the throwable and the input.
     */
    private static void exercise(String caseDescription, String body, String sentinel) {
        for (ParserTarget target : TARGETS) {
            try {
                target.call().run(body);
            } catch (PushCryptoException disciplined) {
                String message = String.valueOf(disciplined.getMessage());
                if (message.length() > MESSAGE_LENGTH_BOUND) {
                    fail("%s: %s threw a PushCryptoException whose message is %d chars — past the echo cap of %d."
                                    .formatted(caseDescription, target.name(), message.length(), MESSAGE_LENGTH_BOUND)
                            + " Input: " + shown(body));
                }
                if (message.contains(TOKEN)) {
                    fail("%s: %s leaked the Vault token into its message. Input: %s"
                            .formatted(caseDescription, target.name(), shown(body)));
                }
                if (!sentinel.isEmpty()) {
                    for (Throwable t = disciplined; t != null; t = t.getCause()) {
                        if (String.valueOf(t.getMessage()).contains(sentinel)) {
                            fail("%s: %s echoed body content from past the cap (the sentinel) via %s. Input: %s"
                                    .formatted(
                                            caseDescription,
                                            target.name(),
                                            t.getClass().getName(),
                                            shown(body)));
                        }
                    }
                }
            } catch (Throwable foreign) {
                fail(
                        "%s: %s threw %s instead of returning or throwing PushCryptoException. Input: %s"
                                .formatted(
                                        caseDescription,
                                        target.name(),
                                        foreign.getClass().getName(),
                                        shown(body)),
                        foreign);
            }
        }
    }

    // ---- mutation generators ----------------------------------------------------------------------

    /** Exhaustive: every truncation, every deletion, every structural replacement, hostile suffixes. */
    private static List<Mutant> systematicMutants(String name, String body) {
        List<Mutant> mutants = new ArrayList<>(truncationsAndDeletions(name, body, 1));
        mutants.addAll(structuralReplacements(name, body));
        mutants.addAll(hostileSuffixes(name, body));
        return mutants;
    }

    /** Sampled truncations/deletions on a fixed stride for oversized bodies; the rest stays exhaustive. */
    private static List<Mutant> sampledMutants(String name, String body, int stride) {
        List<Mutant> mutants = new ArrayList<>(truncationsAndDeletions(name, body, stride));
        mutants.addAll(structuralReplacements(name, body));
        mutants.addAll(hostileSuffixes(name, body));
        return mutants;
    }

    private static List<Mutant> truncationsAndDeletions(String name, String body, int stride) {
        List<Mutant> mutants = new ArrayList<>();
        for (int i = 0; i < body.length(); i += stride) {
            mutants.add(new Mutant(name + " truncated to " + i + " chars", body.substring(0, i)));
            // The plain truncations can never end in a backslash the string scanners must skip over
            // (the sign body has none; the keys body's PEM backslashes sit where the version-entry
            // brace matching fails first), yet a backslash at the FINAL index of an unterminated,
            // actually-scanned string is precisely what makes the escape skip step past the end —
            // the overshoot only the scanners' post-loop bounds checks turn into the module's own
            // exception. Emit that shape at every truncation point.
            mutants.add(new Mutant(
                    name + " truncated to " + i + " chars + trailing backslash", body.substring(0, i) + "\\"));
            mutants.add(new Mutant(
                    name + " with char deleted at index " + i, body.substring(0, i) + body.substring(i + 1)));
        }
        return mutants;
    }

    private static List<Mutant> structuralReplacements(String name, String body) {
        List<Mutant> mutants = new ArrayList<>();
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (STRUCTURAL.indexOf(c) < 0) {
                continue;
            }
            for (int r = 0; r < REPLACEMENTS.length(); r++) {
                char replacement = REPLACEMENTS.charAt(r);
                if (replacement == c) {
                    continue;
                }
                mutants.add(new Mutant(
                        name + ": '" + c + "' at index " + i + " replaced by char " + (int) replacement,
                        body.substring(0, i) + replacement + body.substring(i + 1)));
            }
        }
        return mutants;
    }

    private static List<Mutant> hostileSuffixes(String name, String body) {
        List<Mutant> mutants = new ArrayList<>();
        for (String suffix : List.of(
                "{",
                "}",
                "\"",
                "\\",
                ",",
                ":",
                ",\"x\":\"unterminated",
                "{\"data\":",
                "\"data\"",
                "\uD800",
                "{".repeat(64))) {
            mutants.add(new Mutant(name + " + suffix " + shown(suffix), body + suffix));
        }
        return mutants;
    }

    // ---- fixtures ---------------------------------------------------------------------------------

    /**
     * A realistic {@code transit/keys/<name>} body (field set and Go-map member order as Vault emits them), with an
     * optional decoy planted as a string value at every level the extractor walks through: the root object,
     * {@code data}, inside {@code keys} (as a lexicographically-first {@code "0"} entry), and inside version 1's own
     * entry before its {@code public_key}. {@code decoy} must already be JSON-escaped; empty means no decoys.
     */
    private static String keysBody(String decoy) {
        String decoyMember = decoy.isEmpty() ? "" : "\"decoy\":\"" + decoy + "\",";
        String keysDecoy = decoy.isEmpty() ? "" : "\"0\":\"" + decoy + "\",";
        return "{" + decoyMember
                + "\"request_id\":\"e29882ac-1cd4-44d9-ad2d-8e5c38472452\",\"lease_id\":\"\",\"renewable\":false,"
                + "\"lease_duration\":0,\"data\":{" + decoyMember
                + "\"allow_plaintext_backup\":false,\"auto_rotate_period\":0,\"deletion_allowed\":false,"
                + "\"derived\":false,\"exportable\":false,\"imported_key\":false,\"keys\":{" + keysDecoy
                + "\"1\":{" + decoyMember
                + "\"creation_time\":\"2026-07-01T10:00:00.000000Z\",\"name\":\"P-256\","
                + "\"public_key\":\"" + pemEscaped(PEM_V1) + "\"},"
                + "\"2\":{\"creation_time\":\"2026-08-01T10:00:00.000000Z\",\"name\":\"P-256\","
                + "\"public_key\":\"" + pemEscaped(PEM_V2) + "\"}},"
                + "\"latest_version\":2,\"min_available_version\":0,\"min_decryption_version\":1,"
                + "\"min_encryption_version\":0,\"name\":\"vapid\",\"supports_decryption\":false,"
                + "\"supports_derivation\":false,\"supports_encryption\":false,\"supports_signing\":true,"
                + "\"type\":\"ecdsa-p256\"},\"warnings\":null}";
    }

    /** A realistic {@code transit/sign/<name>} body; decoys planted at the root and inside {@code data}. */
    private static String signBody(String decoy) {
        String decoyMember = decoy.isEmpty() ? "" : "\"decoy\":\"" + decoy + "\",";
        return "{" + decoyMember
                + "\"request_id\":\"1c4b0f4e-9c66-d1a1-2233-445566778899\",\"lease_id\":\"\",\"renewable\":false,"
                + "\"lease_duration\":0,\"data\":{" + decoyMember + "\"key_version\":2,"
                + "\"signature\":\"vault:v1:" + BASE64_URL.encodeToString(realSignature()) + "\"},"
                + "\"warnings\":null}";
    }

    /** The keys body behind ~30k characters of padding, with the sentinel planted at the padding's end. */
    private static String oversizedBody() {
        return "{\"padding\":\"" + "x".repeat(30_000) + OVERSIZED_SENTINEL + "\"," + KEYS_BODY.substring(1);
    }

    /** 64 distinguishable bytes standing in for a real {@code r || s} pair. */
    private static byte[] realSignature() {
        byte[] signature = new byte[64];
        for (int i = 0; i < signature.length; i++) {
            signature[i] = (byte) i;
        }
        return signature;
    }

    /** A well-formed envelope whose payload differs from {@link #realSignature} in every byte. */
    private static String impostorEnvelope() {
        byte[] impostor = new byte[64];
        Arrays.fill(impostor, (byte) 0x55);
        return "vault:v1:" + BASE64_URL.encodeToString(impostor);
    }

    /** A genuine P-256 point (the RFC 8291 §5 user-agent key): the supplied key is validated against the curve. */
    private static byte[] validPublicKey() {
        return Base64.getUrlDecoder()
                .decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
    }

    /** Run a whole {@code sign} round trip against a signer whose Vault answers {@code responseBody}. */
    private static byte[] signAgainst(String responseBody) {
        return VaultTransitVapidSigner.builderWithSuppliedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN), validPublicKey())
                .mount("transit")
                .transport(canned(responseBody))
                .build()
                .sign(PROBE);
    }

    /** Run a whole fetched-mode construction against a Vault whose key read answers {@code responseBody}. */
    private static VaultTransitVapidSigner constructAgainst(String responseBody) {
        return VaultTransitVapidSigner.builderWithFetchedPublicKey(
                        VAULT, new TransitKeyName("vapid"), new VaultToken(TOKEN))
                .mount("transit")
                .transport(canned(responseBody))
                .build();
    }

    private static VaultHttpTransport canned(String body) {
        return new VaultHttpTransport() {
            @Override
            public VaultHttpResponse get(URI uri, Map<String, String> headers) {
                return new VaultHttpResponse(200, body);
            }

            @Override
            public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] requestBody) {
                return new VaultHttpResponse(200, body);
            }
        };
    }

    private static String pemEscaped(String pem) {
        return pem.replace("\n", "\\n");
    }

    /** Escape raw content into a JSON string literal body (backslashes first, then quotes). */
    private static String jsonEscape(String content) {
        return content.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** The input as shown in a failure: enough to reproduce, truncated so the report stays readable. */
    private static String shown(String body) {
        String printable = body.replace("\u0000", "\\0").replace("\n", "\\n");
        if (printable.length() <= 200) {
            return "'" + printable + "'";
        }
        return "'" + printable.substring(0, 200) + "…' (" + body.length() + " chars)";
    }
}
