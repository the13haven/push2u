/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Executes the VAPID key-generation snippet that is in {@code README.md} — the file itself, not a copy of it — and
 * feeds what it prints to {@link VapidKeys#fromBase64} and {@link LocalEcVapidSigner}.
 *
 * <p>The point is drift. push2u ships no key generator, so the README's snippet is the only instruction a new user
 * gets, and a test carrying its own frozen copy of that snippet would stay green while the documented one rotted. So
 * this test locates the block by the HTML-comment anchors around it ({@code vapid-keygen:begin} /
 * {@code vapid-keygen:end}, invisible when the README is rendered), pins the heredoc wrapper the block opens and closes
 * with — otherwise the command could be broken while the Java inside it stayed correct — and runs the body through the
 * {@code jshell} of the JVM running the tests.
 *
 * <p>Running it once is not enough on its own, because the pair it prints is random: the snippet's {@code fixed32} is
 * the part that is easy to get wrong, and both of its plausible regressions — dropping the left-padding, copying from
 * the wrong end of {@code toByteArray()} — survive most single draws. Dropping the left-padding, the worse of the two,
 * shows up in about one generated pair in two hundred. So a second run appends probe lines to the body it feeds
 * {@code jshell} (never to the README, which stays minimal and copy-pasteable), calling the block's <em>own</em>
 * {@code fixed32} on fixed values covering each shape {@link java.math.BigInteger#toByteArray()} produces, and compares
 * all 32 returned bytes. That check is a pure function of the snippet: it fails on the first pull request that breaks
 * the padding, not on the unlucky one.
 *
 * <p>A correct {@code fixed32} that nothing calls is the same failure one level out, and equally invisible to a random
 * draw: a scalar that happens to encode to exactly 32 bytes makes an unpadded snippet look right. So the statements
 * that call it are pinned as text, normalised by {@link #statements(String)}, along with the one that picks the
 * encoder. Nothing else is pinned: everything else the snippet does shows up in the value it prints, and a check on the
 * value costs no brittleness. Those are the only things here checked by reading rather than by running, because there
 * is nothing to run — the values are random, and a green run proves nothing about the next one.
 *
 * <p>It never skips. A missing {@code jshell}, a missing anchor or a missing {@code push2u.readme} system property is a
 * failure, because a skip here reproduces exactly the always-green outcome the test exists to prevent. The README's
 * path comes from Gradle (see {@code push2u-core/build.gradle.kts}); a relative {@code ../README.md} would be a guess
 * about the test's working directory.
 *
 * <p><b>What this guards, and what it does not.</b> It guards an ordinary edit — to the snippet, or to
 * {@link VapidKeys} and {@link LocalEcVapidSigner} underneath it — that makes the documented instructions print a key
 * push2u or a browser rejects. It does not guard against someone with commit access deliberately hiding broken code
 * from a text check: whoever can edit {@code README.md} can edit this file beside it, so hardening against that buys
 * nothing and costs the brittleness that gets a guard deleted. "A block comment, a text block, an escape or dead code
 * could hide a pinned statement" is out of scope by construction, not an open gap.
 *
 * <p>The one real limit that follows: a pinned statement being <em>present</em> is not proof that it produced the value
 * that was printed, and this file does not try to close that.
 */
class ReadmeVapidKeyGenerationTest {

    /**
     * System property carrying the absolute path of the repository's {@code README.md}, set by the Gradle test task.
     */
    private static final String README_PROPERTY = "push2u.readme";

    private static final String BEGIN_ANCHOR = "<!-- vapid-keygen:begin -->";
    private static final String END_ANCHOR = "<!-- vapid-keygen:end -->";
    private static final String FENCE_OPEN = "```bash";
    private static final String FENCE = "```";

    /** The heredoc wrapper, pinned literally: the command is as much of the documentation as the Java inside it. */
    private static final String HEREDOC_OPEN = "jshell -q - <<'EOF'";

    private static final String HEREDOC_CLOSE = "EOF";

    /**
     * The arguments of {@link #HEREDOC_OPEN}, pinned rather than parsed: that line is already matched character for
     * character.
     */
    private static final List<String> JSHELL_ARGUMENTS = List.of("-q", "-");

    /** The line that ends the jshell session; probe lines are spliced in before it. */
    private static final String EXIT_COMMAND = "/exit";

    private static final Pattern PUBLIC_KEY_LINE = Pattern.compile("(?m)^public:\\s+(\\S+)\\s*$");
    private static final Pattern PRIVATE_KEY_LINE = Pattern.compile("(?m)^private:\\s+(\\S+)\\s*$");
    private static final Pattern PROBE_LINE = Pattern.compile("(?m)^probe (\\S+) ([0-9a-f]{64})\\s*$");

    private static final long JSHELL_TIMEOUT_MINUTES = 3;

    /**
     * One check of the snippet's own {@code fixed32}: a {@code BigInteger} expression and the 32 bytes {@code fixed32}
     * must return for it.
     *
     * <p>The four together pin both regressions deterministically. Copying from the wrong end of the array is visible
     * only where {@code toByteArray()} is longer than 32 bytes, so the sign-byte case catches it; dropping the
     * left-padding is visible only where it is shorter, so the 31-byte and single-byte cases catch it. The exact-32
     * case is the shape that needs no adjustment at all and must come through untouched.
     */
    private record Fixed32Probe(String label, String expression, String expectedHex) {}

    private static final List<Fixed32Probe> FIXED32_PROBES = List.of(
            new Fixed32Probe(
                    "sign-byte",
                    "BigInteger.ONE.shiftLeft(255)",
                    "8000000000000000000000000000000000000000000000000000000000000000"),
            new Fixed32Probe(
                    "exactly-32",
                    "BigInteger.ONE.shiftLeft(254)",
                    "4000000000000000000000000000000000000000000000000000000000000000"),
            new Fixed32Probe(
                    "leading-zero",
                    "BigInteger.ONE.shiftLeft(247).subtract(BigInteger.ONE)",
                    "007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            new Fixed32Probe(
                    "single-byte",
                    "BigInteger.ONE",
                    "0000000000000000000000000000000000000000000000000000000000000001"));

    @Test
    void readmeSnippetStillCallsFixed32AndTheUrlSafeEncoder() {
        // snippetBody() fails unless the block opens with HEREDOC_OPEN and closes with HEREDOC_CLOSE.
        String body = snippetBody();

        // Four statements, each guarding something the printed value cannot show.
        //
        // The three fixed32 call sites: the values are random, so no run can prove a call is still
        // there — a coordinate that happens to encode to exactly 32 bytes makes a dropped call look
        // right about half the time. Matching whole statements pins the arraycopy offsets and the
        // destination lengths as well, which nothing else here looks at.
        //
        // The encoder: padding is covered by value on every draw, since 65 and 32 are both 2 mod 3
        // and a padded encoder therefore always leaves a trailing "=". The alphabet is not, because
        // url-safe and standard output coincide on roughly one draw in fifty.
        assertThat(statements(body))
                .as("what the printed value cannot show: that fixed32 is still called, and the encoder's alphabet")
                .contains(
                        "System.arraycopy(fixed32(point.getAffineX()), 0, publicKey, 1, 32);",
                        "System.arraycopy(fixed32(point.getAffineY()), 0, publicKey, 33, 32);",
                        "var privateKey = fixed32(((ECPrivateKey) pair.getPrivate()).getS());",
                        "var base64url = Base64.getUrlEncoder().withoutPadding();");
    }

    /**
     * The block's live lines, normalised for comparison: blanks and whole-line comments dropped, a trailing {@code //}
     * comment cut off, runs of whitespace collapsed, and each line trimmed.
     *
     * <p>The normalisation is what keeps the pins from crying wolf — annotating a still-correct line, re-indenting it
     * or adjusting spacing inside it must not fail a build, or the guard is the thing that gets deleted. It is not a
     * Java parser and does not need to be: it reads a snippet nobody is trying to disguise.
     */
    private static List<String> statements(String body) {
        return body.lines()
                .map(line -> {
                    int comment = line.indexOf("//");
                    return (comment < 0 ? line : line.substring(0, comment))
                            .replaceAll("\\s+", " ")
                            .trim();
                })
                .filter(line -> !line.isEmpty())
                .toList();
    }

    @Test
    void readmeSnippetPrintsAPairThatVapidKeysAndTheLocalSignerAccept(@TempDir Path workingDir) throws Exception {
        JshellRun result = run(snippetBody(), workingDir);

        String publicKey = capture(PUBLIC_KEY_LINE, result, "public");
        String privateKey = capture(PRIVATE_KEY_LINE, result, "private");

        // Unpadded, checked on the printed value rather than on the statement that produced it: both
        // lengths are 2 mod 3, so a padded encoder always leaves exactly one "=". VapidKeys accepts
        // padding (Base64Url tolerates it deliberately), and so would this test — but the browser-side
        // urlBase64ToUint8Array everyone copies does not, so a padded key works everywhere except in
        // the one place the reader needs it.
        assertThat(publicKey)
                .as("base64url without padding — 65 bytes is 2 mod 3, so padding would show as a trailing =")
                .doesNotContain("=");
        assertThat(privateKey)
                .as("base64url without padding — 32 bytes is 2 mod 3, so padding would show as a trailing =")
                .doesNotContain("=");

        VapidKeys keys = accepted(publicKey, privateKey);
        assertThat(keys.publicKey())
                .as("RFC 8292 §3.2 wants the uncompressed X9.62 point")
                .hasSize(65)
                .startsWith((byte) 0x04);

        // LocalEcVapidSigner's constructor signs a probe with the scalar and verifies it against the advertised
        // public key, so this is what rules out a pair whose halves do not belong together.
        assertThatCode(() -> {
                    LocalEcVapidSigner signer = new LocalEcVapidSigner(keys);
                    assertThat(signer.sign("probe".getBytes(UTF_8)))
                            .as("raw r||s ES256")
                            .hasSize(64);
                })
                .doesNotThrowAnyException();
    }

    @Test
    void readmeSnippetsFixed32PadsEveryShapeBigIntegerProduces(@TempDir Path workingDir) throws Exception {
        JshellRun result = run(withFixed32Probes(snippetBody()), workingDir);
        Map<String, String> printed = probeResults(result.printed());

        for (Fixed32Probe probe : FIXED32_PROBES) {
            // "%s" with a prebuilt message: stderr is arbitrary text and would be read as a format string otherwise.
            assertThat(printed)
                    .as(
                            "%s",
                            "fixed32(" + probe.expression() + "), from the block between " + BEGIN_ANCHOR + " and "
                                    + END_ANCHOR + " in " + readme() + " — the " + probe.label()
                                    + " shape, which is where a padding mistake shows.\nstderr:\n"
                                    + result.diagnostics())
                    .containsEntry(probe.label(), probe.expectedHex());
        }
    }

    /** The heredoc body of the anchored block: everything the README feeds to {@code jshell}, wrapper excluded. */
    private static String snippetBody() {
        List<String> block = fencedBlockBetweenAnchors(readme());

        if (block.size() < 3
                || !HEREDOC_OPEN.equals(block.get(0))
                || !HEREDOC_CLOSE.equals(block.get(block.size() - 1))) {
            return fail("The block between " + BEGIN_ANCHOR + " and " + END_ANCHOR + " in " + readme()
                    + " must open with \"" + HEREDOC_OPEN + "\" and close with \"" + HEREDOC_CLOSE
                    + "\". It opens with \"" + block.get(0) + "\" and closes with \""
                    + block.get(block.size() - 1) + "\".");
        }

        return String.join("\n", block.subList(1, block.size() - 1)) + "\n";
    }

    /**
     * The same body with lines printing {@code fixed32}'s output for each {@link #FIXED32_PROBES} entry, spliced in
     * ahead of the block's own {@code /exit}. The README stays as short as a reader wants it; the determinism lives
     * here.
     */
    private static String withFixed32Probes(String body) {
        List<String> lines = new ArrayList<>(body.lines().toList());
        int exit = lines.lastIndexOf(EXIT_COMMAND);
        if (exit < 0) {
            return fail("The block between " + BEGIN_ANCHOR + " and " + END_ANCHOR + " in " + readme()
                    + " no longer ends its session with \"" + EXIT_COMMAND + "\", so there is nowhere to splice the"
                    + " fixed32 probes in. Body was:\n" + body);
        }

        List<String> probes = new ArrayList<>();
        for (Fixed32Probe probe : FIXED32_PROBES) {
            // Prints: probe <label> <32 bytes of fixed32 output, hex>. HexFormat is qualified because the snippet
            // imports only what it needs and these lines must not require an import of their own.
            probes.add("System.out.println(\"probe " + probe.label() + " \" + java.util.HexFormat.of().formatHex("
                    + "fixed32(" + probe.expression() + ")));");
        }
        lines.addAll(exit, probes);
        return String.join("\n", lines) + "\n";
    }

    /** The probe lines out of the run's output, as label → {@code fixed32}'s output in hex. */
    private static Map<String, String> probeResults(String printed) {
        Map<String, String> results = new LinkedHashMap<>();
        Matcher matcher = PROBE_LINE.matcher(printed);
        while (matcher.find()) {
            results.put(matcher.group(1), matcher.group(2));
        }
        return results;
    }

    private static List<String> fencedBlockBetweenAnchors(Path readme) {
        String text = read(readme);

        int begin = text.indexOf(BEGIN_ANCHOR);
        int end = text.indexOf(END_ANCHOR);
        if (begin < 0 || end < 0) {
            return fail("Could not find the " + (begin < 0 ? BEGIN_ANCHOR : END_ANCHOR) + " anchor in " + readme
                    + ". The anchors mark the snippet this test executes; without them there is nothing to verify,"
                    + " and skipping would leave the documented snippet unchecked.");
        }
        if (begin != text.lastIndexOf(BEGIN_ANCHOR) || end != text.lastIndexOf(END_ANCHOR)) {
            return fail("The anchors " + BEGIN_ANCHOR + " / " + END_ANCHOR + " occur more than once in " + readme
                    + "; exactly one block can be the documented one.");
        }
        if (end < begin) {
            return fail(END_ANCHOR + " precedes " + BEGIN_ANCHOR + " in " + readme + ".");
        }

        // Trailing whitespace only — leading whitespace is the snippet's own indentation.
        List<String> lines = new ArrayList<>(text.substring(begin + BEGIN_ANCHOR.length(), end)
                .lines()
                .map(String::stripTrailing)
                .toList());
        while (!lines.isEmpty() && lines.get(0).isEmpty()) {
            lines.remove(0);
        }
        while (!lines.isEmpty() && lines.get(lines.size() - 1).isEmpty()) {
            lines.remove(lines.size() - 1);
        }

        if (lines.size() < 3 || !FENCE_OPEN.equals(lines.get(0)) || !FENCE.equals(lines.get(lines.size() - 1))) {
            return fail("The text between the anchors in " + readme + " must be exactly one " + FENCE_OPEN
                    + " fenced block. Found:\n" + String.join("\n", lines));
        }
        List<String> inside = lines.subList(1, lines.size() - 1);
        if (inside.stream().anyMatch(line -> line.startsWith(FENCE))) {
            return fail("More than one fenced block sits between the anchors in " + readme + ".");
        }
        return List.copyOf(inside);
    }

    private static Path readme() {
        String configured = System.getProperty(README_PROPERTY);
        if (configured == null || configured.isBlank()) {
            return fail("The system property " + README_PROPERTY + " is not set, so the README cannot be located."
                    + " The Gradle test task passes it (push2u-core/build.gradle.kts); running this test outside"
                    + " Gradle needs -D" + README_PROPERTY + "=/path/to/README.md.");
        }
        Path readme = Path.of(configured);
        if (!Files.isRegularFile(readme)) {
            return fail(README_PROPERTY + " points at " + readme.toAbsolutePath() + ", which is not a regular file.");
        }
        return readme;
    }

    private static String read(Path readme) {
        try {
            return Files.readString(readme, UTF_8);
        } catch (IOException e) {
            return fail("Could not read " + readme.toAbsolutePath(), e);
        }
    }

    /**
     * What one run of the block produced. Both streams, because {@code jshell} reports a compile error on stderr and
     * still exits 0 — so the likeliest breakage of all, a snippet that stopped compiling, reaches the assertions as an
     * empty stdout with the actual answer sitting in a file nobody read.
     *
     * @param printed the block's stdout
     * @param diagnostics its stderr, verbatim, including any launcher chatter
     */
    private record JshellRun(String printed, String diagnostics) {}

    /** Runs the given body exactly as the README prescribes: the documented command, with the body on stdin. */
    private static JshellRun run(String body, Path workingDir) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(jshell().toString());
        command.addAll(JSHELL_ARGUMENTS);

        Path output = workingDir.resolve("jshell-stdout.txt");
        // stderr to a file rather than merged into stdout: the launcher's own chatter (JAVA_TOOL_OPTIONS notices and
        // the like) would otherwise land among the printed keys, and it is wanted verbatim in a failure.
        //
        // stdout to a file for a second reason — reading the child's stream here would block until the child closed
        // it, i.e. until it exited, and waitFor's timeout below would then only ever be reached after the thing it is
        // meant to bound had already finished. With both streams redirected, waitFor is the only wait there is.
        Path diagnostics = workingDir.resolve("jshell-stderr.txt");
        Process process = new ProcessBuilder(command)
                .directory(workingDir.toFile())
                .redirectOutput(output.toFile())
                .redirectError(diagnostics.toFile())
                .start();

        // A couple of kilobytes, well inside a pipe buffer, so this completes whether or not the child is reading.
        try (OutputStream stdin = process.getOutputStream()) {
            stdin.write(body.getBytes(UTF_8));
        }

        if (!process.waitFor(JSHELL_TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
            process.destroyForcibly();
            return fail("The README snippet did not finish within " + JSHELL_TIMEOUT_MINUTES + " minutes."
                    + diagnostics(output, diagnostics));
        }
        if (process.exitValue() != 0) {
            return fail(
                    "The README snippet exited with " + process.exitValue() + "." + diagnostics(output, diagnostics));
        }
        return new JshellRun(Files.readString(output, UTF_8), contents(diagnostics));
    }

    private static Path jshell() {
        Path bin = Path.of(System.getProperty("java.home"), "bin");
        // Resolved from java.home, not from PATH: the snippet must be exercised by the JVM this build runs on.
        for (String name : List.of("jshell", "jshell.exe")) {
            Path candidate = bin.resolve(name);
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        return fail("No jshell in " + bin + ". This test runs the README's documented snippet and must not be"
                + " skipped when the tool is missing — run the build on a full JDK.");
    }

    private static String capture(Pattern pattern, JshellRun run, String label) {
        Matcher matcher = pattern.matcher(run.printed());
        if (!matcher.find()) {
            // stderr, not only stdout: a snippet that no longer compiles prints nothing here and everything there.
            return fail("The README snippet printed no \"" + label + ":\" line.\nstdout:\n" + run.printed()
                    + "\nstderr:\n" + run.diagnostics());
        }
        return matcher.group(1);
    }

    /**
     * {@link VapidKeys#fromBase64} on the printed pair, with the rejection named for what it actually is. This is the
     * likeliest way for the test to fail, and the bare exception would say nothing about which file or which block a
     * reader has to go and look at.
     */
    private static VapidKeys accepted(String publicKey, String privateKey) {
        try {
            return VapidKeys.fromBase64(publicKey, privateKey);
        } catch (RuntimeException e) {
            return fail(
                    "The block between " + BEGIN_ANCHOR + " and " + END_ANCHOR + " in " + readme()
                            + " printed a pair that VapidKeys.fromBase64 rejects. That block is what a new user is told to"
                            + " run, and this test executes it rather than a copy of it, so it is the block that needs"
                            + " fixing — start at its fixed32 helper."
                            + "\n  public:  " + publicKey + " (" + decodedByteCount(publicKey)
                            + " decoded bytes; RFC 8292 §3.2 wants 65)"
                            // The scalar is ephemeral and worthless, but printing key material is a habit worth
                            // not having — and its length is what diagnoses an encoding mistake anyway.
                            + "\n  private: " + decodedByteCount(privateKey)
                            + " decoded bytes (32 wanted; the value itself is not printed)",
                    e);
        }
    }

    private static String decodedByteCount(String base64url) {
        try {
            return Integer.toString(Base64.getUrlDecoder().decode(base64url).length);
        } catch (IllegalArgumentException e) {
            // Reads into both call sites, which append " decoded bytes" and their own expectation.
            return "not base64url, so no";
        }
    }

    private static String diagnostics(Path stdoutFile, Path stderrFile) {
        return "\nstdout:\n" + contents(stdoutFile) + "\nstderr:\n" + contents(stderrFile);
    }

    private static String contents(Path file) {
        try {
            return Files.exists(file) ? Files.readString(file, UTF_8) : "";
        } catch (IOException e) {
            return "<unreadable: " + e + ">";
        }
    }
}
