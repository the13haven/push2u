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
import java.util.List;
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
 * <p>It never skips. A missing {@code jshell}, a missing anchor or a missing {@code push2u.readme} system property is a
 * failure, because a skip here reproduces exactly the always-green outcome the test exists to prevent. The README's
 * path comes from Gradle (see {@code push2u-core/build.gradle.kts}); a relative {@code ../README.md} would be a guess
 * about the test's working directory.
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

    private static final Pattern PUBLIC_KEY_LINE = Pattern.compile("(?m)^public:\\s+(\\S+)\\s*$");
    private static final Pattern PRIVATE_KEY_LINE = Pattern.compile("(?m)^private:\\s+(\\S+)\\s*$");

    private static final long JSHELL_TIMEOUT_MINUTES = 3;

    @Test
    void readmeCarriesTheAnchoredBlockWithTheDocumentedHeredocWrapper() {
        Snippet snippet = snippet();

        assertThat(snippet.command())
                .as("the command the README tells the reader to run")
                .containsExactly("jshell", "-q", "-");
        assertThat(snippet.body())
                .as("the heredoc body is the program, so it must at least be the one described in the prose")
                .contains("byte[] fixed32(BigInteger value)")
                .contains("new ECGenParameterSpec(\"secp256r1\")")
                .contains("Base64.getUrlEncoder().withoutPadding()");
    }

    @Test
    void readmeSnippetPrintsAPairThatVapidKeysAndTheLocalSignerAccept(@TempDir Path workingDir) throws Exception {
        Snippet snippet = snippet();

        String printed = run(snippet, workingDir);

        String publicKey = capture(PUBLIC_KEY_LINE, printed, "public");
        String privateKey = capture(PRIVATE_KEY_LINE, printed, "private");

        VapidKeys keys = VapidKeys.fromBase64(publicKey, privateKey);
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

    /** The fenced block between the two anchors, split into the shell command and the heredoc body it is fed. */
    private record Snippet(List<String> command, String body) {}

    private static Snippet snippet() {
        List<String> block = fencedBlockBetweenAnchors(readme());

        if (block.size() < 3
                || !HEREDOC_OPEN.equals(block.get(0))
                || !HEREDOC_CLOSE.equals(block.get(block.size() - 1))) {
            return fail("The block between " + BEGIN_ANCHOR + " and " + END_ANCHOR + " in " + readme()
                    + " must open with \"" + HEREDOC_OPEN + "\" and close with \"" + HEREDOC_CLOSE
                    + "\". It opens with \"" + block.get(0) + "\" and closes with \""
                    + block.get(block.size() - 1) + "\".");
        }

        // The words before "<<" are the command the reader runs; taking them from the line rather than hard-coding
        // them means this test executes what the README says, not what it said when the test was written.
        String beforeHeredoc =
                HEREDOC_OPEN.substring(0, HEREDOC_OPEN.indexOf("<<")).trim();
        List<String> command = List.of(beforeHeredoc.split("\\s+"));

        String body = String.join("\n", block.subList(1, block.size() - 1)) + "\n";
        return new Snippet(command, body);
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

    /** Runs the snippet exactly as the README prescribes: the documented command, with the heredoc body on stdin. */
    private static String run(Snippet snippet, Path workingDir) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(snippet.command());
        command.set(0, jshell().toString());

        Path diagnostics = workingDir.resolve("jshell-stderr.txt");
        Process process = new ProcessBuilder(command)
                .directory(workingDir.toFile())
                // To a file rather than merged into stdout: the launcher's own chatter (JAVA_TOOL_OPTIONS notices and
                // the like) would otherwise land among the printed keys, and it is wanted verbatim in a failure.
                .redirectError(diagnostics.toFile())
                .start();

        try (OutputStream stdin = process.getOutputStream()) {
            stdin.write(snippet.body().getBytes(UTF_8));
        }
        String printed = new String(process.getInputStream().readAllBytes(), UTF_8);

        if (!process.waitFor(JSHELL_TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
            process.destroyForcibly();
            return fail("The README snippet did not finish within " + JSHELL_TIMEOUT_MINUTES + " minutes."
                    + diagnostics(printed, diagnostics));
        }
        if (process.exitValue() != 0) {
            return fail(
                    "The README snippet exited with " + process.exitValue() + "." + diagnostics(printed, diagnostics));
        }
        return printed;
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

    private static String capture(Pattern pattern, String printed, String label) {
        Matcher matcher = pattern.matcher(printed);
        if (!matcher.find()) {
            return fail("The README snippet printed no \"" + label + ":\" line.\nOutput was:\n" + printed);
        }
        return matcher.group(1);
    }

    private static String diagnostics(String printed, Path stderrFile) {
        String stderr;
        try {
            stderr = Files.exists(stderrFile) ? Files.readString(stderrFile, UTF_8) : "";
        } catch (IOException e) {
            stderr = "<unreadable: " + e + ">";
        }
        return "\nstdout:\n" + printed + "\nstderr:\n" + stderr;
    }
}
