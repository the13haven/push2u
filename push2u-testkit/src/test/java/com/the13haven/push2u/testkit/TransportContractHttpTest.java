/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The harness's wire reader, pinned on the bytes it is given rather than on the one client that reaches it through a
 * socket. {@link PushHttpClientContractSelfTest} drives the whole harness end to end, but it can only drive it with the
 * requests the JDK's client chooses to send — one framing per subject, one header spelling, never a trailer, never a
 * chunk extension, and never a request cut off midway. The contract this reader serves is pointed at transports nobody
 * here has seen, so what the JDK client happens not to emit is exactly the untested part.
 *
 * <p>Its two failure modes are not symmetrical, and the checks below are grouped by which one they guard.
 *
 * <p>A reader that <em>records less than arrived</em> makes the contract pass a transport it should have failed: the
 * byte-for-byte check compares what it was handed against a truncated recording, and the two disagree loudly or agree
 * by accident, but in neither case is the transport what was measured. So every way a request can end early is asserted
 * to fail the read rather than to yield a short body — the reader's own documented promise.
 *
 * <p>A reader that <em>refuses legal HTTP</em> makes the contract fail a transport that was right: the implementor gets
 * a body mismatch or a missing header in a kit they had every reason to trust, in code they cannot see, over a framing
 * choice that was theirs to make. So the spellings a transport is entitled to use — either framing, chunk extensions,
 * trailers, a repeated header, any case — are asserted to reach the recording unchanged.
 */
final class TransportContractHttpTest {

    // ---------------------------------------------------------------------------------------------------------------
    // Legal HTTP a transport may send: every one of these must reach the recording intact.
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * The reader's central promise, asserted as an equality between the two framings rather than as two separate
     * expectations: a transport frames its body as it likes, and the recording the contract compares against must not
     * carry a trace of which way it chose. The payload runs over every byte value, because the request line and the
     * headers are read a character at a time and a body read the same way would mangle exactly these bytes.
     */
    @Test
    void bothFramingsOfOneBodyAreRecordedAsTheSameBytes() throws IOException {
        byte[] payload = everyByteValue();

        byte[] underContentLength = new Wire()
                .text("POST /push HTTP/1.1\r\nHost: harness\r\nContent-Length: " + payload.length + "\r\n\r\n")
                .raw(payload)
                .parse()
                .body();

        byte[] underChunkedFraming = new Wire()
                .text("POST /push HTTP/1.1\r\nHost: harness\r\nTransfer-Encoding: chunked\r\n\r\n")
                .text("100\r\n")
                .raw(payload)
                .text("\r\n0\r\n\r\n")
                .parse()
                .body();

        assertThat(underContentLength).isEqualTo(payload);
        assertThat(underChunkedFraming)
                .as("the framing a transport chose leaves no trace in what was recorded")
                .isEqualTo(underContentLength);
    }

    /**
     * The parts of a chunked body that carry no payload: the size line's extension after {@code ;}, the several chunks
     * a streaming publisher produces, and the trailer section a transport may append. All three are ordinary HTTP that
     * the JDK client never emits, and a reader that folded any of them into the body would hand the contract a body
     * mismatch against a transport that did nothing wrong. The transfer coding is spelled {@code Chunked} here because
     * the token is case-insensitive and a reader matching it literally would fall through to the empty body.
     */
    @Test
    void chunkExtensionsAndTrailersLeaveOnlyThePayloadInTheBody() throws IOException {
        byte[] body = new Wire()
                .text("POST /push HTTP/1.1\r\nHost: harness\r\nTransfer-Encoding: Chunked\r\n\r\n")
                .text("5;ext=first\r\nHello\r\n")
                .text("6\r\n, wire\r\n")
                .text("0\r\n")
                .text("X-Trailer: after the last chunk\r\nX-Another: and one more\r\n\r\n")
                .parse()
                .body();

        assertThat(new String(body, StandardCharsets.ISO_8859_1)).isEqualTo("Hello, wire");
    }

    /**
     * The framing is decided by the coding a transport named, not by the header having been sent. A transport that
     * applies a coding to a body it still frames by length would otherwise have its {@code Content-Length} ignored and
     * its first byte read as a chunk size — a body mismatch reported against a request that was well formed.
     */
    @Test
    void aTransferCodingThatIsNotChunkedLeavesTheBodyFramedByItsLength() throws IOException {
        byte[] body = new Wire()
                .text("POST /push HTTP/1.1\r\nHost: harness\r\n")
                .text("Transfer-Encoding: gzip\r\nContent-Length: 11\r\n\r\n")
                .text("Hello, wire")
                .parse()
                .body();

        assertThat(new String(body, StandardCharsets.ISO_8859_1)).isEqualTo("Hello, wire");
    }

    /**
     * A header sent twice means one field whose values are joined by a comma, and the contract's checks look up what
     * they gave the transport by name. A reader keeping only the first or only the last would report a header absent
     * that the transport did send, or present with a value it never sent — a verdict about the transport drawn from the
     * reader's own choice.
     */
    @Test
    void aRepeatedHeaderIsRecordedAsItsValuesJoined() throws IOException {
        TransportContractServer.ReceivedRequest request = new Wire()
                .text("POST /push HTTP/1.1\r\nHost: harness\r\n")
                .text("X-Repeated: first\r\nX-Repeated: second\r\nContent-Length: 0\r\n\r\n")
                .parse();

        assertThat(request.header("X-Repeated")).contains("first, second");
    }

    /**
     * Case and surrounding space are the sender's business and not part of what a header says. The contract asserts the
     * presence of headers it handed over, so a reader that matched the spelling it happened to receive would turn a
     * transport's ordinary normalisation — or its absence — into a contract failure.
     */
    @Test
    void aHeaderIsFoundWhateverCaseEitherSideSpelledItIn() throws IOException {
        TransportContractServer.ReceivedRequest request = new Wire()
                .text("POST /push HTTP/1.1\r\nHost: harness\r\n")
                .text("CoNtEnT-EnCoDiNg:   aes128gcm   \r\nContent-Length: 0\r\n\r\n")
                .parse();

        assertThat(request.header("content-encoding")).contains("aes128gcm");
        assertThat(request.header("Content-Encoding")).contains("aes128gcm");
        assertThat(request.header("X-Never-Sent")).isEmpty();
    }

    /**
     * The request line as the wire carried it, kept whole. The target is everything between the first and the last
     * space, so a query string reaches the recording intact and a version token is not mistaken for part of it — the
     * checks assert over the target the harness itself handed out.
     */
    @Test
    void theMethodAndTheRequestTargetAreRecordedAsTheyWereSent() throws IOException {
        TransportContractServer.ReceivedRequest request = new Wire()
                .text("POST /push/sub?ttl=60&x=1 HTTP/1.1\r\nHost: harness\r\nContent-Length: 0\r\n\r\n")
                .parse();

        assertThat(request.method()).isEqualTo("POST");
        assertThat(request.target()).isEqualTo("/push/sub?ttl=60&x=1");
    }

    /**
     * A request that frames no body at all — which a transport is free to send for an empty payload — is read as an
     * empty body and nothing else. A reader waiting for a body it was never promised would hold the connection until
     * the contract's budget expired, and the check would abort with no verdict at all; so what is asserted here is not
     * only the empty recording but that the reader stopped exactly at the blank line and consumed none of what
     * followed.
     */
    @Test
    @Timeout(10)
    void aRequestFramingNoBodyIsReadAsAnEmptyOneAndNothingAfterItIsConsumed() throws IOException {
        ByteArrayInputStream wire =
                new Wire().text("POST /push HTTP/1.1\r\nHost: harness\r\n\r\nnot part of this request").stream();

        TransportContractServer.ReceivedRequest request = TransportContractHttp.parse(wire);

        assertThat(request.body()).isEmpty();
        assertThat(new String(wire.readAllBytes(), StandardCharsets.ISO_8859_1))
                .as("the reader stopped at the blank line")
                .isEqualTo("not part of this request");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // A request that ended early: every one of these must fail the read rather than yield a short recording.
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * The truncation that would be invisible: a body cut short under {@code Content-Length} recorded as the bytes that
     * did arrive. The contract's fidelity check would then compare a transport's request against a prefix of itself,
     * and a transport whose body was corrupted downstream of the point that matters could pass on the agreement of two
     * equally wrong recordings.
     */
    @Test
    void aBodyCutShortUnderContentLengthFailsTheReadRatherThanRecordingWhatArrived() {
        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nContent-Length: 32\r\n\r\n")
                        .text("only eleven")
                        .parse())
                .isInstanceOf(EOFException.class);
    }

    /**
     * The same truncation under the other framing, where the count that is short is a chunk's rather than the body's.
     */
    @Test
    void aChunkedBodyCutShortFailsTheReadRatherThanRecordingWhatArrived() {
        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .text("20\r\nonly eleven")
                        .parse())
                .isInstanceOf(EOFException.class);
    }

    /**
     * A chunk running into the next size line instead of ending at its declared length. Nothing is missing from the
     * stream here, which is what makes it worth its own check: the framing is wrong rather than incomplete, and a
     * reader taking the next size line's bytes as payload would record a body that never was.
     */
    @Test
    void aChunkNotClosedByItsOwnCrlfFailsTheRead() {
        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .text("5\r\nHelloTHIS IS NOT A CRLF\r\n0\r\n\r\n")
                        .parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("CRLF");
    }

    /**
     * A length that is not a number, and one that is negative. Both are the same defect on the wire and must leave by
     * the same door: the handler thread that calls this reader catches {@link IOException} and nothing else, so a
     * number the parser rejects some other way escapes as an uncaught exception on a daemon thread — a stack trace from
     * the kit's own internals in an implementor's build, while the check that was running waits out its budget and
     * aborts without a verdict.
     */
    @Test
    void aContentLengthThatIsNotAReadableCountFailsTheReadAsAnIoFailure() {
        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nContent-Length: not-a-number\r\n\r\n")
                        .parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Content-Length");

        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nContent-Length: -32\r\n\r\n")
                        .parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Content-Length");
    }

    /**
     * The same for a chunk size, which is hexadecimal, carries no sign and can overflow the count the reader can hold.
     * The negative spelling is the one that matters most: it parses, and a body ended on it would be recorded as fewer
     * bytes than arrived while the read reported success — the silent truncation the checks above exist to prevent,
     * arriving through the door marked well-formed.
     */
    @Test
    void aChunkSizeThatIsNotAReadableCountFailsTheReadAsAnIoFailure() {
        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .text("zz\r\n")
                        .parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("chunk size");

        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .text("FFFFFFFFFF\r\n")
                        .parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("chunk size");

        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .text("-5\r\nHello\r\n0\r\n\r\n")
                        .parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("chunk size");
    }

    /** A request line without its version: two of the three tokens the line is made of, and no target to record. */
    @Test
    void aRequestLineMissingATokenFailsTheRead() {
        assertThatThrownBy(() -> new Wire().text("POST\r\n\r\n").parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("request line");

        assertThatThrownBy(() -> new Wire().text("POST /push\r\n\r\n").parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("request line");
    }

    /** A header line with no colon: a name with no value, which would otherwise be recorded as a header of neither. */
    @Test
    void aHeaderLineWithoutItsColonFailsTheRead() {
        assertThatThrownBy(() -> new Wire()
                        .text("POST /push HTTP/1.1\r\nHost: harness\r\nX-No-Colon\r\n\r\n")
                        .parse())
                .isInstanceOf(IOException.class)
                .hasMessageContaining("header line");
    }

    /**
     * A peer that goes away mid-line — a handshake probe, a client that changed its mind — ends the read, not a wait.
     */
    @Test
    @Timeout(10)
    void aConnectionEndingInsideALineFailsTheRead() {
        assertThatThrownBy(() ->
                        new Wire().text("POST /push HTTP/1.1\r\nHost: har").parse())
                .isInstanceOf(EOFException.class);
    }

    /**
     * The bound on a line, asserted against a peer that never ends one rather than against a fixture of some chosen
     * size — a fixture proves only that the reader rejects that size, and would pass just as well against a reader
     * bounded ten times higher or bounded by the heap. The stream stops far past the reader's own bound so that a
     * regression fails this check with its own message instead of taking the test JVM down with it.
     */
    @Test
    @Timeout(30)
    void aLineThatNeverEndsFailsTheReadRatherThanGrowingWithoutBound() {
        assertThatThrownBy(() -> TransportContractHttp.parse(new EndlessLine()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exceeded the harness's bound");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The response the harness composes.
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * The bytes a check gets to choose and the bytes it does not. The status line and the given headers are the check's
     * own statement; the two framing headers are the harness's, and they are what keeps connection reuse and response
     * bodies from becoming part of what any check asserts. Composed as one string here because that is how a regression
     * would present itself — a missing blank line, a header run together with the next.
     */
    @Test
    void aResponseCarriesItsStatusLineTheGivenHeadersAndTheFramingTheHarnessAlwaysAdds() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Location", "https://elsewhere.example/push");
        headers.put("Retry-After", "120");

        String response = new String(TransportContractHttp.response(301, headers), StandardCharsets.ISO_8859_1);

        assertThat(response)
                .isEqualTo("HTTP/1.1 301 Contract\r\n"
                        + "Location: https://elsewhere.example/push\r\n"
                        + "Retry-After: 120\r\n"
                        + "Content-Length: 0\r\n"
                        + "Connection: close\r\n"
                        + "\r\n");
    }

    /** A response with nothing of its own is still a complete one, which is the shape most of the checks use. */
    @Test
    void aResponseWithNoHeadersOfItsOwnIsStillComplete() {
        String response = new String(TransportContractHttp.response(201, Map.of()), StandardCharsets.ISO_8859_1);

        assertThat(response).isEqualTo("HTTP/1.1 201 Contract\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }

    /** Every byte value once, as a body: the payload a character-oriented read would not survive. */
    private static byte[] everyByteValue() {
        byte[] values = new byte[256];
        for (int value = 0; value < values.length; value++) {
            values[value] = (byte) value;
        }
        return values;
    }

    /** One request under construction, mixing wire text with raw body bytes the way a real exchange does. */
    private static final class Wire {

        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        Wire text(String wireText) {
            bytes.writeBytes(wireText.getBytes(StandardCharsets.ISO_8859_1));
            return this;
        }

        Wire raw(byte[] payload) {
            bytes.writeBytes(payload);
            return this;
        }

        ByteArrayInputStream stream() {
            return new ByteArrayInputStream(bytes.toByteArray());
        }

        TransportContractServer.ReceivedRequest parse() throws IOException {
            return TransportContractHttp.parse(stream());
        }
    }

    /**
     * A peer whose first line never ends. It stops delivering far past the reader's own bound and well short of what
     * would exhaust the test JVM, so a reader that lost its bound fails here by assertion rather than by
     * {@link OutOfMemoryError}.
     */
    private static final class EndlessLine extends InputStream {

        private static final int CEILING = 8 * 1024 * 1024;

        private int delivered;

        @Override
        public int read() throws IOException {
            delivered++;
            if (delivered > CEILING) {
                throw new IOException("the reader took " + CEILING + " bytes of one line and was still reading");
            }
            return 'a';
        }
    }
}
