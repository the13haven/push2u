/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The minimal HTTP/1.1 the transport contract's harness speaks: reading one request exactly as the wire carried it, and
 * composing one response as exactly the bytes a check wants. Package-private machinery of
 * {@link PushHttpClientContractTest}, split from the socket handling so each half stays small enough to read whole.
 *
 * <p>Minimal on purpose, and by hand on purpose: the wire is what the contract is about, and a server library that
 * parses the request into an object, decides the framing and manages the connection would be a layer whose behaviour
 * becomes part of what every check asserts. What this reader owes so that the contract measures the transport rather
 * than one HTTP stack: both {@code Content-Length} and chunked request bodies are read, since a transport may frame the
 * body either way and both are correct HTTP; and header names are stored for case-insensitive lookup, as HTTP requires.
 */
final class TransportContractHttp {

    /** A bound on any single line, so a runaway peer fails the read instead of growing it. */
    private static final int MAX_LINE_BYTES = 64 * 1024;

    /** Room for the status line and the framing headers of a typical harness response. */
    private static final int TYPICAL_RESPONSE_HEAD = 256;

    private TransportContractHttp() {}

    /**
     * Composes one complete HTTP/1.1 response: the status line, the given headers, then {@code Content-Length: 0} and
     * {@code Connection: close} — every harness response closes the connection, so connection reuse never becomes part
     * of what a check asserts, and carries no body, because the seam never reads one.
     */
    static byte[] response(int statusCode, Map<String, String> headers) {
        StringBuilder response = new StringBuilder(TYPICAL_RESPONSE_HEAD)
                .append("HTTP/1.1 ")
                .append(statusCode)
                .append(" Contract\r\n");
        headers.forEach((name, value) ->
                response.append(name).append(": ").append(value).append("\r\n"));
        response.append("Content-Length: 0\r\nConnection: close\r\n\r\n");
        return response.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Reads one request off the wire: request line, headers, then the body in whichever framing was used. */
    static TransportContractServer.ReceivedRequest parse(InputStream in) throws IOException {
        String requestLine = readLine(in);
        int firstSpace = requestLine.indexOf(' ');
        int lastSpace = requestLine.lastIndexOf(' ');
        if (firstSpace < 0 || lastSpace <= firstSpace) {
            throw new IOException("malformed request line");
        }
        String method = requestLine.substring(0, firstSpace);
        String target = requestLine.substring(firstSpace + 1, lastSpace);

        Map<String, String> headers = new LinkedHashMap<>();
        String headerLine = readLine(in);
        while (!headerLine.isEmpty()) {
            int colon = headerLine.indexOf(':');
            if (colon < 0) {
                throw new IOException("malformed header line");
            }
            // Names lower-cased for the case-insensitive lookup HTTP requires; a repeated header
            // joins its values with a comma, which is the meaning a repeat has on the wire.
            headers.merge(
                    headerLine.substring(0, colon).strip().toLowerCase(Locale.ROOT),
                    headerLine.substring(colon + 1).strip(),
                    (first, second) -> first + ", " + second);
            headerLine = readLine(in);
        }

        return new TransportContractServer.ReceivedRequest(method, target, headers, readBody(in, headers));
    }

    /**
     * The request body in whichever of the two correct framings the transport chose: chunked when declared, else
     * exactly {@code Content-Length} bytes, else empty. A body cut short by the peer is an {@link EOFException} rather
     * than a truncated recording — a check comparing bytes must never compare against a partial read.
     */
    private static byte[] readBody(InputStream in, Map<String, String> headers) throws IOException {
        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null
                && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked")) {
            return readChunked(in);
        }
        String contentLength = headers.get("content-length");
        if (contentLength == null) {
            return new byte[0];
        }
        int declared;
        try {
            declared = Integer.parseInt(contentLength);
        } catch (NumberFormatException notANumber) {
            throw new IOException("unreadable Content-Length", notANumber);
        }
        if (declared < 0) {
            // A negative count is the same defect on the wire as an unreadable one and leaves by the
            // same door: reading that many bytes is refused with an IllegalArgumentException, which
            // the listener's handler does not catch, so it would surface as an uncaught exception on
            // the exchange's own thread instead of as a connection that carried no request.
            throw new IOException("unreadable Content-Length");
        }
        byte[] body = in.readNBytes(declared);
        if (body.length != declared) {
            throw new EOFException("connection ended inside the request body");
        }
        return body;
    }

    /** A chunked body: size-prefixed chunks until the zero chunk, then any trailers up to the final blank line. */
    private static byte[] readChunked(InputStream in) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int size = readChunkSize(in);
        while (size > 0) {
            byte[] chunk = in.readNBytes(size);
            if (chunk.length != size) {
                throw new EOFException("connection ended inside a chunk");
            }
            body.write(chunk);
            if (!readLine(in).isEmpty()) {
                throw new IOException("a chunk was not followed by its CRLF");
            }
            size = readChunkSize(in);
        }
        String trailer = readLine(in);
        while (!trailer.isEmpty()) {
            trailer = readLine(in);
        }
        return body.toByteArray();
    }

    /** One chunk-size line: hexadecimal size, any chunk extension after {@code ;} ignored. */
    private static int readChunkSize(InputStream in) throws IOException {
        String line = readLine(in);
        int extension = line.indexOf(';');
        String hex = (extension < 0 ? line : line.substring(0, extension)).strip();
        int size;
        try {
            size = Integer.parseInt(hex, 16);
        } catch (NumberFormatException notANumber) {
            throw new IOException("unreadable chunk size", notANumber);
        }
        if (size < 0) {
            // A size line is hexadecimal and has no sign, so a negative one is not a short body but
            // an unreadable line: ending the body on it would answer the caller with a recording of
            // fewer bytes than arrived, which is the one thing this reader must never do.
            throw new IOException("unreadable chunk size");
        }
        return size;
    }

    /** One CRLF-terminated line, without its terminator. Bounded, and EOF inside a line fails the read. */
    private static String readLine(InputStream in) throws IOException {
        StringBuilder line = new StringBuilder();
        int next = in.read();
        while (next >= 0) {
            if (next == '\n') {
                int length = line.length();
                if (length > 0 && line.charAt(length - 1) == '\r') {
                    line.setLength(length - 1);
                }
                return line.toString();
            }
            line.append((char) next);
            if (line.length() > MAX_LINE_BYTES) {
                throw new IOException("a line exceeded the harness's bound");
            }
            next = in.read();
        }
        throw new EOFException("connection ended inside a line");
    }
}
