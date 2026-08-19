/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.signer.vault;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A healthy in-memory Transit engine behind the {@link VaultHttpTransport} seam: it holds a real P-256 key pair,
 * answers the {@code transit/keys/<name>} GET with that key's metadata, and answers the {@code sign} POST with a real
 * ES256 signature over the request's {@code input} — so everything downstream (the signer's validation, the health
 * probe's local verification) exercises genuine cryptography with no network and no container. Shared as a test fixture
 * between this module's tests and the Vault starter's, which need a Vault that works without Docker.
 *
 * <p>Every call is recorded in order ({@code "GET <uri>"} / {@code "POST <uri>"}), which is what lets a test assert not
 * only how many reads happened but when — a deferred signer proves itself by the calls that did <em>not</em> happen at
 * construction. Thread-safe: concurrent senders are the normal case for everything holding a signer.
 */
public final class FakeTransitVault implements VaultHttpTransport {

    private final int latestVersion;
    private final KeyPair keyPair;
    private final List<String> calls = new CopyOnWriteArrayList<>();

    /** A Transit key at version 1. */
    public FakeTransitVault() {
        this(1);
    }

    /**
     * A Transit key whose {@code latest_version} is the given one.
     *
     * @param latestVersion the version the metadata read advertises and the sign envelope echoes
     */
    public FakeTransitVault(int latestVersion) {
        this.latestVersion = latestVersion;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            this.keyPair = generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("this JVM cannot generate a P-256 key pair", e);
        }
    }

    /**
     * The key's public half as the 65-byte uncompressed point — what a correctly fetching signer must advertise.
     *
     * @return the uncompressed point, a fresh copy
     */
    public byte[] publicKeyUncompressed() {
        return uncompressedPoint((ECPublicKey) keyPair.getPublic());
    }

    /**
     * Every call this transport served, in order, as {@code "GET <uri>"} / {@code "POST <uri>"}.
     *
     * @return the recorded calls
     */
    public List<String> calls() {
        return Collections.unmodifiableList(calls);
    }

    /**
     * How many {@code transit/keys} metadata reads were served.
     *
     * @return the GET count
     */
    public long keyReads() {
        return calls.stream().filter(call -> call.startsWith("GET ")).count();
    }

    /**
     * How many {@code sign} requests were served.
     *
     * @return the POST count
     */
    public long signs() {
        return calls.stream().filter(call -> call.startsWith("POST ")).count();
    }

    @Override
    public VaultHttpResponse get(URI uri, Map<String, String> headers) {
        calls.add("GET " + uri);
        String pem = "-----BEGIN PUBLIC KEY-----"
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
                + "-----END PUBLIC KEY-----";
        return new VaultHttpResponse(
                200,
                "{\"data\":{\"type\":\"ecdsa-p256\",\"latest_version\":" + latestVersion + ",\"keys\":{\""
                        + latestVersion + "\":{\"public_key\":\"" + pem + "\"}}}}");
    }

    @Override
    public VaultHttpResponse post(URI uri, Map<String, String> headers, byte[] body) {
        calls.add("POST " + uri);
        String request = new String(body, StandardCharsets.UTF_8);
        byte[] signingInput = Base64.getDecoder().decode(jsonStringValue(request, "input"));
        String envelopeVersion = requestedVersion(request);
        try {
            Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
            signer.initSign(keyPair.getPrivate());
            signer.update(signingInput);
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
            return new VaultHttpResponse(
                    200, "{\"data\":{\"signature\":\"vault:v" + envelopeVersion + ":" + signature + "\"}}");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("this JVM cannot produce an ES256 signature", e);
        }
    }

    /** The version the request pinned, or this key's latest where it pinned none — what real Vault signs with. */
    private String requestedVersion(String request) {
        int label = request.indexOf("\"key_version\":");
        if (label < 0) {
            return Integer.toString(latestVersion);
        }
        int start = label + "\"key_version\":".length();
        int end = start;
        while (end < request.length() && Character.isDigit(request.charAt(end))) {
            end++;
        }
        return request.substring(start, end);
    }

    /** The string value of {@code "name":"..."} in a request this fixture itself shaped — not a general parser. */
    private static String jsonStringValue(String json, String name) {
        String label = "\"" + name + "\":\"";
        int start = json.indexOf(label);
        if (start < 0) {
            throw new IllegalArgumentException("request carries no '" + name + "' string");
        }
        start += label.length();
        int end = json.indexOf('"', start);
        if (end < 0) {
            throw new IllegalArgumentException("request's '" + name + "' string is unterminated");
        }
        return json.substring(start, end);
    }

    private static byte[] uncompressedPoint(ECPublicKey key) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        writeFixed32(key.getW().getAffineX(), out, 1);
        writeFixed32(key.getW().getAffineY(), out, 33);
        return out;
    }

    private static void writeFixed32(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        int start = bytes.length > 32 ? bytes.length - 32 : 0;
        int length = bytes.length - start;
        System.arraycopy(bytes, start, out, offset + 32 - length, length);
    }
}
