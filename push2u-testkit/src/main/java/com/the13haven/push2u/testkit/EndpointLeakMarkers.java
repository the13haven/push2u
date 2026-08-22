/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u.testkit;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;

import com.the13haven.push2u.Endpoints;

/**
 * What the endpoint policy contract may search a refusal's reason for, taken apart from one refused endpoint: the
 * strings worth looking for, and — when the endpoint yields none below the URI as a whole — the account of why it
 * cannot be used as a witness at all.
 *
 * <p>A refused endpoint is a capability URL, so this is the one place in the kit that decides two things about it at
 * once. Which strings are searched for, since finding the wrong one convicts a policy that leaked nothing; and whether
 * the witness can support the check, since a witness with nothing distinctive in it would let a search report success
 * for a property it never tested.
 *
 * @param searchable every part of the endpoint long enough to mean something and absent from the redaction a conforming
 *     policy may print, the whole URI included
 * @param searchableComponents how many of those lie <em>below</em> the whole URI — a component, a path segment or a
 *     query value. The whole URI is deliberately left out of this count: every endpoint has one and it passes the
 *     fitness rule almost always, so counting it would let any endpoint at all satisfy the demand for something
 *     distinctive to look for, while a policy naming a single path segment went unnoticed
 * @param tooShort how many parts below the whole URI were dropped for being shorter than {@link #MARKER_MIN_LENGTH}
 * @param alreadyRedacted how many parts below the whole URI were dropped for occurring in the redaction of this very
 *     endpoint
 */
record EndpointLeakMarkers(List<Marker> searchable, int searchableComponents, int tooShort, int alreadyRedacted) {

    /**
     * How long a string taken out of the witness endpoint must be before a refusal's reason is searched for it.
     *
     * <p>The number balances two failures against each other. Too low and the check convicts correct policies: the
     * segments every endpoint carries — {@code v1}, {@code api}, {@code push} — say something about the wording of a
     * refusal and nothing about the endpoint, and a short run of characters can turn up inside an ordinary English
     * sentence by accident. Too high and a real credential goes unsearched. Sixteen is above every word an
     * operator-facing refusal is likely to contain — no word in the three refusals the standard allowlist writes runs
     * past eight characters — and far below the capability components real push services issue, which run to dozens or
     * hundreds of characters. It also sits at the length of the fingerprint {@link Endpoints#redact} prints, so nothing
     * shorter than the one endpoint-derived value a conforming policy may publish is ever hunted for.
     */
    static final int MARKER_MIN_LENGTH = 16;

    /**
     * Splits a raw path into its segments, and a raw query into its parameters. Precompiled patterns rather than
     * {@code String.split}, whose one-argument form silently drops trailing empty fields — a trailing separator would
     * then change which parts are searched for.
     */
    private static final Pattern PATH_SEPARATOR = Pattern.compile("/");

    /** The query's parameter separator; see {@link #PATH_SEPARATOR} for why it is a pattern. */
    private static final Pattern QUERY_SEPARATOR = Pattern.compile("&");

    /**
     * One string to look for, carrying where in the endpoint it came from and how it is spelled — so that a failure can
     * say what it found without printing it.
     *
     * @param value the text searched for
     * @param level where in the endpoint it came from
     * @param spelling how it is written, since a policy may render a component decoded
     */
    record Marker(String value, String level, String spelling) {}

    /**
     * Sorts every part of one refused endpoint into the strings worth searching for and the ones that would answer a
     * question about the policy's prose instead of about the endpoint.
     *
     * <p>The fitness rule is applied to each spelling separately, because a decoded form can collide with the redaction
     * where its raw form does not.
     */
    static EndpointLeakMarkers of(URI witness) {
        String redaction = Endpoints.redact(witness.toString());
        Set<String> seen = new LinkedHashSet<>();
        List<Marker> searchable = new ArrayList<>();
        for (Marker candidate : wholeUri(witness)) {
            if (seen.add(candidate.value()) && isFit(candidate.value(), redaction)) {
                searchable.add(candidate);
            }
        }

        int searchableComponents = 0;
        int tooShort = 0;
        int alreadyRedacted = 0;
        for (Marker candidate : components(witness)) {
            if (!seen.add(candidate.value())) {
                continue;
            }
            if (candidate.value().length() < MARKER_MIN_LENGTH) {
                tooShort++;
            } else if (redaction.contains(candidate.value())) {
                alreadyRedacted++;
            } else {
                searchable.add(candidate);
                searchableComponents++;
            }
        }
        return new EndpointLeakMarkers(List.copyOf(searchable), searchableComponents, tooShort, alreadyRedacted);
    }

    /** Whether the witness carries anything distinctive below the whole URI, which is what makes it usable. */
    boolean hasSearchableComponent() {
        return searchableComponents > 0;
    }

    /**
     * Why this witness cannot be searched against, naming the half (or halves) of the fitness rule its parts failed.
     * The parts themselves are deliberately not printed: a witness may well be a real endpoint out of a real store, and
     * this message goes to the same log everything else in a failing build goes to.
     */
    String unfitWitnessMessage() {
        List<String> halves = new ArrayList<>(2);
        if (tooShort > 0) {
            halves.add(tooShort + " of them are shorter than " + MARKER_MIN_LENGTH
                    + " characters, which is too short to tell a leaked credential apart from the ordinary words of a "
                    + "refusal");
        }
        if (alreadyRedacted > 0) {
            halves.add(alreadyRedacted
                    + " of them already occur in the rendering a conforming policy is entitled to print for this "
                    + "endpoint — its origin and a sixteen-character fingerprint — where finding one would convict a "
                    + "policy that leaked nothing");
        }
        if (halves.isEmpty()) {
            halves.add("it has no path, query or fragment at all");
        }
        return "refusedEndpoint() is unfit for this check, which is a problem with the fixture and not with the "
                + "policy: nothing in that endpoint below the URI as a whole can be searched for, because "
                + String.join(" and ", halves)
                + ". Supply an endpoint carrying a capability-shaped path segment or query value, like the ones a real "
                + "subscription store holds. An endpoint with nothing distinctive under its origin leaves this check "
                + "searching for the whole URI and nothing else, which a policy naming one path segment — the whole of "
                + "the credential, in the spelling a policy is most likely to write — passes without difficulty. The "
                + "parts are not named here: a witness may be a real endpoint, and a capability URL must not travel "
                + "into a log.";
    }

    /** What a leaking refusal is told, in terms of where the match came from rather than of what it was. */
    static String leakMessage(Marker leaked) {
        return "a refusal's reason must not carry the capability part of the endpoint, and this one does: it contains "
                + leaked.level() + " of the refused endpoint, " + leaked.spelling() + ". A push endpoint is a "
                + "capability URL — whoever reads that line can message the subscriber — and a refusal's reason "
                + "travels, onto the outcome the send hands back and from there into an application's logs. Render "
                + "the endpoint with the library's own redaction, which keeps its origin and a fingerprint and drops "
                + "the rest, and say what your rule objected to beside it. The matched text is deliberately not "
                + "printed here: this message goes into a build log like every other failure, and you have the "
                + "fixture and your policy's source in front of you.";
    }

    /**
     * Whether one string may be searched for: long enough that finding it in a sentence about an endpoint means
     * something, and absent from the rendering a conforming policy is entitled to print for that same endpoint.
     */
    private static boolean isFit(String candidate, String redaction) {
        return candidate.length() >= MARKER_MIN_LENGTH && !redaction.contains(candidate);
    }

    /** The coarsest granularity: the endpoint as one string, which catches a policy quoting it whole. */
    private static List<Marker> wholeUri(URI witness) {
        List<Marker> markers = new ArrayList<>(2);
        addSpellings(markers, witness.toString(), "the whole URI", false);
        return markers;
    }

    /**
     * Everything below the whole URI, at the two granularities a leak really happens at: each component that can carry
     * the credential entire, and each path segment and each query value on its own. A policy naming one segment has
     * published the whole credential while its sentence holds neither the URI nor the path.
     */
    private static List<Marker> components(URI witness) {
        List<Marker> markers = new ArrayList<>();
        addSpellings(markers, witness.getRawUserInfo(), "the user-info component", false);
        addSpellings(markers, witness.getRawPath(), "the path component", false);
        addSpellings(markers, witness.getRawQuery(), "the query component", false);
        addSpellings(markers, witness.getRawFragment(), "the fragment component", false);

        String path = witness.getRawPath();
        if (path != null) {
            for (String segment : PATH_SEPARATOR.split(path, -1)) {
                addSpellings(markers, segment, "one path segment", false);
            }
        }
        String query = witness.getRawQuery();
        if (query != null) {
            for (String parameter : QUERY_SEPARATOR.split(query, -1)) {
                int assignment = parameter.indexOf('=');
                String value = assignment < 0 ? parameter : parameter.substring(assignment + 1);
                addSpellings(markers, value, "one query value", true);
            }
        }
        return markers;
    }

    /**
     * Adds one part in each spelling a policy might write it in, skipping what has no content — an empty query or a
     * bare path names nothing, and searching for it would match every reason ever written.
     *
     * <p>A query value takes a third spelling. In a form-encoded query {@code +} means a space, so a policy rendering a
     * value with a form decoder prints a space where the endpoint carries a plus — and a standard-alphabet base64
     * token, which is what several push services put in a query, is full of them.
     */
    private static void addSpellings(List<Marker> markers, @Nullable String raw, String level, boolean formEncoded) {
        if (raw == null || raw.isEmpty()) {
            return;
        }
        markers.add(new Marker(raw, level, "raw, as the endpoint carries it"));
        String percentDecoded = percentDecoded(raw);
        if (!percentDecoded.equals(raw)) {
            markers.add(new Marker(percentDecoded, level, "percent-decoded"));
        }
        if (formEncoded) {
            String formDecoded = formDecoded(raw);
            if (!formDecoded.equals(raw) && !formDecoded.equals(percentDecoded)) {
                markers.add(new Marker(formDecoded, level, "form-decoded, with + read as a space"));
            }
        }
    }

    /**
     * The percent-decoded spelling of one part of a URI: the plain decoding of {@code %XX} escapes, which is what every
     * URI component accessor that decodes performs.
     *
     * <p>{@code +} is protected before decoding because it means a space only in a form-encoded query and stands for
     * itself everywhere else in a URI — a path segment carrying one is ordinary, and turning it into a space would
     * search for a string no policy could ever print. A part that is not valid percent-encoding is left as it is: this
     * is a fixture being read, not input being validated.
     */
    private static String percentDecoded(String raw) {
        try {
            return URLDecoder.decode(raw.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException notPercentEncoded) {
            return raw;
        }
    }

    /** The form-decoded spelling, {@code +} read as a space; see {@link #addSpellings} for where that can be right. */
    private static String formDecoded(String raw) {
        try {
            return URLDecoder.decode(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException notPercentEncoded) {
            return raw;
        }
    }
}
