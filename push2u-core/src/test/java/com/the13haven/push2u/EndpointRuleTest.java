/*
 * Copyright 2026 The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link EndpointRule}, grouped by what each group is defending.
 *
 * <p><b>Origin parity</b> replays every construction refusal {@code EndpointPoliciesTest} pins for
 * {@code allowedOrigins} directly against {@link EndpointRule#origin}, with the same exception type in the same order,
 * because that factory is now nothing but a mapping onto this rule and ADR-017 froze its behaviour.
 *
 * <p><b>The wildcard group</b> pins the one refusal ADR-017 changed on purpose: an origin entry with a {@code *} where
 * a host label belongs is told about the domain rule, while an entry with a {@code *} anywhere else keeps the advice it
 * had, which is the correct advice for it.
 *
 * <p><b>The domain groups</b> pin acceptance and normalization, one test per refusal message, and the rendering rule —
 * a domain entry reaches a message only when it is a plain host-shaped token.
 *
 * <p><b>The last group is named for the bad outcome being impossible</b>, which is why the feature exists at all: a
 * domain rule matches at a DNS label boundary, over https, on the default port, and nothing else.
 */
class EndpointRuleTest {

    // ---------------------------------------------------------------- origin parity

    @Test
    void originAcceptsABareHttpsOriginAndNormalizesIt() {
        assertThat(EndpointRule.origin("https://PUSH.Example:443/"))
                .isEqualTo(EndpointRule.origin("https://push.example"));
        assertThat(EndpointRule.origin("https://push.example:8443"))
                .hasToString("EndpointRule.origin(https://push.example:8443)");
    }

    @Test
    void originRejectsAnUnparseableEntryWithoutEchoingIt() {
        assertThatThrownBy(() -> EndpointRule.origin("https://push example/secret-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a valid URI")
                .hasMessageNotContaining("secret-token")
                .hasNoCause();
    }

    @Test
    void originRejectsANonHttpsEntry() {
        assertThatThrownBy(() -> EndpointRule.origin("http://push.example"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be https");
    }

    @Test
    void originRejectsAHostlessEntry() {
        assertThatThrownBy(() -> EndpointRule.origin("https://exa_mple.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no host");
    }

    @Test
    void originRejectsARawUnicodeHostAndKeepsTheALabelAdvice() {
        assertThatThrownBy(() -> EndpointRule.origin("https://пример.испытание"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("A-label");
    }

    @Test
    void originRejectsAPastedEndpointUrlWithoutEchoingIt() {
        assertThatThrownBy(() -> EndpointRule.origin("https://push.example/send/secret-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bare scheme://host[:port]")
                .hasMessageNotContaining("secret-token");
    }

    @Test
    void originRejectsQueryFragmentAndUserinfoEntries() {
        assertThatThrownBy(() -> EndpointRule.origin("https://push.example?tenant=1"))
                .as("query")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EndpointRule.origin("https://push.example#frag"))
                .as("fragment")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EndpointRule.origin("https://user:pass@push.example"))
                .as("userinfo")
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void originRejectsNull() {
        assertThatThrownBy(() -> EndpointRule.origin(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void originChecksTheSchemeBeforeTheHost() {
        // The order of the checks is frozen along with the behaviour: an http entry that ALSO has
        // no host must still be told "must be https", which is the first thing wrong with it.
        assertThatThrownBy(() -> EndpointRule.origin("http://exa_mple.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be https");
    }

    // ---------------------------------------------------------------- the wildcard group

    @Test
    void originSendsAWildcardInTheHostPositionToTheDomainRule() {
        for (String entry : new String[] {
            "https://*.notify.windows.com",
            "https://*",
            "https://*.com",
            "https://wns2-*.notify.windows.com",
            "https://*.example.com:8443",
            "https://user@*.example.com"
        }) {
            assertThatThrownBy(() -> EndpointRule.origin(entry))
                    .as("%s", entry)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("EndpointRule.domain")
                    .hasMessageNotContaining("A-label");
        }
    }

    @Test
    void originKeepsTheBareOriginAdviceForAWildcardOutsideTheHostPosition() {
        // java.net.URI finds a real host in all three, so they are already refused for being more
        // than a bare origin — which is the right thing to tell whoever wrote them. A check firing
        // on a '*' anywhere would capture them and send their author to the domain rule instead.
        for (String entry :
                new String[] {"https://example.com/*", "https://a*b@example.com", "https://*@example.com"}) {
            assertThatThrownBy(() -> EndpointRule.origin(entry))
                    .as("%s", entry)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("bare scheme://host[:port]")
                    .hasMessageNotContaining("EndpointRule.domain");
        }
    }

    @Test
    void originSendsAPercentEncodedWildcardToTheDomainRuleToo() {
        // The host position is read off the DECODED authority, so "%2A" is diagnosed as the
        // wildcard it is rather than as a host the parser could not read. Both spellings are
        // refused either way — this only decides which refusal the author is handed — but the
        // decoded one is the better diagnosis, and it is a choice rather than an accident.
        assertThatThrownBy(() -> EndpointRule.origin("https://%2A.notify.windows.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("EndpointRule.domain");
    }

    @Test
    void originSurvivesAnAuthorityLessUri() {
        // "https:*" parses with getAuthority() == null; reading the authority without a null guard
        // would turn a malformed entry into a NullPointerException.
        assertThatThrownBy(() -> EndpointRule.origin("https:*"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no host");
    }

    // ---------------------------------------------------------------- domain accepted and normalized

    @Test
    void domainAcceptsAndNormalizesAnEntry() {
        assertThat(EndpointRule.domain("notify.windows.com")).hasToString("EndpointRule.domain(notify.windows.com)");
        assertThat(EndpointRule.domain("NOTIFY.WINDOWS.COM")).hasToString("EndpointRule.domain(notify.windows.com)");
        assertThat(EndpointRule.domain("xn--bcher-kva.example")).hasToString("EndpointRule.domain(bücher.example)");
        assertThat(EndpointRule.domain("UPPER.xn--BCHER-KVA.example"))
                .hasToString("EndpointRule.domain(upper.bücher.example)");
        assertThat(EndpointRule.domain("xn--e1afmkfd.xn--80akhbyknj4f"))
                .hasToString("EndpointRule.domain(пример.испытание)");
    }

    @Test
    void anEntryNormalizedFromAnALabelIsALiveRuleRatherThanADeadOne() {
        // The reason normalization is not optional: an A-label entry only ever meets a host that
        // has already been decoded to its U-label, so an entry that were merely validated would
        // look configured and never fire.
        EndpointPolicy policy = EndpointPolicies.allowedDomains("xn--e1afmkfd.xn--80akhbyknj4f");

        assertThatCode(() -> policy.validate(URI.create("https://a.XN--E1AFMKFD.XN--80AKHBYKNJ4F/subscriber-token")))
                .doesNotThrowAnyException();
    }

    @Test
    void domainAcceptsALabelLongerThanSixtyThreeCharacters() {
        // Deliberate. DNS caps a label at 63 octets, so this entry can never match any real host —
        // it is a dead entry, not a widening. Checking the length here would be the hand-rolled
        // hostname grammar the entry validation deliberately does not have; java.net.URI is the
        // one grammar, and it accepts this.
        String longLabel = "a".repeat(64);

        assertThatCode(() -> EndpointRule.domain(longLabel + ".example")).doesNotThrowAnyException();
    }

    @Test
    void domainRejectsNull() {
        assertThatThrownBy(() -> EndpointRule.domain(null)).isInstanceOf(NullPointerException.class);
    }

    // ---------------------------------------------------------------- domain refused, one test per message

    @Test
    void domainRejectsAnEmptyEntry() {
        assertThatThrownBy(() -> EndpointRule.domain(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be empty");
    }

    @Test
    void domainRejectsAControlCharacterBeforeItLooksLikeAnAddressLiteral() {
        // An ANSI escape sequence carries a '[', so without the control-character check running
        // first the entry falls into the bracket check and the operator is told their hostname is an
        // IP address literal — a cause that has nothing to do with what they pasted.
        // Built rather than written as a literal: a raw escape byte in a source file is invisible.
        String colourised = "zone.example" + (char) 0x1B + "[31mX";
        assertThatThrownBy(() -> EndpointRule.domain(colourised))
                .as("terminal formatting dragged in with a copied line, and the entry still withheld")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("control character")
                .hasMessageNotContaining("IP address literal")
                .hasMessageContaining("left out of this message")
                .hasMessageNotContaining("zone.example");
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com\r"))
                .as("a stray carriage return from a file written on Windows")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("control character")
                .hasMessageNotContaining("notify.windows.com");
    }

    @Test
    void domainRejectsAnIpv6LiteralBeforeItsColonsAreSeen() {
        // The bracket check runs first on purpose: otherwise an address literal is refused for its
        // colons and the operator is told to remove a port that is not there.
        assertThatThrownBy(() -> EndpointRule.domain("[::1]"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not an IP address literal");
    }

    @Test
    void domainRejectsASchemeOrPort() {
        assertThatThrownBy(() -> EndpointRule.domain("https://notify.windows.com"))
                .as("a pasted scheme would otherwise parse with the host \"https\"")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no scheme and no port");
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com:8443"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no scheme and no port");
    }

    @Test
    void domainRejectsAPathQueryOrFragment() {
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com/w/p"))
                .as("path")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a URL");
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com?tenant=1"))
                .as("query")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a URL");
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com#frag"))
                .as("fragment")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a URL");
    }

    @Test
    void domainRejectsUserinfo() {
        // "notify.windows.com@evil.example" parses with the host "evil.example", so everything the
        // operator wrote would be discarded and the rule would cover the attacker's zone instead.
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com@evil.example"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("userinfo");
    }

    @Test
    void domainRejectsAWildcard() {
        assertThatThrownBy(() -> EndpointRule.domain("*.notify.windows.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("wildcard");
    }

    @Test
    void domainRejectsALeadingDotOrAnEmptyLabel() {
        assertThatThrownBy(() -> EndpointRule.domain(".notify.windows.com"))
                .as("leading dot")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty label");
        assertThatThrownBy(() -> EndpointRule.domain("notify..windows.com"))
                .as("empty label in the middle")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty label");
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com.."))
                .as("String.split drops trailing empty fields, so this must not be checked with split")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty label");
    }

    @Test
    void domainRejectsATrailingRootDotBeforeCallingItASingleLabel() {
        // Load-bearing rather than only diagnostic: "notify.windows.com." is read back as itself by
        // the parser, so the closing equality check would pass it, and the entry could never match
        // a host the endpoint side compares without the root dot. The order matters too — checked
        // after the single-label rule, "com." would be reported as a single label.
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com."))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("root dot");
        assertThatThrownBy(() -> EndpointRule.domain("com."))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("root dot");
    }

    @Test
    void domainRejectsASingleLabel() {
        // Also load-bearing: both are read back as themselves by the parser.
        assertThatThrownBy(() -> EndpointRule.domain("com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least two labels");
        assertThatThrownBy(() -> EndpointRule.domain("localhost"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least two labels");
    }

    @Test
    void domainRejectsAnIpv4Literal() {
        // Load-bearing: "1.2.3.4" is read back as itself, and an operator reads
        // domain("10.0.0.0") as a subnet rather than as a name with no subdomains.
        assertThatThrownBy(() -> EndpointRule.domain("1.2.3.4"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not an IP address literal");
    }

    @Test
    void domainRejectsRawUnicodeWithTheALabelAdviceRatherThanAsHostless() {
        // The non-ASCII check runs before the parse: java.net.URI answers getHost() == null for a
        // non-ASCII authority, so leaving this to the parser would tell the operator their entry
        // has no host instead of telling them how to spell it.
        assertThatThrownBy(() -> EndpointRule.domain("bücher.example"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("A-label")
                .hasMessageNotContaining("hostname the URI parser recognises");
    }

    @Test
    void domainRejectsAnEntryTheParserCannotRead() {
        for (String entry : new String[] {"-lead.example", "a_b.example", "xn--.example", "1.2.3.4.5"}) {
            assertThatThrownBy(() -> EndpointRule.domain(entry))
                    .as("%s", entry)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not a hostname the URI parser recognises")
                    .hasNoCause();
        }
    }

    @Test
    void domainRejectsAnEntryTheParserRefusesOutright() {
        // A trailing or leading space makes java.net.URI throw rather than answer a null host.
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a valid URI host")
                .hasNoCause();
        assertThatThrownBy(() -> EndpointRule.domain(" notify.windows.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a valid URI host")
                .hasNoCause();
    }

    // ---------------------------------------------------------------- entry rendering

    @Test
    void anUnsafeDomainEntryNeverReachesTheMessageWholeOrInPart() {
        // The reason the domain entry is not rendered through Endpoints.redact and not printed
        // unconditionally either: the domain field is exactly where a pasted capability URL lands.
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com/secret-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("notify.windows.com/secret-token")
                .hasMessageNotContaining("secret-token")
                .hasMessageNotContaining("notify.windows.com")
                .hasMessageContaining("left out of this message");
        assertThatThrownBy(() -> EndpointRule.domain("zone.example\nX-Injected: 1"))
                .as("a control character never reaches a log line")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("X-Injected")
                .hasMessageNotContaining("zone.example");
    }

    @Test
    void aSafeDomainEntryIsQuotedIntoTheMessage() {
        // Endpoints.redact would answer a bare hostname with "<opaque endpoint>#" plus a
        // fingerprint, showing the operator not one character of what they typed.
        assertThatThrownBy(() -> EndpointRule.domain("notify.windows.com."))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'notify.windows.com.'")
                .hasMessageNotContaining("<opaque endpoint>");
        assertThatThrownBy(() -> EndpointRule.domain("localhost"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'localhost'");
    }

    @Test
    void anOriginEntryIsAlwaysRedactedBecauseItMayBeAPastedCapabilityUrl() {
        String entry = "https://push.example/send/secret-token";

        assertThatThrownBy(() -> EndpointRule.origin(entry))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(Endpoints.redact(entry))
                .hasMessageNotContaining("secret-token");
    }

    // ---------------------------------------------------------------- value equality

    @Test
    void rulesAreEqualByKindAndNormalizedEntry() {
        assertThat(EndpointRule.origin("https://push.example"))
                .isEqualTo(EndpointRule.origin("https://PUSH.Example:443/"))
                .hasSameHashCodeAs(EndpointRule.origin("https://PUSH.Example:443/"))
                .isNotEqualTo(EndpointRule.origin("https://other.example"));
        assertThat(EndpointRule.domain("zone.example"))
                .isEqualTo(EndpointRule.domain("ZONE.EXAMPLE"))
                .hasSameHashCodeAs(EndpointRule.domain("ZONE.EXAMPLE"))
                .isNotEqualTo(EndpointRule.domain("other.example"));
        assertThat(EndpointRule.domain("xn--bcher-kva.example"))
                .isEqualTo(EndpointRule.domain("XN--BCHER-KVA.example"));
    }

    @Test
    void aRuleIsNeverEqualToOneOfTheOtherKind() {
        // Equality lives on each implementation rather than on the base class: a base-class equals
        // written over "instanceof EndpointRule" would let these two collapse into one another
        // inside an allowlist, and they mean entirely different things.
        EndpointRule origin = EndpointRule.origin("https://zone.example");
        EndpointRule domain = EndpointRule.domain("zone.example");

        assertThat(origin).isNotEqualTo(domain);
        assertThat(domain).isNotEqualTo(origin);
        assertThat(origin).isNotEqualTo(null).isNotEqualTo("https://zone.example");
    }

    // ------------------------------------------- the bad outcome the domain rule exists to make impossible

    @Test
    void aDomainRuleCannotAdmitAHostOutsideItsZone() {
        EndpointPolicy policy = EndpointPolicies.allowedEndpoints(EndpointRule.domain("notify.windows.com"));

        for (String endpoint : new String[] {
            "https://evilnotify.windows.com/x", // the label boundary: the dot belongs to the suffix
            "https://notify.windows.com.evil.example/x", // the zone as a prefix of someone else's
            "https://xnotify.windows.com/x",
            "http://notify.windows.com/x", // the scheme is anchored, not inherited
            "https://notify.windows.com:8443/x", // a port is a statement about a service, not a name
            "https://notify.windows.com:80/x" // 80 is http's default port and is not this rule's
        }) {
            assertThatThrownBy(() -> policy.validate(URI.create(endpoint)))
                    .as("%s", endpoint)
                    .isInstanceOf(EndpointRejectedException.class)
                    .hasMessageContaining("not in the allowed set");
        }
    }

    @Test
    void aDomainRuleIsNeverReachedByAnEndpointWithNoOriginOrWithUserinfo() {
        EndpointPolicy policy = EndpointPolicies.allowedEndpoints(EndpointRule.domain("notify.windows.com"));

        assertThatThrownBy(() -> policy.validate(URI.create("mailto:someone@example.com")))
                .isInstanceOf(EndpointRejectedException.class)
                .hasMessageContaining("no scheme or host");
        assertThatThrownBy(() -> policy.validate(URI.create("https://notify.windows.com@evil.example/x")))
                .as("the shared pre-check fires before any rule is consulted")
                .isInstanceOf(EndpointRejectedException.class)
                .hasMessageContaining("userinfo");
    }

    @Test
    void aDomainRuleAdmitsTheApexAndEverySubdomainOverHttpsOnTheDefaultPort() {
        EndpointPolicy policy = EndpointPolicies.allowedEndpoints(EndpointRule.domain("notify.windows.com"));

        for (String endpoint : new String[] {
            "https://notify.windows.com/x",
            "https://cloud.notify.windows.com/x",
            "https://wns2-ln2p.notify.windows.com/x",
            "https://a.b.c.notify.windows.com/x",
            "https://NOTIFY.WINDOWS.COM:443/x"
        }) {
            assertThatCode(() -> policy.validate(URI.create(endpoint)))
                    .as("%s", endpoint)
                    .doesNotThrowAnyException();
        }
    }
}
