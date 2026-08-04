package com.the13haven.push2u;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link EndpointPolicies#allowedOrigins}: the origin comparison must use the same RFC 6454 §6.1
 * normalization on both sides (so no spelling of an allowed origin is rejected and no spelling of a foreign one is
 * admitted), a malformed configuration must fail at construction rather than at send time, and no rejection message may
 * carry the capability part of an endpoint URL.
 */
class EndpointPoliciesTest {

    @Test
    void acceptsAnEndpointOnAnAllowedOrigin() {
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://push.example");

        assertThatCode(() -> policy.validate(URI.create("https://push.example/subscriber-token")))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsAnEndpointOnAForeignOrigin() {
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://push.example");

        assertThatThrownBy(() -> policy.validate(URI.create("https://attacker.example/subscriber-token")))
                .isInstanceOf(EndpointRejectedException.class)
                .hasMessageContaining("not in the allowed set");
    }

    @Test
    void rejectionMessageNeverCarriesTheCapabilityPathOrQuery() {
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://push.example");

        assertThatThrownBy(() -> policy.validate(URI.create("https://attacker.example/secret-token?key=secret-query")))
                .isInstanceOf(EndpointRejectedException.class)
                .hasMessageNotContaining("secret-token")
                .hasMessageNotContaining("secret-query")
                // The redacted origin+fingerprint form IS expected — it is what lets a log line be
                // correlated with a stored subscription without disclosing the capability.
                .hasMessageContaining("https://attacker.example/…#");
    }

    @Test
    void anExplicitDefaultPortMatchesTheImplicitFormBothWays() {
        // RFC 6454 §6.1 drops the scheme's default port, so :443 and no port are the same origin —
        // whichever side spells it out.
        EndpointPolicy explicitInConfig = EndpointPolicies.allowedOrigins("https://push.example:443");
        assertThatCode(() -> explicitInConfig.validate(URI.create("https://push.example/subscriber-token")))
                .doesNotThrowAnyException();

        EndpointPolicy implicitInConfig = EndpointPolicies.allowedOrigins("https://push.example");
        assertThatCode(() -> implicitInConfig.validate(URI.create("https://push.example:443/subscriber-token")))
                .doesNotThrowAnyException();
    }

    @Test
    void aDifferentPortIsADifferentOrigin() {
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://push.example");

        assertThatThrownBy(() -> policy.validate(URI.create("https://push.example:8443/subscriber-token")))
                .isInstanceOf(EndpointRejectedException.class);
    }

    @Test
    void aSubdomainOfAnAllowedOriginIsNotAllowed() {
        // Origins compare exactly (RFC 6454 §5) — allowing "push.example" must not admit an
        // attacker-registered "evil.push.example" endpoint.
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://push.example");

        assertThatThrownBy(() -> policy.validate(URI.create("https://evil.push.example/subscriber-token")))
                .isInstanceOf(EndpointRejectedException.class);
    }

    @Test
    void hostAndSchemeCaseDoNotMatter() {
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://PUSH.Example");

        assertThatCode(() -> policy.validate(URI.create("HTTPS://push.EXAMPLE/subscriber-token")))
                .doesNotThrowAnyException();
    }

    @Test
    void idnALabelsMatchWhateverCaseTheEndpointUses() {
        // Both sides go through the RFC 6454 Unicode serialization, so an A-label allowlist entry
        // matches the endpoint's uppercase A-label spelling of the same host.
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://xn--e1afmkfd.xn--80akhbyknj4f");

        assertThatCode(() -> policy.validate(URI.create("https://XN--E1AFMKFD.XN--80AKHBYKNJ4F:443/subscriber-token")))
                .doesNotThrowAnyException();
    }

    @Test
    void ipv6LiteralsMatchByExactTextualFormWithPortNormalization() {
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://[::1]:8443", "https://[::1]:443");

        assertThatCode(() -> policy.validate(URI.create("https://[::1]:8443/subscriber-token")))
                .doesNotThrowAnyException();
        assertThatCode(() -> policy.validate(URI.create("https://[::1]/subscriber-token")))
                .as("the configured :443 and the endpoint's implicit port are the same origin")
                .doesNotThrowAnyException();
        // The serialization lowercases but does NOT canonicalize IPv6 textual forms: the expanded
        // spelling of the same address is a different origin string and fails to match. That is
        // the fail-closed direction — a spelling variant can be denied, never admitted.
        assertThatThrownBy(() -> policy.validate(URI.create("https://[0:0:0:0:0:0:0:1]:8443/subscriber-token")))
                .isInstanceOf(EndpointRejectedException.class);
        assertThatThrownBy(() -> policy.validate(URI.create("https://[::2]:8443/subscriber-token")))
                .as("a genuinely different literal is rejected")
                .isInstanceOf(EndpointRejectedException.class);
    }

    @Test
    void rejectsAnEndpointWhoseUserinfoImpersonatesAnAllowedOrigin() {
        // https://fcm.googleapis.com@evil.example/x — java.net.URI resolves the real host
        // (evil.example), so the comparison would reject it anyway; the policy additionally
        // rejects ANY endpoint userinfo outright, because no push service issues it and a custom
        // transport re-parsing the raw string could split the authority differently.
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://fcm.googleapis.com");

        assertThatThrownBy(
                        () -> policy.validate(URI.create("https://fcm.googleapis.com@evil.example/subscriber-token")))
                .isInstanceOf(EndpointRejectedException.class)
                .hasMessageContaining("userinfo");
        assertThatThrownBy(() -> policy.validate(URI.create("https://user:pass@fcm.googleapis.com/subscriber-token")))
                .as("userinfo is rejected even when the real host IS allowed")
                .isInstanceOf(EndpointRejectedException.class)
                .hasMessageContaining("userinfo");
    }

    @Test
    void anEndpointWithoutAnOriginIsRejectedWithThePromisedType() {
        // Unreachable through PushSender (Subscription enforces scheme+host first), but validate()
        // is public API promising EndpointRejectedException — a direct caller must not get the
        // plain IllegalArgumentException Origin.serialize would throw.
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://push.example");

        assertThatThrownBy(() -> policy.validate(URI.create("mailto:someone@example.com")))
                .isInstanceOf(EndpointRejectedException.class)
                .hasMessageContaining("no scheme or host");
    }

    @Test
    void aLoneTrailingSlashInTheConfigurationIsTolerated() {
        // Humans paste "https://push.example/"; RFC 6454 prints origins without the slash.
        EndpointPolicy policy = EndpointPolicies.allowedOrigins("https://push.example/");

        assertThatCode(() -> policy.validate(URI.create("https://push.example/subscriber-token")))
                .doesNotThrowAnyException();
    }

    @Test
    void constructionRejectsAnEmptyAllowlist() {
        List<String> none = List.of();
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins(none))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one origin");
    }

    @Test
    void constructionRejectsAnUnparseableEntryWithoutEchoingIt() {
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins("https://push example/secret-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a valid URI")
                .hasMessageNotContaining("secret-token");
    }

    @Test
    void constructionRejectsANonHttpsEntry() {
        // Subscription endpoints are https-only, so an http allowlist entry is dead configuration
        // that could never match — fail the deployment, not every send.
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins("http://push.example"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be https");
    }

    @Test
    void constructionRejectsAHostlessEntry() {
        // An underscore label makes java.net.URI treat the authority as registry-based and return
        // getHost() == null — parseable, yet hostless. ("https://" itself fails URI parsing and is
        // covered by the unparseable-entry test.)
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins("https://exa_mple.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no host");
    }

    @Test
    void constructionRejectsARawUnicodeHost() {
        // java.net.URI yields getHost() == null for a non-ASCII authority, so a U-label entry can
        // never match; the failure must point at the fix (use the A-label form) at construction.
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins("https://пример.испытание"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("A-label");
    }

    @Test
    void constructionRejectsAPastedEndpointUrlWithoutEchoingIt() {
        // The likeliest malformed entry is a full endpoint pasted from a subscription — a
        // capability URL. It must be rejected (the path would otherwise be silently ignored) and
        // must not be echoed.
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins("https://push.example/send/secret-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bare scheme://host[:port]")
                .hasMessageNotContaining("secret-token");
    }

    @Test
    void constructionRejectsQueryFragmentAndUserinfoEntries() {
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins("https://push.example?tenant=1"))
                .as("query")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins("https://push.example#frag"))
                .as("fragment")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EndpointPolicies.allowedOrigins("https://user:pass@push.example"))
                .as("userinfo")
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void collectionAndVarargsOverloadsAgree() {
        EndpointPolicy fromCollection = EndpointPolicies.allowedOrigins(List.of("https://push.example"));

        assertThatCode(() -> fromCollection.validate(URI.create("https://push.example/subscriber-token")))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> fromCollection.validate(URI.create("https://attacker.example/subscriber-token")))
                .isInstanceOf(EndpointRejectedException.class);
    }
}
