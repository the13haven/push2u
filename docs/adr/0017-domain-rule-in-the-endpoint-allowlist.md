# ADR-017 — A domain rule in the endpoint allowlist

**Status:** Proposed

ADR-016 made the egress decision mandatory and left exactly two answers behind it:
`EndpointPolicies.allowedOrigins(...)`, whose rule is exact per origin — a subdomain of an allowed
origin is not allowed — and `EndpointPolicies.unrestricted()`. Microsoft Edge delivers Web Push
through WNS, and Microsoft's WNS documentation instructs the application server to do the opposite
of exact matching: the service must ensure the channel URI uses the domain `notify.windows.com` and
must never push to a channel on any other domain, and, verbatim, "The subdomain of the channel URI
is subject to change and should not be considered when validating the channel URI"
(https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/wns-overview).
The subdomains are real and they vary: that same page's notification example posts to
`cloud.notify.windows.com` and sends it as the `Host:` header, while a report of a failing Edge
endpoint names `wns2-ln2p.notify.windows.com`
(https://github.com/MicrosoftEdge/DevTools/issues/262).

So for a deployment serving Edge the safe rule is not expressible, and the only reachable answer is
the one ADR-016 named unsafe. Enumerating the datacentre subdomains is not a workaround but exactly
the failure mode ADR-016 named when it rejected a built-in browser allowlist: an allowlist that is
mostly right, that goes stale as WNS adds a datacentre, and that fails silently when it does. The
other three services are single fixed hosts, so WNS is the only one affected today — but the same
shape returns for any self-hosted or intra-organisation push service fronted by more than one host,
which ADR-016 lists as a legitimate deployment. ADR-016 set out to stop unrestricted egress from
being what a deployment gets by not deciding; this is unrestricted egress being what it gets *after*
deciding correctly, because the correct rule has no spelling.

This does not supersede ADR-016, and every decision in it stands: the policy remains a required
argument of both factory methods, the library still ships no allowlist of its own, no policy is
derived by resolving the endpoint, `unrestricted()` keeps its name as the single opt-out, and the
Spring starter still fails to start when no decision is expressed. What widens is the answer space —
one more rule a deployment can state, so that stating the correct one becomes possible.

The decision: the standard allowlist becomes heterogeneous rather than composable — three public
entry points on `EndpointPolicies` over one shared rule, and no combinator.

```java
public static EndpointPolicy allowedDomains(String... domains);
public static EndpointPolicy allowedDomains(Collection<String> domains);
public static EndpointPolicy allowedOriginsAndDomains(
        Collection<String> origins, Collection<String> domains);
```

`allowedOriginsAndDomains` is the primary cross-browser call, not a convenience over a composition:
for anyone serving Edge, the union of ordinary origins and one domain *is* the ordinary
configuration, and a design that puts the primary call behind a composition has put the sharp tool
on the main path.

- **A domain entry covers the apex and every subdomain at any depth, matched at a label boundary**:
  `host.equals(domain) || host.endsWith("." + domain)`. The dot belongs to the suffix, not to the
  string being searched — without it `evilnotify.windows.com` matches `notify.windows.com`. That is
  the whole vulnerability class, it costs one character, and it is the bug every consumer writing
  this rule by hand reaches independently.
- **Both sides of the comparison are normalized by the same code.** The endpoint's host comes from
  wherever `Origin.serialize` gets it — lowercased, IDNA A-label decoded to U-label — and never from
  a `URI.getHost()` call sitting beside it. Two normalizers mean two answers for one endpoint, and
  they diverge precisely in the internationalised cases nobody exercises by hand. The two
  endpoint-side refusals that guard that comparison today hold unchanged on the domain and union
  paths: an endpoint carrying userinfo is rejected outright, before any comparison, and one with no
  scheme or host is rejected as having no origin to compare at all.
- **A domain rule matches only the scheme `https` and the default port**, an absent port or an
  explicit `443`. The scheme is anchored explicitly rather than inherited: `Origin.serialize` does
  not enforce a scheme, by its own documented contract — that is `Endpoints.requireSecure`'s job at
  the `Subscription` boundary — and the origin rule is protected for free only because it compares
  the whole serialization including `https://`. The port is a decision rather than an accident: a
  domain rule is a statement about which *names* are trusted, while a port is a statement about
  which *service on a host* is trusted, and permitting every port across a zone re-creates the blind
  SSRF oracle ADR-016 exists to close, relocated into an external zone. A deployment that genuinely
  needs `https://host.zone:8443` names it exactly with `allowedOrigins`, which is the right
  granularity for a port.
- **`allowedOriginsAndDomains` refuses only when both collections are empty; either one alone may be
  empty.** `allowedDomains` refuses an empty collection as `allowedOrigins` already does, but the
  union entry point cannot: it has to serve the origins-only configuration that every `0.1.0`
  deployment already has, and a refusal on either side alone would make it unusable for the case it
  is meant to absorb. The asymmetry with `allowedOrigins(List.of())` is not an inconsistency — that
  refusal is about an allowlist with no entries at all, which rejects every send and is far likelier
  a wiring bug than a policy, while an empty list beside a non-empty one is a rule this deployment
  does not use.
- **A malformed domain entry fails at construction**, as a malformed origin entry already does, and
  every message renders the entry through `Endpoints.redact`. Refused: an empty entry; `:` (which
  catches both a port and a pasted `https://x`, an entry that would otherwise parse with the host
  `https`); `/`, `?` or `#` (a pasted capability URL, whose path would be silently ignored); `@`
  (`notify.windows.com@evil.example` parses with the host `evil.example`, so everything the operator
  wrote is discarded); `*` (the CSP and cookie habit); a leading dot or an empty label; a trailing
  root dot, which `java.net.URI` accepts as a host and which would leave the rule unable to ever
  fire — a dead entry that looks configured; a single label (`com`, `localhost`); an IP literal,
  since an address has no subdomains and an operator reads `allowedDomains("10.0.0.0")` as a subnet;
  and raw Unicode. A closing check that the entry equals the host the parser found, ignoring case,
  is the complete defence against the scheme concatenation reinterpreting the entry — which is what
  lets the list above exist for the sake of its *messages* rather than for completeness. Validation
  runs through the same `java.net.URI` the endpoint side uses, never a hand-rolled hostname regex,
  so a configured entry can never be a shape an endpoint could never have; a regex would be a second
  grammar of "a valid host" to keep in step with the first.
- **The library makes no public-suffix judgement.** There is no public-suffix list in the JDK,
  `HttpCookie.domainMatches`'s embedded-dot heuristic is wrong in both directions, a dependency is
  forbidden by ADR-002, and a bundled data file ages between releases while going on looking
  authoritative. Refusing a single label is the one case that is unambiguously wrong with no data at
  all. The rest is stated plainly rather than half-checked: a domain rule is worth exactly what the
  DNS of that zone is worth, and a domain rule over a shared hosting zone permits every tenant of
  it. The operator-facing rule of thumb is that a domain rule belongs only where the service
  operator *documents* that its hostnames vary within a zone, as Microsoft does for WNS — which is
  also the honest justification for the feature: the wide rule is not the library's guess, it is the
  service operator's published instruction.
- **`allowedDomains` misreads in the dangerous direction** — as "the same as origins, minus the
  scheme", that is, exact host matching, which leaves the operator believing the rule is narrower
  than it is. It is therefore normative that the first Javadoc sentence, the one an IDE shows, leads
  with subdomains, and that the Spring property's documentation does the same.
- **The behaviour of the origins-only path is frozen, and the freeze is scoped to behaviour.**
  `allowedOrigins` shipped in `0.1.0`, so which entries it accepts and which it refuses, the
  exception types it throws, and the order of its checks do not change because the implementation
  became shared — that drift is what the freeze exists to prevent. The literal text of every message
  is deliberately *not* frozen: a refusal gaining precision is not the drift being guarded against,
  and freezing prose would forbid the one improvement named below. The non-empty check therefore
  lives at the entry points rather than in the shared rule, and the rejection message is chosen by
  what was configured, domains-only and the union each getting their own. One message merged across
  all three configurations is ruled out for a reason of substance rather than of wording: the one
  thing an operator needs from a rejection is which rule refused.
- **One refusal changes, and it is named here rather than left to the implementation**: an *origin*
  entry carrying a `*` where a host label belongs earns its own construction check, refusing it with
  a message naming `allowedDomains`. (A `*` in a *domain* entry is refused by the construction
  checks above.) The criterion is the host position and not the presence of the character:
  `https://example.com/*` and `https://a*b@example.com` are already refused today for being more
  than a bare `scheme://host[:port]`, which is the right thing to tell their author, and a check
  firing on a `*` anywhere would capture them and send them to `allowedDomains` instead. For the
  same reason it has to be its own check rather than a repointing of the branch a wildcard host
  currently falls into, which is not `*`-specific either — a leading dot, an empty label and a raw
  Unicode host all reach it too, since `java.net.URI` yields no host for any of them. The
  raw-Unicode entry's present advice — spell the host in its A-label form — is correct, and
  `allowedDomains` refuses raw Unicode as well, so repointing the branch would replace right advice
  with wrong for every entry that is not a wildcard.
- **Two same-typed `Collection<String>` parameters are acceptable here.** The convention is that
  several same-typed required values are made swap-proof by value types rather than by argument
  order. The protection here is different but real: the two grammars are disjoint — an origin entry
  must contain `://`, a domain entry containing `://` is refused by the construction checks above,
  and `notify.windows.com` offered as an origin fails on "must be https" — so a swapped call
  assembles in neither direction and fails at construction with a message naming the shape it got.
  Recorded because the next reader would otherwise see a convention broken and no reason given.
- **Spring gains `push2u.allowed-domains` beside `push2u.allowed-origins`.** ADR-016's refusal of a
  property was about a *mode*: a flag that removes the control, whose danger is that it travels
  between profiles as a copied line. A domain list is data: it cannot be set to a value that
  disables the control. The asymmetry that decided ADR-015 and ADR-016 — a property can be added
  later without breaking anyone, and cannot be removed after a release — argues as it always did
  that withholding is the cheap default, and it is not overridden lightly. What overrides it here is
  what withholding would do: a Spring deployment serving Edge would then choose between a `@Bean`
  carrying a list of hostnames and `EndpointPolicies.unrestricted()`, and it picks the second. The
  property is admitted precisely because it makes the safe answer reachable by the route operators
  already use.
- **The starter's existing rules are restated over two properties.** "Expressed" means at least one
  of the two properties is non-empty. Both sources at once — expressed, plus a bean — still fails
  the context, naming which property is non-empty and naming the bean. Neither of them — both
  properties unset, no bean — still fails, now offering three ways to fix it instead of two. The
  empty-value escape hatch keeps its shape, because it was always per-property: an explicitly empty
  value means "this property is deliberately unused here", and a service empties whichever key it
  inherited. One case changes character: every set property empty, with no bean. Today the starter
  delegates that refusal to the core, which answers in its own words; with two properties the
  emptiness is a statement about the *pair*, and no single core factory can speak for both, so the
  starter owns a message naming both keys. Attribution of a malformed entry follows the
  `retryPolicy` precedent already in the starter — probe each key separately, discard the probe's
  result, then build the union — with the adjustment that precedent itself demands: **the probe runs
  only over the keys that are non-empty.** What makes that precedent work is filling the components
  a probe is not testing with values acceptable regardless, and here the natural filler is the empty
  collection, which is precisely what an entry point refuses. Copied literally, a domains-only
  configuration would fail its origins probe with "requires at least one origin" and attribute the
  failure to the key the operator deliberately left empty. An empty list has nothing to validate, so
  there is nothing to attribute.

Rejected alternatives:

- **A public `anyOf(EndpointPolicy...)`.** It is a union of permissions wearing the grammar of a
  restriction: `anyOf(allowedOrigins(...), unrestricted())` *is* `unrestricted()` while reading in a
  diff as an allowlist — a direct attack on the only mechanism ADR-016 has, which was making
  `unrestricted()` a visible token in the consumer's own source. A deny-shaped custom policy
  composed into it is silently neutered, and deny-shaped is what a custom policy usually is. The
  diagnostics collapse too: a union must discard N rejection messages and synthesise one, when the
  one thing an operator needs from a rejection is which rule refused and why.
- **An `anyOf` restricted to the rules this class itself built.** Enforcing that at compile time
  would require `allowedOrigins` to return a library-owned subtype, and a changed descriptor on an
  already-published method is a `NoSuchMethodError` for everyone compiled against `0.1.0`. What
  remains is a runtime `instanceof` check — an API that publishes a combinator over a public
  interface and then refuses implementations of that interface, which is worse than no API at all,
  because it refuses the composition every reader tries first.
- **A `default` method such as `or` on `EndpointPolicy` itself.** Everything above, plus: the
  combinator lands on the SPI and is inherited by every third-party implementation, and it adds a
  permanent member to a published `@FunctionalInterface`. The asymmetry it would teach is the wrong
  one — intersection is the safe combinator and union is not — and a consumer narrowing an allowlist
  with their own deny rule writes a two-line lambda.
- **A wildcard entry such as `https://*.notify.windows.com` inside `allowedOrigins`.** It is the
  least legible possible spelling of "and this one is an entire DNS zone", sitting in a list of
  visually identical origins, when ADR-016's whole thesis is that the security-relevant choice must
  be legible in a diff. And `*` announces a pattern language that does not exist: `https://*`,
  `https://*.com` and `https://wns2-*.notify.windows.com` would each need their own refusal inside
  one validator now describing two grammars. What this decision does fix is the diagnostic: `*`
  stays a construction failure, and gets the refusal named above instead of falling into a branch
  that can only tell the operator their origin has no host.
- **Shipping `notify.windows.com` as a default.** ADR-016 rejected the built-in allowlist, and for a
  *zone* the rejection holds a fortiori: it is the library asserting trust in a third party's DNS on
  the deployment's behalf, and it would silently widen every existing deployment on upgrade. What
  survives the rejection is that the names belong in documentation and examples, which is not an
  allowlist — the operator copies them into their own configuration, where they appear in their own
  diff.
- **Publishing the normalizer instead of the rule.** Exporting `Origin` answers the wrong question:
  ADR-005 admits a seam where there is a difference the library cannot decide for the deployment,
  and here the matching rule is universal while only the list is deployment-specific. Handing out
  the normalizer means every consumer re-derives the label boundary and writes the `evilnotify` bug.
  It would also freeze the serialization, whose exact output is changeable today only because both
  call sites are inside the package.
- **A regex entry, or a predicate factory.** A regex over a hostname is the canonical source of this
  same vulnerability class — unanchored patterns, and `.` matching any character. A
  `Predicate<String>` factory adds nothing over the `EndpointPolicy` lambda ADR-005 already
  provides, only surface.
- **Letting a domain rule match any port or any scheme**, which is a port and protocol oracle over
  an unbounded set of hosts; and **expressing all four push services as domains**, which widens
  three single-host services to three zones for no gain.

This rules out a public combinator over `EndpointPolicy`, whether on this class or on the interface;
a domain rule matching a scheme other than `https` or a port other than the default; a pattern or
wildcard syntax inside an origin entry; a public-suffix judgement made by the library, by dependency
or by bundled data; and a push service's zone shipped as a default.
`EndpointPolicies.unrestricted()` is untouched, and `Endpoints.requireSecure` stays what ADR-005
called it: a protocol check, not a security control. Nothing changes in either `module-info.java` —
these are new members of an already-exported package — or in `push2u-testkit`, since the rule is
concrete rather than a seam and there is no contract here for a third party to satisfy.
