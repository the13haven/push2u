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

So for a deployment serving Edge the safe rule is not expressible through anything the library
ships to state it with: not `allowedOrigins`, whose match is exact per origin, and not the Spring
property that binds to it. The seam is not the gap. An application-supplied `EndpointPolicy` does
express the WNS rule, and ADR-005 admitted that seam precisely so a deployment's own egress rule has
somewhere to live — this is a question of what the built-in answers cover, not of a missing
capability. What reaching for the seam costs is the point: the deployment re-implements, per
consumer, the URI and origin handling the library already performs correctly and does not expose —
the RFC 6454 serialization, the IDNA form, the default-port drop and the userinfo refusal are all
package-private — and it independently re-derives the label boundary that separates
`notify.windows.com` from `evilnotify.windows.com`, which is the bug this decision names below and
the kind no operator finds by testing the configuration they meant to write. Enumerating the
datacentre subdomains is not a workaround either, but exactly the failure mode ADR-016 named when it
rejected a built-in browser allowlist: an allowlist that is mostly right, that goes stale as WNS
adds a datacentre, and that fails silently when it does. The other three services are single fixed
hosts, so WNS is the only one affected today — but the same shape returns for any self-hosted or
intra-organisation push service fronted by more than one host, which ADR-016 lists as a legitimate
deployment. ADR-016 set out to stop unrestricted egress from being what a deployment gets by not
deciding; here it is what a deployment can reach for *after* deciding correctly, because the correct
rule has no spelling among the answers the library ships and the spelling it does have is forty
lines of security-critical normalization the deployment has to get right on its own. That is a
failure of correctness-by-default over a control every consumer would otherwise re-derive.

This does not supersede ADR-016, and every decision in it stands: the policy remains a required
argument of both factory methods, the library still ships no allowlist of its own, no policy is
derived by resolving the endpoint, `unrestricted()` keeps its name as the single opt-out, and the
Spring starter still fails to start when no decision is expressed. What widens is the answer space —
one more rule a deployment can state, so that stating the correct one stays inside the library's own
vocabulary instead of being a lambda each deployment writes and gets right on its own.

The decision: an allowlist entry becomes a value that carries its own kind, and the standard
allowlist is a list of those values rather than a list of strings whose meaning depends on which
parameter they were passed in.

```java
public abstract sealed class EndpointRule {
    public static EndpointRule origin(String origin);
    public static EndpointRule domain(String domain);
}

public static EndpointPolicy allowedEndpoints(EndpointRule... rules);
public static EndpointPolicy allowedEndpoints(Collection<? extends EndpointRule> rules);

public static EndpointPolicy allowedDomains(String... domains);
public static EndpointPolicy allowedDomains(Collection<String> domains);
```

`allowedEndpoints` is the primary cross-browser call: for anyone serving Edge, a list holding three
origin rules and one domain rule *is* the ordinary configuration, not an edge case. The two string
factories are convenience over it — `allowedOrigins` keeps the signatures it shipped with and is
neither changed nor deprecated, `allowedDomains` is its new counterpart — and each maps its entries
to rules of one kind and delegates.

- **A rule is a value that carries its own kind, and that is a design rather than a defence.** The
  shape considered first was a single factory taking two same-typed `Collection<String>` parameters,
  origins and domains, argued safe on the grounds that the two grammars are disjoint: an origin
  entry must contain `://`, a domain entry containing `://` would be refused, and a hostname offered
  as an origin fails on "must be https", so a transposed call could not assemble. That argument
  holds, and it is still an argument about what strings a caller happens to pass. The convention
  here is that several same-typed required values are made swap-proof by value types rather than by
  argument order, and that a value type earns its place by also carrying validation —
  `TransitKeyName` and `VaultToken` are the precedent, and a rule that validates its own entry at
  construction and cannot be mistaken for the other kind fits it exactly. Swap-proofness stops being
  a property of the contents and becomes a property of the types. Being a value, a rule is equal by
  kind and normalized entry, so a list of rules collapses duplicates as the `0.1.0` origins path
  already does through its set — value equality is not something that can be added after release
  without changing what every consumer's collection of rules does. An entry is a validated host or
  origin and never a capability URL, so nothing a rule carries is what the endpoint redaction exists
  for.
- **The hierarchy is closed, and closing it is what keeps this from being a seam.** `EndpointRule`
  is sealed, both permitted implementations are private to it, and the method by which a rule
  matches an endpoint is package-private, so nothing outside the library can add a rule kind or
  implement one. It is an enumeration of the kinds the library supports, not an extension point:
  ADR-005's bar — a seam only where there is an articulable difference the library cannot decide for
  the deployment — is untouched, and no SPI is added. `EndpointPolicy` remains the seam it already
  was, and a deployment whose rule is neither of these still writes the lambda ADR-005 provides.
- **A domain rule covers the apex and every subdomain at any depth, matched at a label boundary**:
  `host.equals(domain) || host.endsWith("." + domain)`. The dot belongs to the suffix, not to the
  string being searched — without it `evilnotify.windows.com` matches `notify.windows.com`. That is
  the whole vulnerability class, it costs one character, and it is the bug every consumer writing
  this rule by hand reaches independently.
- **The endpoint is parsed and normalized once, by the same code the origin serialization already
  uses, and every rule sees only that normalized value** — never a `URI.getHost()` call of its own.
  Two normalizers mean two answers for one endpoint, and they diverge precisely in the
  internationalised cases nobody exercises by hand. The two endpoint-side refusals that guard the
  comparison today hold unchanged for every rule kind: an endpoint carrying userinfo is rejected
  outright, before any comparison, and one with no scheme or host is rejected as having no origin to
  compare at all.
- **A domain rule matches only the scheme `https` and the default port**, an absent port or an
  explicit `443`. The scheme is anchored explicitly rather than inherited: the origin serialization
  does not enforce a scheme, by its own documented contract — that is `Endpoints.requireSecure`'s
  job at the `Subscription` boundary — and an origin rule is protected for free only because it
  compares the whole serialization including `https://`. The port is a decision rather than an
  accident: a domain rule is a statement about which *names* are trusted, while a port is a
  statement about which *service on a host* is trusted, and permitting every port across a zone
  re-creates the blind SSRF oracle ADR-016 exists to close, relocated into an external zone. A
  deployment that genuinely needs `https://host.zone:8443` names it exactly with an origin rule,
  which is the right granularity for a port.
- **A malformed domain entry fails at construction**, as a malformed origin entry already does, and
  every message renders the entry through `Endpoints.redact`. Refused: an empty entry; `:` (which
  catches both a port and a pasted `https://x`, an entry that would otherwise parse with the host
  `https`); `/`, `?` or `#` (a pasted capability URL, whose path would be silently ignored); `@`
  (`notify.windows.com@evil.example` parses with the host `evil.example`, so everything the operator
  wrote is discarded); `*` (the CSP and cookie habit); a leading dot or an empty label; a trailing
  root dot, which `java.net.URI` accepts as a host and which would leave the rule unable to ever
  fire — a dead entry that looks configured; a single label (`com`, `localhost`); an IP literal,
  since an address has no subdomains and an operator reads `EndpointRule.domain("10.0.0.0")` as a
  subnet; and raw Unicode. A closing check that the entry equals the host the parser found, ignoring
  case, is the complete defence against the scheme concatenation reinterpreting the entry — which is
  what lets the list above exist for the sake of its *messages* rather than for completeness.
  Validation runs through the same `java.net.URI` the endpoint side uses, never a hand-rolled
  hostname regex, so a configured entry can never be a shape an endpoint could never have; a regex
  would be a second grammar of "a valid host" to keep in step with the first.
- **A domain entry is then normalized, not merely validated** — put through the same serialization
  the endpoint side is, so that case and internationalised form agree on both sides of the
  comparison. An origin entry is already normalized rather than only checked, and a domain entry
  that were only checked would accept two spellings and leave them permanently inert:
  `NOTIFY.WINDOWS.COM`, which passes a case-insensitive check while every endpoint host arrives
  lowercased, and the A-label spelling that the raw-Unicode refusal above directs the operator to,
  which can never meet a host decoded to its U-label. Both are the dead entry that looks configured,
  the failure the trailing-root-dot refusal exists to prevent, and one of them would be the form the
  library itself recommends. Normalization runs after the closing equality check rather than in
  place of it: that check is validation against the concatenation reinterpreting the entry, and
  neither does the other's work.
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
- **A domain rule misreads in the dangerous direction** — as "an origin, minus the scheme", that is,
  exact host matching, which leaves the operator believing the rule is narrower than it is. It is
  therefore normative that the first Javadoc sentence of `EndpointRule.domain` and of
  `allowedDomains`, the one an IDE shows, leads with subdomains, and that the Spring property's
  documentation does the same.
- **Every entry point requires at least one entry, and no emptiness asymmetry has to be explained.**
  `allowedEndpoints` refuses an empty list of rules; `allowedOrigins` and `allowedDomains` each keep
  their own single-list refusal and its wording. One list of self-describing values is what removes
  the question — a union factory over two per-kind collections would have had to accept an empty one
  on either side while its single-kind siblings refused one, and that exception would then have had
  to be documented, tested and remembered.
- **The behaviour of the origins-only path is frozen, and the freeze is scoped to behaviour.**
  `allowedOrigins` shipped in `0.1.0`, and nothing about which entries it accepts and which it
  refuses, the exception types it throws, or the order in which an entry meets those checks may
  drift *as a consequence of being reimplemented* over `EndpointRule.origin`. Drift is what the
  freeze forbids; a check this decision adds deliberately — the one named in the next bullet — is
  the single exception, and it is a change made on purpose rather than a side effect of moving the
  code. The freeze is a promise about the convenience factory and not about the rule's internals:
  whatever the rule throws, `allowedOrigins` presents what it presented in `0.1.0`. The literal text
  of every message is deliberately *not* frozen — a refusal gaining precision is not the drift being
  guarded against, and freezing prose would forbid that exception. One consequence is worth stating
  rather than leaving to be discovered: the Spring path no longer runs through this factory at all,
  since the attribution decision below has the starter build a rule per entry, so what an operator
  sees for a malformed `push2u.allowed-origins` entry comes from the rule rather than from the
  frozen factory. That is legal precisely because the text is not frozen and the exception type is
  pinned by reference, but the freeze should not be read as covering the commonest consumer path.
- **One refusal changes, and it is named here rather than left to the implementation**: an *origin*
  entry carrying a `*` where a host label belongs earns its own construction check on the origin
  rule, refusing it with a message naming the domain rule. (A `*` in a *domain* entry is refused by
  the construction checks above.) The criterion is the host position and not the presence of the
  character: `https://example.com/*` and `https://a*b@example.com` are already refused today for
  being more than a bare `scheme://host[:port]`, which is the right thing to tell their author, and
  a check firing on a `*` anywhere would capture them and send them to the domain rule instead. For
  the same reason it has to be its own check rather than a repointing of the branch a wildcard host
  currently falls into, which is not `*`-specific either — a leading dot, an empty label and a raw
  Unicode host all reach it too, since `java.net.URI` yields no host for any of them. The
  raw-Unicode entry's present advice — spell the host in its A-label form — is correct, and a domain
  rule refuses raw Unicode as well, so repointing the branch would replace right advice with wrong
  for every entry that is not a wildcard.
- **Spring gains `push2u.allowed-domains` beside `push2u.allowed-origins`.** ADR-016's refusal of a
  property was about a *mode*: a flag that removes the control, whose danger is that it travels
  between profiles as a copied line. A domain list is data: it cannot be set to a value that
  disables the control. The asymmetry that decided ADR-015 and ADR-016 — a property can be added
  later without breaking anyone, and cannot be removed after a release — argues as it always did
  that withholding is the cheap default, and it is not overridden lightly. What overrides it here is
  the pressure withholding puts on a Spring deployment serving Edge, which is a claim about the
  choice on offer rather than a prediction of which branch is taken. A bean is exclusive with the
  property, so one extra rule costs the three ordinary origins their place in YAML too; what is left
  is a `@Bean` carrying the hostnames *and* the matching rule, or one of two bad built-in outcomes
  — `EndpointPolicies.unrestricted()`, which is unrestricted egress, or an allowlist of the three
  fixed origins, which silently excludes a major browser's users. The third is a real outcome and a
  different failure: an Edge subscription is registered, then permanently rejected at every send
  with a WARN. Nothing about it is unsafe and no startup fails — the feature simply does not work
  for those users, which is the kind of failure that survives review by being invisible. The
  property is admitted precisely because it makes the safe answer reachable by the route operators
  already use.
- **The starter's existing rules are restated over two properties, and attribution becomes exact.**
  "Expressed" means at least one of the two properties is non-empty. **Two non-empty properties are
  not a conflict: they are unioned into one allowlist**, which is the shape the WNS case needs —
  three origin entries beside one domain entry. The exclusivity ADR-016 established holds between
  the properties and a bean, never between the two properties, which are two halves of one statement
  rather than two statements of the same control. Both sources at once — expressed, plus a bean —
  still fails the context, naming which property is non-empty and naming the bean. Neither of them —
  both properties unset, no bean — still fails, now offering three ways to fix it instead of two.
  The empty-value escape hatch keeps its shape, because it was always per-property: an explicitly
  empty value means "this property is deliberately unused here", and a service empties whichever key
  it inherited. One case changes character: every set property empty, with no bean. Today the
  starter delegates that refusal to the core, which answers in its own words; with two properties
  the emptiness is a statement about the *pair*, and no single core factory can speak for both, so
  the starter owns a message naming both keys. Attribution of a malformed entry then needs no
  machinery at all: the starter builds each rule itself, from one entry of one named property, so at
  the moment the rule refuses it holds both the property name and the entry's index. The shape
  considered first had to borrow the starter's `retryPolicy` probe-and-discard precedent and then
  adjust it, because one call over two lists could not say which list a bad entry came from; none of
  that survives, and it is the strongest single argument for rules as values.
- **Both property components are nullable, neither carries a `@DefaultValue`, and unset stays
  distinguishable from explicitly empty.** An absent key binds as `null`; a key set to an empty
  value binds as an empty list. Every Spring rule above rests on that difference and none survives
  without it: "expressed" means at least one property is non-empty, the escape hatch *is* an
  explicitly empty value, and the neither-case failure fires only when both are unset. A
  `@DefaultValue` on either component would collapse the two — an unset property would arrive as an
  empty list — and the starter would lose the distinction between "this deployment has not decided"
  and "this deployment deliberately cedes to a bean", which are the two cases it has to answer
  differently: a context failure naming three ways to fix it, against a bean quietly winning. This
  is the shape the single `0.1.0` component already has; it is recorded as a decision because with
  two properties it stops being an implementation detail of one binding and becomes the premise the
  semantics above are stated in.
- **The constructor `Push2uProperties` shipped with is preserved.** Adding a component widens the
  record's canonical constructor, and a changed descriptor on an already-published constructor is a
  `NoSuchMethodError` for anything compiled against `0.1.0` — the same incompatibility this decision
  refuses to pay for the provenance-restricted `anyOf` below, where it is the whole reason that
  alternative cannot be built. Accepting it here while refusing it there would leave a later reader
  unable to tell which of the two is the rule, and this document cannot be amended once its decision
  is implemented. So the shipped constructor stays, the wider canonical constructor is what Spring
  binds through, and because the record then has more than one constructor the binding target is
  named rather than inferred — `@ConstructorBinding` on the canonical one. That ambiguity is why
  this is a decision and not an implementation detail: with a single constructor the framework needs
  no annotation, so adding a second silently changes what "the constructor" means. What does change,
  unavoidably for any added component, is `equals`, `hashCode`, `toString` and the arity a record
  pattern spells — none of which is a linkage failure for code already compiled.

Rejected alternatives:

- **A public `anyOf(EndpointPolicy...)`.** It is a union of permissions wearing the grammar of a
  restriction: `anyOf(allowedOrigins(...), unrestricted())` *is* `unrestricted()` while reading in a
  diff as an allowlist — a direct attack on the only mechanism ADR-016 has, which was making
  `unrestricted()` a visible token in the consumer's own source. A deny-shaped custom policy
  composed into it is silently neutered, and deny-shaped is what a custom policy usually is. The
  diagnostics collapse too: a policy reports a refusal by throwing, so a generic union has to catch
  N exceptions to decide whether any member allowed the endpoint — turning exceptions into control
  flow — and then discard N messages to synthesise one, when the one thing an operator needs from a
  rejection is which rule refused and why.
- **An `anyOf` restricted to the rules this class itself built.** Enforcing that at compile time
  would require `allowedOrigins` to return a library-owned subtype, and a changed descriptor on an
  already-published method is a `NoSuchMethodError` for everyone compiled against `0.1.0`. What
  remains is a runtime `instanceof` check — an API that publishes a combinator over a public
  interface and then refuses implementations of that interface, which is worse than no API at all,
  because it refuses the composition every reader tries first. Composition of *rules* inside one
  allowlist is what `allowedEndpoints` provides instead, and it composes the things that can be
  meaningfully unioned rather than arbitrary policies.
- **A `default` method such as `or` on `EndpointPolicy` itself.** Everything above, plus: the
  combinator lands on the SPI and is inherited by every third-party implementation, and it adds a
  permanent member to a published `@FunctionalInterface`. The asymmetry it would teach is the wrong
  one — intersection is the safe combinator and union is not — and a consumer narrowing an allowlist
  with their own deny rule writes a two-line lambda.
- **A third property, `push2u.allowed-endpoints`, whose entries carry mandatory `origin:` /
  `domain:` tags.** The danger it guards against is real and its guard is the right one: tags have
  to be mandatory, because an entry taken for a domain merely by lacking a scheme would turn a
  forgotten `https://` into a silently wider rule. What the unified key would buy is one list
  holding both kinds interleaved, in the order the operator wrote them — which nothing needs today,
  since a rule either matches or it does not and the order of the list carries no meaning. Against
  that, two typed keys already give the same protection without a parser — **the YAML keys are the
  tags**, hoisted to where a typo fails the binder instead of a hand-rolled split — while a tag
  inside a value needs a specification of its own: surrounding whitespace, case, an unknown tag, and
  splitting on the first colon only, since `origin:https://x` carries a second one. It would also
  leave three spellings of one allowlist and a matrix of legal combinations between them; ADR-016
  declined to keep the optional builder step beside the required parameter partly because one sender
  would have had two spellings, and three is further along the same line. Failing fast on a mix of
  styles means nothing is silently ignored, so this is a judgement about surface and documentation
  rather than about danger. It is rejected now and on these grounds, not in principle: adopting a
  unified key later would mean deprecating `push2u.allowed-origins`, which at `0.x` costs little, so
  the case for two keys rests on the parser and the migration rather than on deprecation being
  expensive.
- **A wildcard entry such as `https://*.notify.windows.com` inside an origin rule.** It is the least
  legible possible spelling of "and this one is an entire DNS zone", sitting in a list of visually
  identical origins, when ADR-016's whole thesis is that the security-relevant choice must be
  legible in a diff. And `*` announces a pattern language that does not exist: `https://*`,
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
- **Publishing the normalizer instead of the rule.** Exporting the origin serialization answers the
  wrong question: ADR-005 admits a seam where there is a difference the library cannot decide for
  the deployment, and here the matching rule is universal while only the list is
  deployment-specific. Handing out the normalizer means every consumer re-derives the label boundary
  and writes the `evilnotify` bug. It would also freeze the serialization, whose exact output is
  changeable today only because both call sites are inside the package.
- **A regex rule, or a predicate factory.** A regex over a hostname is the canonical source of this
  same vulnerability class — unanchored patterns, and `.` matching any character. A
  `Predicate<String>` factory adds nothing over the `EndpointPolicy` lambda ADR-005 already
  provides, only surface.
- **Letting a domain rule match any port or any scheme**, which is a port and protocol oracle over
  an unbounded set of hosts; and **expressing all four push services as domains**, which widens
  three single-host services to three zones for no gain.

This rules out a public combinator over `EndpointPolicy`, whether on `EndpointPolicies` or on the
interface; a rule kind contributed from outside the library; a domain rule matching a scheme other
than `https` or a port other than the default; a pattern or wildcard syntax inside an origin entry;
a public-suffix judgement made by the library, by dependency or by bundled data; and a push
service's zone shipped as a default. `EndpointPolicies.unrestricted()` is untouched, and
`Endpoints.requireSecure` stays what ADR-005 called it: a protocol check, not a security control.
Neither `module-info.java` changes — the new type joins an already-exported package — nor
`push2u-testkit`, since a sealed hierarchy with private implementations is the opposite of a seam
and there is no contract here for a third party to satisfy.
