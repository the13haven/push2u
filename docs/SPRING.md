# Spring Boot integration

`push2u-spring-boot-starter` binds the `push2u.*` properties to an autoconfigured `PushSender`.
This is the configuration reference — [`README.md` → Spring Boot](../README.md#spring-boot)
carries the dependency coordinate, the Spring Boot version the starters need, and the minimal
working configuration.

## Properties

Configure a local VAPID signer:

```yaml
push2u:
  vapid:
    public-key: "${VAPID_PUBLIC_KEY}"
    private-key: "${VAPID_PRIVATE_KEY}"
    subject: "mailto:ops@example.com"
  jwt-expiry: 12h
  jwt-renew-before: 5m
  jwt-reuse: true
  jwt-cache-size: 64
  default-ttl: 24h
  record-size: 4096                 # defaults, shown for reference
  max-encrypted-body-bytes: 4096    # defaults, shown for reference
  allowed-origins:                  # one of the two is required, unless an EndpointPolicy bean
    - "https://fcm.googleapis.com"  # supplies the allowlist instead
    - "https://updates.push.services.mozilla.com"
  allowed-domains:                  # a whole DNS zone per entry — see Endpoint policy below
    - "push.apple.com"
    - "notify.windows.com"
  retry:
    max-attempts: 3
    initial-backoff: 1s
    max-backoff: 60s
```

The starter creates a `VapidSigner`, `PushHttpClient`, and `PushSender`. Application beans of the
same types take precedence.

`push2u.vapid.subject` is required to build the *autoconfigured* `PushSender`, regardless of where
the `VapidSigner` comes from; leaving it unset fails the context with a message naming the
property. The endpoint policy is required in the same way, from one of its two sources — see
[Endpoint policy](#endpoint-policy). Neither is required when the application supplies its own
`PushSender` bean — that bean bypasses the starter's checks entirely.

`jwt-expiry`, `jwt-renew-before`, `jwt-reuse`, `jwt-cache-size`, `default-ttl`, `record-size` and
`max-encrypted-body-bytes` are optional; unset, they leave `PushSender`'s defaults untouched (12h,
5m, `true`, 64 entries, 24h, 4096 bytes and 4096 bytes respectively — see
[`README.md` → Payload size limits](../README.md#payload-size-limits) for the two size
properties). The three `retry.*` properties carry their own defaults instead (3 attempts, 1s
initial backoff, 60s ceiling), which match `RetryPolicy.defaults()`, so a `RetryPolicy` is always
built explicitly.

Setting any of them to a value the builder — or, for `retry.*`, `RetryPolicy` itself — rejects
(`jwt-expiry` not strictly positive or over 24h, `jwt-renew-before` negative, `jwt-cache-size`
below 1, `default-ttl` negative, `record-size` below 18, `max-encrypted-body-bytes` below the fixed
103-byte `aes128gcm` overhead, `retry.max-attempts` below 1, or either `retry.*` backoff negative)
fails the context with that message, prefixed by the YAML property name (the builder and
`RetryPolicy` only name their Java parameters). Both backoff bounds share one message in
`RetryPolicy`, so the prefix is the only thing that says which of the two you got wrong.

**The three `jwt-*` reuse properties are the ones to know about before something surprises you.**
With `jwt-reuse` at its default, an autoconfigured sender signs one VAPID token per push-service
origin and reuses it for every later message to that origin until it is within `jwt-renew-before`
of expiry, holding at most `jwt-cache-size` of them and evicting the least recently used.
`jwt-reuse: false` restores a fresh signature per message.
[`README.md` → VAPID token reuse](../README.md#vapid-token-reuse) says what each of the three is
for and when a deployment reaches for it. Neither `jwt-renew-before` nor `jwt-cache-size` is
validated against `jwt-expiry` or against the other: a margin at or above `jwt-expiry` is not an
error but simply means every send signs afresh, and a cache bound is never a second way to spell
`jwt-reuse: false`, which is why below 1 is refused rather than read as "cache nothing".

## Endpoint policy

The autoconfigured `PushSender` needs an `EndpointPolicy`, because every `PushSender` does — which
endpoints a deployment may POST to is a decision it has to express, and a subscription's endpoint
is attacker-influenced wherever subscriptions are registered by clients. See
[`README.md` → Endpoint policy (SSRF hardening)](../README.md#endpoint-policy-ssrf-hardening) for
the threat model and the limits of a URI-level check.

The starter takes that decision from one of two **sources**, and exactly one of them:

- **The allowlist properties**, `push2u.allowed-origins` and `push2u.allowed-domains`. An origin
  entry is one origin, matched exactly; a domain entry is a whole DNS zone, the apex and every
  subdomain at any depth, over `https` on the default port only.
  [`PUSH-SERVICES.md`](PUSH-SERVICES.md) has the four browser push services in this form — two
  origins, and two domains for the two services that publish a zone rather than a host.
- **An application `EndpointPolicy` bean**, which the autoconfigured sender picks up. This is the
  route for anything the properties cannot express — a corporate egress rule, a custom check, or
  `EndpointPolicies.unrestricted()`.

**The two properties are not two sources.** They are two halves of one statement, and a context
setting both gets one allowlist holding all of their entries — which is exactly the shape a
deployment naming the browser push services needs, since some of them publish a host and some a
zone. The decision is *expressed* when at least one of them is non-empty.

Expressing it **and** supplying a bean fails the context, naming whichever property is non-empty
and naming the bean — they express the same security control, and silently preferring one would
leave the other believed-active but ignored. Expressing **neither** — both properties unset, no
bean — fails the context too, with a message naming the three ways to fix it: a sender wired
without a policy would POST wherever a subscription's endpoint points, and that is not an outcome
anyone should reach by leaving a property out.

One escape hatch, and it is per property: a service that *inherits* `push2u.allowed-origins` from
a shared configuration it does not own cannot unset the property, so setting it to an explicitly
**empty** value means "deliberately not using this property here" — beside a bean, the bean wins;
beside the other property, that property carries the allowlist alone. Every set property empty with
no bean still fails the context, with a message naming both keys: emptying them is a statement
about the pair, and no single entry is left to refuse on its own terms.

A malformed entry fails the context named exactly — the property it came from and its index in that
property's list, `push2u.allowed-origins[2]`, since the starter builds each rule itself from one
entry of one named property. The entry appears in the message the way an endpoint appears in a
rejection: an origin entry with its path and query stripped, because a pasted capability URL is
precisely the mistake being reported, and a domain entry verbatim only when it is a plain
host-shaped token.

### No property turns the restriction off

There is deliberately no `push2u.*` flag for unrestricted egress. Sending anywhere is a legitimate
choice where subscriptions never arrive from untrusted clients, but under Spring it is expressed as
a bean:

```java
@Bean
EndpointPolicy endpointPolicy() {
    // Subscriptions here are entered by operators, never registered by clients.
    return EndpointPolicies.unrestricted();
}
```

A YAML flag reaches production by copying a dev profile; a bean is a code change that passes a
review. A property could be added later without breaking anyone, and could not be removed after a
release — so the asymmetry decides it.

`push2u.allowed-domains` is not a hole in that. What the refusal is about is a *mode*: a flag whose
danger is that it removes the control and travels between profiles as one copied line. A domain list
is data — every value it can hold is a restriction, and there is no value of it that turns the
restriction off. The asymmetry above still argues, as it always does, that withholding a property is
the cheap default, and what overrides it here is the pressure withholding puts on a Spring
deployment serving the two services that publish a zone rather than a host — Safari's and Edge's, a
major browser's users each. A bean is exclusive with the properties, so reaching for one to express
those two zones costs every ordinary origin its place in YAML too: what
is left is a `@Bean` carrying the hostnames *and* the matching rules, or one of two bad answers the
starter can otherwise give — `EndpointPolicies.unrestricted()`, which is unrestricted egress, or an
origins-only allowlist, which can express neither zone.

That second answer is the quieter failure, and it is quiet in two different ways. Edge's endpoints
sit on varying subdomains, so an origins-only allowlist refuses them now: the subscription is
registered and then refused at every send for the rest of its life, and the application sees an
`EndpointRejectedException` per send and nothing else, since the core has no logger of its own.
Safari's sit on one host today, so naming that host works — until Apple uses the rest of the zone
its own documentation reserves, and those subscriptions then fail the same way. Neither is unsafe
and neither fails a startup, so there is nothing in a review to notice; the feature simply stops
working for those users. The property exists so that the safe answer is reachable by the route
operators already use.

## Health indicator

When Spring Boot health support is present, the starter also exposes
a health indicator that exercises the configured signer end to end: it signs a probe input and
verifies the resulting 64-byte ES256 signature locally against the signer's advertised public
key — so a signer that returns bytes which do not verify (a mispinned Vault `public-key`, for
instance) reports `DOWN` instead of failing every real send with `401`/`403`. On the rare JVM
whose providers offer no ES256 verification primitive at all, the probe degrades to checking the
signature length only and says so in the payload with a fixed `verification: unavailable` detail
(plus a one-time WARN); the detail's absence means the `UP` went through full verification.

Because the health endpoint is polled (Kubernetes probes commonly hit it every ~10 seconds per
pod) and each probe of a remote signer is a full backend round-trip — against Vault Transit, one
sign operation that is written to every audit device, counted against rate-limit quotas and, for
`managed_key`-backed keys, billed as an HSM operation — the probe result is cached per process:

```yaml
push2u:
  health:
    enabled: true      # default — false removes the indicator, so health never touches the signer
    cache-ttl: 30s     # default — how long a successful probe result is reused
```

A successful result is served from cache for `cache-ttl`; a *failed* result for at most 5 seconds
(the shorter of `cache-ttl` and 5s), so recovery is noticed quickly even under a long TTL.
Concurrent health evaluations are collapsed into a single signing operation. `cache-ttl: 0s`
disables caching entirely; negative values fail startup naming the property. The cache is
per-process by design — probes ask about the pod they run in.

The indicator participates in the health endpoint's primary group only. Spring Boot's `liveness`
group contains just the application's own liveness state, so a signer outage can never restart
pods — an unreachable Vault is not something a container restart fixes.

The indicator is registered when a `VapidSigner` bean exists, and asks about nothing else: the
signer is the only part of a send that can stop working while the application runs — it reaches a
backend that can go down, holds a token that can expire, names a key that can be deleted — while
the rest of a `PushSender` is configuration the builder validated at startup.

While the main autoconfiguration is active, a signer bean gives you a `PushSender` bean as well (or
a startup failure naming `push2u.vapid.subject` or the allowlist properties), so this changes
nothing there. Where it matters is a context that *excludes* `Push2uAutoConfiguration` and wires its
own `PushSender` around a signer kept as a bean: the probe then applies to exactly the signer that
sender uses.

An application that supplies its own `PushSender` and no `push2u.vapid.*` therefore gets no
indicator: that sender's signer lives inside it, where the starter cannot reach it, and an
indicator reporting health it never established would be worse than its absence. When the entry is
missing and you expected it, `/actuator/conditions` (or starting with `--debug`) names the bean the
condition did not find. Note the flip side of probing a bean: an application that supplies both its
own `PushSender` *and* `push2u.vapid.*` gets an indicator that exercises the signer built from
those properties, not the one inside its sender.
