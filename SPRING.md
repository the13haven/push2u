# Spring Boot integration

`push2u-spring-boot-starter` binds the `push2u.*` properties to an autoconfigured `PushSender`.
This is the configuration reference — [`README.md` → Spring Boot](README.md#spring-boot) carries
the dependency coordinate, the Spring Boot version the starters need, and the minimal working
configuration.

## Properties

Configure a local VAPID signer:

```yaml
push2u:
  vapid:
    public-key: "${VAPID_PUBLIC_KEY}"
    private-key: "${VAPID_PRIVATE_KEY}"
    subject: "mailto:ops@example.com"
  jwt-expiry: 12h
  default-ttl: 24h
  record-size: 4096                 # defaults, shown for reference
  max-encrypted-body-bytes: 4096    # defaults, shown for reference
  allowed-origins:                  # optional but recommended — see Endpoint policy in the README
    - "https://fcm.googleapis.com"
    - "https://updates.push.services.mozilla.com"
    - "https://web.push.apple.com"
  retry:
    max-attempts: 3
    initial-backoff: 1s
    max-backoff: 60s
```

The starter creates a `VapidSigner`, `PushHttpClient`, and `PushSender`. Application beans of the
same types take precedence.

`push2u.vapid.subject` is required to build the *autoconfigured* `PushSender`, regardless of where
the `VapidSigner` comes from; leaving it unset fails the context with a message naming the
property. It is not required when the application supplies its own `PushSender` bean — that bean
bypasses the starter's checks entirely.

`jwt-expiry`, `default-ttl`, `record-size` and `max-encrypted-body-bytes` are optional; unset, they
leave `PushSender`'s defaults untouched (12h, 24h, 4096 bytes and 4096 bytes respectively — see
[`README.md` → Payload size limits](README.md#payload-size-limits) for the two size properties).
The three `retry.*` properties carry their own defaults instead (3 attempts, 1s initial backoff,
60s ceiling), which match `RetryPolicy.defaults()`, so a `RetryPolicy` is always built explicitly.

Setting any of them to a value the builder — or, for `retry.*`, `RetryPolicy` itself — rejects
(`jwt-expiry` not strictly positive or over 24h, `default-ttl` negative, `record-size` below 18,
`max-encrypted-body-bytes` below the fixed 103-byte `aes128gcm` overhead, `retry.max-attempts`
below 1, or either `retry.*` backoff negative) fails the context with that message, prefixed by the
YAML property name (the builder and `RetryPolicy` only name their Java parameters). Both backoff
bounds share one message in `RetryPolicy`, so the prefix is the only thing that says which of the
two you got wrong.

## Endpoint policy

`allowed-origins` binds to `EndpointPolicies.allowedOrigins` — see
[`README.md` → Endpoint policy (SSRF hardening)](README.md#endpoint-policy-ssrf-hardening). Unset,
it leaves the `PushSender` default of no endpoint policy. A malformed entry fails the context with
the message prefixed by the property name, like the size properties. Alternatively, supply an
`EndpointPolicy` bean, which the autoconfigured sender picks up; configuring *both* the property
and a bean fails the context, naming the property and the bean — they express the same security
control, and silently preferring one would leave the other believed-active but ignored.

One escape hatch: a service that *inherits* `push2u.allowed-origins` from a shared configuration
it does not own cannot unset the property, so setting it to an explicitly **empty** value beside
a bean means "deliberately not using the property here" and the bean wins. An empty value on its
own still fails the context (`requires at least one origin`), so the control cannot be disabled
by accident.

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
a startup failure naming `push2u.vapid.subject`), so this changes nothing there. Where it matters
is a context that *excludes* `Push2uAutoConfiguration` and wires its own `PushSender` around a
signer kept as a bean: the probe then applies to exactly the signer that sender uses.

An application that supplies its own `PushSender` and no `push2u.vapid.*` therefore gets no
indicator: that sender's signer lives inside it, where the starter cannot reach it, and an
indicator reporting health it never established would be worse than its absence. When the entry is
missing and you expected it, `/actuator/conditions` (or starting with `--debug`) names the bean the
condition did not find. Note the flip side of probing a bean: an application that supplies both its
own `PushSender` *and* `push2u.vapid.*` gets an indicator that exercises the signer built from
those properties, not the one inside its sender.
