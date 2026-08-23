# Observability

push2u emits nothing on the send path: no meters, no spans, no log lines. (One thing in the tree
logs — the Spring starter's health indicator, which warns when its probe starts failing, debugs
while the failure persists, and warns once where the JVM's providers cannot verify ES256. All of it
is readiness, not a view of delivery.) What it publishes instead is the *meaning* of a send —
a sealed `PushOutcome` naming exactly what happened, three seams whose calls are worth counting, and
a redaction that decides which parts of an endpoint may be rendered at all. The
telemetry framework, the meter names, the tag vocabulary, the sampling and the export are the
deployment's, and this document is the convention worth sharing so that two teams instrumenting the
same library do not end up with two vocabularies.

The examples use Micrometer because it is the facade a Spring Boot application already has. Nothing
here depends on it: the same recipes fit OpenTelemetry, Dropwizard Metrics or a counter you increment
yourself. push2u has no telemetry dependency under the current decision —
[ADR-031](adr/0031-telemetry-is-emitted-by-the-deployment.md) is that record, including the one
question it deliberately leaves open and the evidence that would reopen it.

## Where each question is answered

| Question | Where it is answered | What it costs |
|---|---|---|
| How many sends, of what outcome, how long | the call site — `send` returns the answer | a `try`/`finally` and a `switch` |
| How many POSTs, how long, how many unanswered | a `PushHttpClient` decorator | one class |
| How often the egress allowlist refused | an `EndpointPolicy` decorator | one class |
| How many real signing operations the custodian served | a `VapidSigner` decorator | one class, and the section below on what it counts |
| Attempts, retry delay, dead-lettering | the caller's scheduler | push2u does not retry |

Start with the first row. It is the only one that sees the library's own classification, it needs no
Spring wiring at all, and for most deployments it is the whole of what is wanted.

## Instrumenting `send`

One `Timer` carries both the rate and the latency, so no separate counter is needed beside it.

```java
public PushOutcome deliver(Subscription subscription, PushMessage message) {
    Timer.Sample sample = Timer.start(registry);
    String service = serviceOf(subscription);  // total by construction — see the rule below
    String outcomeTag = "error";
    try {
        PushOutcome outcome = sender.send(subscription, message);
        outcomeTag = tagFor(outcome);
        return outcome;
    } catch (PushInterruptedException e) {
        outcomeTag = "interrupted";
        throw e;
    } finally {
        sample.stop(Timer.builder("push2u.send")
                .tag("outcome", outcomeTag)
                .tag("service", service)                   // a closed set — see below
                .register(registry));
    }
}
```

The initial value and the one `catch` are not decoration. `send` answers every *operational* result
with a value, but it still throws on a defect or an unusable substrate — `PushCryptoException`,
`IllegalArgumentException`, `NullPointerException` — and `PushInterruptedException` when the sending
thread was interrupted. A meter that only switches over `PushOutcome` records nothing at all for
those, which is precisely the case an operator most wants to see rise.

**The rule the tag computation follows: it must not throw, and it must not change what the send
does.** Both failures are easy to write and neither shows up in a test that passes a good
subscription. Building a tag inside `finally` lets a throw there replace the exception the send was
about, and the measurement goes with it. Building it before the `try` moves the throw earlier, where
it pre-empts `send` entirely — a `null` subscription would then be reported as an instrumentation
error and never as the `NullPointerException` this library documents, and the timer would never be
stopped at all. So `serviceOf` is *total*: it answers `other` for a `null` subscription rather than
refusing, and the rest of it cannot throw because `Subscription` validated its endpoint at
construction. The meter observes the send; it does not get a vote in it.

**Asynchronously**, instrument the future rather than the call: `sendAsync` runs `send` on the
executor you supplied, or on this library's own virtual-thread executor. **push2u performs no
context propagation of its own and promises none** — what a worker sees depends on the executor,
on how the context is implemented and on the JDK. An ordinary `ThreadLocal` does not cross;
an `InheritableThreadLocal` may, since a thread created per task inherits from its creator; an MDC
or an open observation scope crosses only if the executor you supplied carries it. Do not reason
from the default: instrument the future, where the answer does not depend on any of that.

```java
Timer.Sample sample = Timer.start(registry);
return sender.sendAsync(subscription, message).whenComplete((outcome, failure) -> sample.stop(
        Timer.builder("push2u.send")
                .tag("outcome", failure == null ? tagFor(outcome) : tagForFailure(failure))
                .tag("service", service)
                .register(registry)));
```

`CompletableFuture` wraps a thrown failure in a `CompletionException`, so unwrap the cause before
classifying it. One path this sample does not cover: an executor you supplied can reject the task
*synchronously* with a `RejectedExecutionException`, in which case no future is returned, the
`whenComplete` is never attached and the sample is never stopped. Wrap the submission in its own
`try`/`catch` if a saturated pool is a state you need on the meter rather than only in the
exception. Note also that this sample starts before the task is submitted, so time spent queued on
the executor lands in the same timer as the send — which is usually what you want from an
application's point of view, but it is not the same measurement the synchronous recipe makes. Give
it its own meter name if you run both.

## The outcome vocabulary

Derive the tag from the sealed hierarchy, not from a list you maintain:

```java
static String tagFor(PushOutcome outcome) {
    return switch (outcome) {
        case PushOutcome.Accepted ignored -> "accepted";
        case PushOutcome.SubscriptionExpired ignored -> "subscription_expired";
        case PushOutcome.RetryableFailure ignored -> "retryable_failure";
        case PushOutcome.NonRetryableFailure ignored -> "non_retryable_failure";
        case PushOutcome.SignerUnavailable ignored -> "signer_unavailable";
        case PushOutcome.PayloadRejected ignored -> "payload_rejected";
        case PushOutcome.EndpointRejected ignored -> "endpoint_rejected";
        case PushOutcome.Indeterminate ignored -> "indeterminate";
    };
}
```

`PushOutcome` is sealed, so this `switch` is exhaustive without a `default` — and if a future
version adds a variant, *your* build fails on it rather than your dashboard quietly filing it as
something else. That is the reason to write the `switch` rather than a `Map` or a `getSimpleName()`
call.

The ten values, with the two thrown ones, are the vocabulary this document proposes:

| Tag value | Means |
|---|---|
| `accepted` | the push service took the message (`2xx`) |
| `subscription_expired` | `404`/`410` — delete the row; a repeat cannot succeed |
| `retryable_failure` | a repeat *may* be useful — the caller still decides whether it is safe and when; carries `retryAfter()` when the service sent one |
| `non_retryable_failure` | this identical request already has its answer, so repeating it buys nothing — not a forecast about the endpoint |
| `signer_unavailable` | the custodian could not sign *now*; nothing was sent |
| `payload_rejected` | too large for the configured body limit; nothing was sent |
| `endpoint_rejected` | the endpoint policy refused; nothing was sent, nothing left the process |
| `indeterminate` | the POST went out and nothing came back — **do not** count this as a failure to deliver |
| `interrupted` | `PushInterruptedException` — the sending thread was interrupted |
| `error` | anything else thrown: a defect, an unusable substrate, a recurring misconfiguration |

A status tag, if you want one, comes off the outcome — `Accepted.statusCode()`,
`SubscriptionExpired.statusCode()`, `RetryableFailure.statusCode()`,
`NonRetryableFailure.statusCode()` — normalised to a small set (`2xx`, `404`, `410`, `429`, `5xx`,
`other`). Take it from the outcome rather than from a transport decorator: the outcome already
carries the status *and* what this library concluded from it, and a second bucketing derived from
the raw response is a second answer to a question that has one.

**`SignerUnavailable.status()` does not belong in that tag.** It is the custodian's status, and the
two are different events wearing the same integer: a `503` from a push service means the POST was
made and refused, a `503` from a custodian means nothing was sent at all. Give it its own tag —
`custodian_status` beside `push_status` — or leave it off the main meter entirely and let `outcome`
carry it, which is what `signer_unavailable` is for.

## Tag safety

These are not style preferences. Each one is a way a metrics backend becomes either a disclosure or
a resource the remote side controls.

- **Never the capability-bearing part of the endpoint — anywhere, at any cardinality.** The whole
  URI, its path, one path segment, its query, one query value, its fragment; raw or percent-decoded;
  a meter tag, a span attribute, a log field. It is a capability URL (RFC 8030 §8.3): possession of
  it is authority to push to that browser. This library redacts it everywhere it renders one, and a
  tag is the least reviewed string in a deployment. The origin is the exception and gets its own
  rule two bullets down — it is the part this library itself prints.
- **Never a policy's refusal reason.** `EndpointAssessment.Refused` carries free prose written by
  whoever wrote the policy, for a human reading a log line. Nothing bounds its length, its
  cardinality or what it happens to quote.
- **Never the message of a cause, from either outcome that carries one.**
  `Indeterminate.cause()` is the transport's exception and its message can embed the URL it was
  posting to; `SignerUnavailable.cause()` comes from whatever custodian failed, and this library
  does not vouch for what is beneath it — the shipped Vault transport puts the (redacted) Vault
  address and the method in its own message, and the exception under that one is the JDK's. Both
  `toString()` implementations are safe by construction: neither prints a message, `Indeterminate`
  renders the cause's *class* and `SignerUnavailable` the custodian's status and retry hint. Log the
  outcome itself, or the cause's class — never its message, unless you redact it yourself first.
- **Never a raw origin or host as a *meter tag*.** Not for disclosure — the origin carries no
  credential — but for cardinality: an allowlist does not bound the value, since a domain rule
  matches the apex *and every subdomain*, which is exactly how Apple's and Microsoft's zones are
  written, and `EndpointPolicies.unrestricted()` bounds nothing at all. Stripping the scheme and the
  port does not help and loses a distinction this library makes: `https://push.example` and
  `https://push.example:8443` are different origins here.
- **Never an implementation's class name.** `VaultTransitVapidSigner` in a tag says something about
  your deployment's internals to everyone who can read the metric, and it changes under you when the
  bean is decorated.

So three rules, and they are different rules: the capability-bearing parts go nowhere; the raw
origin stays off meter tags but is a perfectly good high-cardinality field on a trace attribute or a
log line, where cardinality is expected and the field is not an aggregation key — that one is your
call; and a meter tag is always a closed set you named.

**The service tag is yours to define.** Map the endpoint's host to a fixed vocabulary and default
everything else to `other`:

```java
private static String serviceOf(Subscription subscription) {
    if (subscription == null) {
        return "other";            // a tag computation never decides whether a send happens
    }
    String raw = URI.create(subscription.endpoint()).getHost();
    if (raw == null) {
        return "other";
    }
    String host = raw.toLowerCase(Locale.ROOT);          // URI.getHost() preserves the case it parsed
    if (host.equals("fcm.googleapis.com")) return "fcm";                     // one exact host
    if (host.equals("updates.push.services.mozilla.com")) return "mozilla";  // one exact host
    if (under(host, "push.apple.com")) return "apple";                       // a zone, per the vendor
    if (under(host, "notify.windows.com")) return "wns";                     // a zone, per the vendor
    return "other";
}

private static boolean under(String host, String zone) {
    return host.equals(zone) || host.endsWith("." + zone);   // a label boundary, not a suffix
}
```

Three things in those eight lines are load-bearing, and each of them is a mislabelled tag if
dropped — a dashboard saying one vendor is failing when another is.

- **Match the two origins exactly.** Google and Mozilla publish one host each, and a zone match
  would file every other `googleapis.com` or `mozilla.com` service under a push service that never
  saw the request.
- **Match the two zones at a label boundary.** Apple and Microsoft publish wildcards, so a zone
  match is right there — but a bare `endsWith` files `evilnotify.windows.com` under `wns`, which is
  the mistake the allowlist's own domain rule exists to avoid.
- **Lower-case the host.** `URI.getHost()` returns it as parsed, so `FCM.GOOGLEAPIS.COM` falls into
  `other` without this.

The four names come from [`PUSH-SERVICES.md`](PUSH-SERVICES.md), which carries the vendor citation
for each and says plainly that it is a snapshot rather than something this repository verifies.

push2u ships no such mapping and will not: those are the push services' own zones, they change
without telling us, and this library shipping them as a default is ruled out for the same reason it
ships no allowlist. [`PUSH-SERVICES.md`](PUSH-SERVICES.md) is the snapshot to copy out of, with the
vendor citations and the warning that it is a snapshot.

## Decorating the three seams

Each seam is an interface you already supply, so a decorator is an ordinary delegating class. What
matters is what each one can and cannot see.

**`PushHttpClient` — the POST.** Times the exchange and separates "answered" from "nothing came
back".

```java
public PushResponse post(URI endpoint, Map<String, String> headers, byte[] body) {
    Timer.Sample sample = Timer.start(registry);
    String result = "error";
    try {
        PushResponse response = delegate.post(endpoint, headers, body);
        result = statusClass(response.statusCode());
        return response;
    } catch (PushDeliveryException e) {
        result = "no_response";
        throw e;
    } finally {
        sample.stop(registry.timer(
                "push2u.http.post", "result", result, "service", serviceOf(endpoint)));
    }
}
```

An HTTP timer is not a send timer: it excludes encryption, the VAPID token and everything the
sender does before and after, and it never fires at all for a `NotAttempted` outcome — a refused
endpoint, an oversized payload or an unavailable custodian never reaches the transport. Keep both
meters if you want the difference; keep only `push2u.send` if you want one.

**`EndpointPolicy` — the egress control.** The allowlist is a security control, and a control with
no counter is one nobody notices firing.

```java
public EndpointAssessment assess(URI endpoint) {
    EndpointAssessment assessment = delegate.assess(endpoint);
    String result = switch (assessment) {              // a null assessment is a defect, and this
        case EndpointAssessment.Allowed ignored -> "allowed";   // switch raises it rather than
        case EndpointAssessment.Refused ignored -> "refused";   // filing it as an admission
    };
    registry.counter("push2u.endpoint.assessed", "result", result).increment();
    return assessment;
}
```

No tag beyond that: not the endpoint, not the reason. A rise in `refused` is either an allowlist
that no longer matches the services in use or someone feeding hand-crafted subscriptions into the
registration boundary, and both are worth an alert. If the same policy instance is also applied
where subscriptions are registered — which is what it is published for — this counter sums both
boundaries; tag by call site at each of them if you need to tell them apart.

**`VapidSigner` — the custodian.** Read the next section before drawing conclusions from it.

```java
public byte[] sign(byte[] signingInput) {
    Timer.Sample sample = Timer.start(registry);
    boolean returned = false;
    try {
        byte[] signature = delegate.sign(signingInput);
        returned = true;
        return signature;
    } finally {
        sample.stop(registry.timer(
                "push2u.signer.sign", "result", returned ? "returned" : "threw"));
    }
}
```

`returned` and not `ok`: a custodian that answers is not yet a custodian that answered *correctly*.
Both are refused downstream while the token is minted, and not as the same thing: `sign` owes a raw
64-byte `r||s`, so a `null` signature becomes a `NullPointerException` and a wrong-length one a
`PushCryptoException`. A decorator labelling every return a success reports one where the send is
about to fail either way. Do not re-check the length here: that duplicates a rule the library already
owns, in a second place that can drift from it. Name what the decorator actually sees, and let
`outcome=error` on the send meter carry the rest.

## What a signer counter actually counts

Not sends — not, at least, with the defaults. push2u reuses the VAPID token until it nears expiry,
keyed by the push service's origin, so `sign` runs on a **token-cache miss**: roughly once per
distinct origin per token lifetime, plus whatever a cache eviction adds. That is what makes the
counter valuable: for a custodian like Vault Transit or an HSM it is a close estimate of the
operations actually being billed, audited and rate-limited. The custodian counts them too — Vault's
audit log records every request — but only this meter has them beside the sends that caused them,
on the application's own clock and with the application's own tags.

Four things to know before alerting on it:

- **`jwtReuse(false)` changes what it measures entirely.** The builder step, and `push2u.jwt-reuse`
  under Spring, switch the cache off, and then every send signs — so the counter tracks sends one
  for one and the paragraph above does not apply to that deployment. Know which of the two you are
  looking at before you set a threshold; the difference is orders of magnitude, not a correction.

- **The health indicator signs too.** The Spring starter's probe exercises the configured signer end
  to end — a `sign` and a `publicKey` on every evaluation the probe's own cache does not serve, with
  a default `management.health.push2u.cache-ttl` of 30 s, which caps its contribution at about two
  operations a minute per instance and reaches that cap only where something polls the probe at
  least that often. A *failing* probe is cached for at most 5 s, so the same instance can reach
  twelve a minute while the custodian is down — which is the moment you are most likely to be
  reading the meter. Subtract it, or raise the TTL, or accept it as a heartbeat — but do not read
  it as delivery. Under Spring the health indicator and the sender share one signer bean, so the two
  cannot be separated without building the sender yourself.
- **`publicKey()` is on the send path**, and for the signers shipped here it is not a round trip —
  the local signer holds the key, and the Vault signer advertises one that never moves. Two details
  if you meter it. It is read once to build the cache key and once more while the header is minted,
  so a cache *miss* reads it twice and a hit once. And a Vault signer built in the deferred mode has
  not contacted Vault yet, so exactly one of those first calls performs the key-metadata read: with
  reuse on it is `publicKey()`, which runs before the cache is consulted, and with `jwtReuse(false)`
  it is `sign()`, which the header path calls first. Counting either is fine; reading `publicKey()`
  as custodian load is not.
- **`sends / signs`** is a useful derived number — how well the token cache is working — but it is a
  ratio you compute in your dashboard from two meters, not a property this library promises.

## Retry

push2u performs exactly one POST per `send` and does not retry. Everything about repeating — the
attempt count, the delay, the budget, the dead-letter, and whether a `Retry-After` was honoured —
happens in your scheduler or queue, and is measured there. What this library contributes to those
meters is the classification, and it is narrower than the two names suggest. `RetryableFailure`
says a repeat *may* be useful — never that one is safe: a `502` or a `504` is an intermediary
reporting nothing valid from upstream, which may have applied the POST already, and a `507` whose
request came from a user action must not be repeated until a separate user action asks for it.
It carries the service's own `retryAfter()` when it sent one, uncapped, so the ceiling on the wait
is yours. `NonRetryableFailure` is a verdict about *this* response and not a forecast about the
endpoint: an identical request has its answer, so sending it again buys nothing — it does not
promise a later, different send fails. `SubscriptionExpired` is the one that says stop and delete
the row. `Indeterminate` says the POST left the process and nothing came back, so a repeat may
duplicate a delivery that already happened.

## Spring Boot

**The recommended shape needs no push2u bean changed at all**: instrument `send` inside your own
service, exactly as shown at the top. Everything below is for the seams whose bean the starter
creates — all three of them.

An ordinary `@Bean` returning a wrapper does **not** work, and its failure is quiet in one case and
loud in the other:

- `PushHttpClient` and `VapidSigner` are published `@ConditionalOnMissingBean`. Your bean of the
  same type does not wrap the default — it *replaces* it, and the default is never created, so
  there is nothing to delegate to. With the Vault starter this is worse than inconvenient: your
  wrapper suppresses `VaultTransitVapidSigner` itself, and the deployment silently loses its remote
  custodian.
- `EndpointPolicy` is stronger still: a policy bean beside a configured `push2u.allowed-origins` or
  `push2u.allowed-domains` is a conflict the starter **refuses at startup** on purpose, because two
  statements of one egress rule is exactly the state that ends with one of them being ignored.

Build the delegate yourself where you can — `new JdkPushHttpClient()` is public, and a Vault signer
you construct with its own builder is the same object the starter would have built. Where you
cannot, or where you want the starter's own construction preserved, a `BeanPostProcessor` wraps the
instance without adding a second definition:

```java
@Bean
static BeanPostProcessor meteredPush2uSeams(ObjectProvider<MeterRegistry> registries) {
    return new BeanPostProcessor() {
        @Override
        public Object postProcessAfterInitialization(Object bean, String name) {
            MeterRegistry registry = registries.getIfAvailable();
            return registry != null && bean instanceof VapidSigner signer
                    ? new MeteredVapidSigner(signer, registry)
                    : bean;
        }
    };
}
```

This is an advanced, deliberately opt-in recipe, and it has sharp edges worth knowing before you
reach for it:

- the bean is no longer assignable to its concrete type, so anything injecting
  `VaultTransitVapidSigner` rather than `VapidSigner` stops resolving;
- the health indicator gets the wrapper too, so its probes land in your meters (see above);
- ordering against other post-processors and any AOP proxying is now part of your configuration;
- a type check that matches more than one bean wraps more than you meant, and a second processor
  can wrap the wrapper;
- bean identity no longer means the object the starter created, which matters for any code
  comparing instances.

push2u does none of this on your behalf, and will not: a wrapper installed by the starter would
change what the health probe runs through in a deployment that asked for metrics and said nothing
about health.

## What cannot be measured from outside

Individual stage durations — the ECDH, the HKDF, the AES-GCM record, the token-cache lookup, the
status classification — are not observable without a new seam inside the sender, and there is not
going to be one. Publishing each stage would turn the current pipeline into a lifecycle contract
this library then owes forever, in exchange for numbers that answer no operational question: an
end-to-end timer, the transport timer and the signer timer already bracket everything with an
external dependency in it, and what those three leave between them is CPU work.
[`PERFORMANCE.md`](PERFORMANCE.md) is where the per-stage cost is measured, once, against a machine
that is named.

Whether a particular send reused a cached VAPID token is likewise not reported per send — the
`sends / signs` ratio above answers it in aggregate, which is the form the question is actually
asked in.

## If these recipes are not enough

Say so in an issue on the tracker, with what the recipes cost you — a divergence in names between
teams that both read this document, the cost of the Spring recipe where you had to use it, or a
measurement your call site could not produce. That is the evidence
[ADR-031](adr/0031-telemetry-is-emitted-by-the-deployment.md) names as what would oblige a fresh
decision about shipping an observability module, rather than a link back to it.
