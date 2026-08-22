# The push2u test kit

`push2u-testkit` is a test-scoped artifact with two halves. One is the conformance contract every
`VapidSigner` implementation extends, which is [`SIGNER.md`](SIGNER.md)'s subject. The other is what
this document covers: values and a transport fake for the tests an application writes around its
own sending code — a VAPID pair, a browser subscription, and a `PushHttpClient` that answers a
declared sequence of responses and records what it was asked to send. [`README.md` → Writing a
VapidSigner](../README.md#writing-a-vapidsigner) carries the dependency coordinate; the kit belongs
on a **test** classpath and never on an application's runtime one.

What admits something to the kit is not that assembly is tedious. It is that the knowledge the
value carries belongs to this library and moves with it. A stub transport answering one constant
status is five lines and a consumer will get it right; what the current `Subscription` contract
accepts is something a consumer can only find out by upgrading and watching what breaks. The kit
publishes the second kind.

## What the kit brings with it

Everything the kit declares is `api`, and that is not an oversight. A consumer *extends*
`VapidSignerContractTest`, so the JUnit Jupiter annotations it carries, the AssertJ assertions its
methods run and the `VapidSigner` its abstract method returns are all part of what compiling against
the kit requires. The fixtures themselves use neither JUnit nor AssertJ, so an application on
another test runner can still use them — but the artifact is one, and the contract needs both.

The JUnit **BOM** travels the same way, and on a Gradle build it is the part worth knowing about
before it happens. Its constraints reach whatever test classpath the kit lands on, and a Spring Boot
build already has a source of the same constraint in Boot's own managed versions. Gradle resolves
the conflict by taking the higher, so adding the kit can move your test JUnit off the version Boot
manages and onto the one the kit's BOM names. Nothing about the kit requires that version and
nothing about it is fragile — this repository's own Spring starter tests took exactly this shift
when they picked the kit up, and it was accepted rather than pinned back, because one JUnit across a
build is the better state. But a build that has to stay on Boot's managed JUnit should learn that
here rather than from a conflict-resolution report: state the version you want explicitly instead of
leaving it to resolution — an `enforcedPlatform` of Boot's BOM on the test classpath, or a
dependency constraint naming the JUnit version — and the kit will compile against it unchanged.

## Why the values are generated rather than fixed

A fixture produced by the library satisfies whatever the library currently requires, by
construction. A literal pasted into a test satisfies whatever the library required on the day it
was pasted, and nothing tells anyone when the two stop being the same thing.

That difference is not theoretical, and this kit exists because of a case of it. An application had
key-shaped placeholders in its controller tests — strings of the right rough shape, valid for as
long as nothing decoded them. A release tightened the endpoint to strict `https` and started
enforcing the key lengths at the API boundary, and five of six tests in one class broke on an
upgrade whose release notes could not have warned about them, because the values were never wrong
on purpose. They were written against a contract, and the contract moved.

So the fixtures generate. `VapidKeyPairFixture.generate()` and `SubscriptionFixture.at(...)` make
new material on every call, decode it back through the library's own public constructors before
handing it over, and therefore fail in the test that asked for them rather than three assertions
later. There is no fixed pair and no key-shaped constant anywhere in the artifact.

## The whole thing in one block

A sender, a subscription and a scripted transport, which is the setup nearly every send test needs:

```java
VapidKeyPairFixture keys = VapidKeyPairFixture.generate();
SubscriptionFixture subscription = SubscriptionFixture.at(URI.create("https://push.example/s/abc"));
ScriptedPushHttpClient transport = ScriptedPushHttpClient.respondingWith(201);

PushSender sender = PushSender.builder(
        keys.vapidKeys(), "mailto:ops@example.com",
        EndpointPolicies.allowedOrigins("https://push.example"))
    .httpClient(transport)
    .build();

PushOutcome outcome = sender.send(subscription.subscription(), PushMessage.builder(payload).build());

assertThat(outcome).isInstanceOf(PushOutcome.Accepted.class);
assertThat(transport.sent()).singleElement().satisfies(push ->
    assertThat(push.endpoint()).hasHost("push.example"));
```

The endpoint policy is in that block on purpose. `at(URI)` has no argument-free form, because the
endpoint has to agree with the policy the test configures beside it: a fixture that picked its own
endpoint would either force every test to allow it, or push the test towards
`EndpointPolicies.unrestricted()` in the source set where security assumptions get the least
attention. The egress decision is the application's, and both halves of it stay visible together.

There is no `PushSender` fixture, for the same reason and one more: a preconfigured sender would
freeze a builder configuration into a published artifact, so every option added later would arrive
with the question of whether the fixture sets it. With the values in hand the sender is one
statement — and it is the statement the application's production code writes too, which is the one
worth having in the test.

## The VAPID pair

```java
public final class VapidKeyPairFixture {
    public static VapidKeyPairFixture generate();
    public VapidKeys vapidKeys();
    public String publicKeyBase64Url();
    public String privateKeyBase64Url();
}
```

`vapidKeys()` is what `PushSender.builder(keys, contact, endpointPolicy)` and `LocalEcVapidSigner`
take. The two string accessors are the form a configuration file carries: `push2u.vapid.public-key`
and `push2u.vapid.private-key` bind unpadded URL-safe base64, so a Spring test of a deployment's own
property binding — the most ordinary Spring test there is — needs the pair in exactly that spelling.
Without those accessors it writes a literal, which is the defect this kit exists to remove.

The strings are the primary form and `vapidKeys()` is `VapidKeys.fromBase64` applied to them, which
makes the round trip the fixture's own acceptance test: the library checks the public half against
the curve and the scalar's length, so a mis-encoded public key fails inside `generate()`. That check
reaches half of what could go wrong and no further, because nothing in the library's runtime checks
relates a scalar to a point. So the kit pins that correspondence where it can: a test inside the kit
signs with a generated pair and verifies the signature against its public half through
`Es256Verifier`, on the pairs where a fixed-width encoding is most likely to slip. That test is part
of the fixture rather than an extra — without it the fixture would carry a defect class this
library's own key handling does not have, and one whose only symptom is a push service rejecting the
JWT.

The pair comes from the JCA's standard `"EC"` and `secp256r1` names with no provider selected,
named or inspected. The environment chooses, exactly as it does for the code under test. A fixture
pinning its own provider would either fail outright on a JVM that does not carry it, or produce keys
through a provider the library under test is not using.

**A generated pair is right for a test and wrong for a deployment, and the difference is not about
secrecy.** A deployment's pair is generated once, out of band, and configured. A pair generated at
deployment start is replaced by a different pair at the next restart, and every browser subscription
taken under the old application server key becomes unusable at that moment — the browser bound the
subscription to the `applicationServerKey` it was created with, and a push service may refuse a JWT
signed under any other. [`VAPID.md`](VAPID.md) is the one-time recipe, and
[`VAPID-KEY-ROTATION.md`](VAPID-KEY-ROTATION.md) is what replacing a live pair actually takes.

Where a test needs the same public key twice, it needs it within one run: hold one `generate()` in a
field.

## The subscription

```java
public final class SubscriptionFixture {
    public static SubscriptionFixture at(URI endpoint);
    public Subscription subscription();
    public String endpoint();
    public String p256dhBase64Url();
    public String authBase64Url();
}
```

One instance holds one coherent set: an endpoint, a fresh P-256 public key as `p256dh`, and 16 fresh
random bytes as `auth`. A send test takes `subscription()`; a registration or controller test takes
the three strings and posts them as the JSON a browser's `PushSubscription` produces. They describe
the same subscription, which is why they sit on one fixture rather than on separate factories —
separate factories would let a test combine the `p256dh` of one subscription with the `auth` of
another, and that mismatch has no symptom at all until decryption fails at a receiver nobody is
watching.

**The string accessors close a trap that is worth naming, because it is where a hand-written test
goes wrong on the first attempt.** Both values are unpadded URL-safe base64.
`Subscription.fromBase64` tolerates *padding*, because browsers vary on it, and does not tolerate a
second alphabet — so `java.util.Base64.getEncoder()` where `getUrlEncoder()` was meant produces a
string the library refuses. How that refusal presents differs by value, and the difference is the
reason both accessors exist:

- Over 65 bytes the two alphabets differ for around 93 % of keys, so the wrong encoder is caught on
  essentially the first run.
- The 16-byte `auth` is short enough that the two alphabets agree about half the time. The same
  mistake therefore passes on some runs and fails on others, in a value whose only downstream
  symptom is a subscription the browser cannot decrypt for.

A test that hand-encodes these values does not have a bug it can reproduce; it has a flaky suite.

`at(URI)` takes an absolute `https` URL, like every endpoint this library accepts, and refuses
anything else with the `IllegalArgumentException` `Subscription` would have raised.

## The scripted transport

```java
public final class ScriptedPushHttpClient implements PushHttpClient {
    public static ScriptedPushHttpClient respondingWith(int firstStatus, int... followingStatuses);
    public static ScriptedPushHttpClient respondingWith(PushResponse first, PushResponse... following);
    public static ScriptedPushHttpClient failingWith(PushDeliveryException failure);
    public List<SentPush> sent();
}
```

The library performs exactly one POST per send and hands the repeat decision back to the caller, so
the shape a caller's own loop has to handle — `429`, `429`, `201` — can only come from a transport
that answers differently on consecutive calls. That is the whole reason this fake is scripted rather
than constant:

```java
ScriptedPushHttpClient transport = ScriptedPushHttpClient.respondingWith(429, 429, 201);
```

The first response is a separate parameter so an empty script cannot be written: the compiler
refuses it, rather than a runtime check discovering it later.

**A `Retry-After` belongs to one particular response**, which is what the `PushResponse` form is
for — the retry test is precisely the one that needs the second answer to carry a different hint
from the first, and a per-fake header setting would put the same hint on all of them:

```java
ScriptedPushHttpClient transport = ScriptedPushHttpClient.respondingWith(
    new PushResponse(429, Map.of("Retry-After", "2")),
    new PushResponse(429, Map.of("Retry-After", "30")),
    PushResponse.of(201));
```

**An exhausted script raises `IllegalStateException`, and it comes out of `send` itself.** The
sender converts a signer's unavailability and the transport's own `PushDeliveryException` into
outcomes and treats every other runtime exception from a seam as a defect, so this one propagates
unconverted — out of `send`, or out of the future `sendAsync` answered. That is what a test wants:
one POST more than the test declared is a failed expectation, not a scenario. Do not wait for an
`Indeterminate` that will not come.

`failingWith(...)` is a mode of the whole fake rather than a script element: every call records the
attempt and then throws the given failure, which is the transport's contract for a POST that went
out and got no answer, and what the sender reports as `Indeterminate`. A sequence mixing responses
and failures — `429`, then nothing answering, then `201` — is deliberately not expressible here. A
test needing that composes a few-line `PushHttpClient` of its own, which is exactly the case where
writing the stub is the right answer.

**Under a fan-out, the answers do not go where a reader expects.** `sendAsync` makes concurrent
`post` calls the ordinary case, and responses are handed out in the order calls *enter* the fake,
which for concurrent sends is not the order of the subscriptions. So:

- A scripted sequence is for the sequential repeat loop over **one** subscription.
- A fan-out test declares **one constant response** per expected call and asserts over `sent()`,
  never over which subscription drew which status.

Left unsaid, this produces flaky consumer tests that read as a library defect, which is why it is
said here and on the fake's own Javadoc.

Concurrent use is otherwise safe by construction. Taking the next scripted answer and recording the
call are one atomic step, so the recorded order is the order answers were handed out and no call is
answered without being recorded — including a call that drew the configured failure or found the
script exhausted, since the POST was attempted either way. `sent()` answers an immutable
point-in-time snapshot, so an assertion made while a fan-out is still running reads a list that
cannot change under it.

There is no `reset` and no mutable configuration. A fake reused across tests shows one test its
neighbour's requests, and the first symptom of a test that forgot the reset is a failure in a
different test; a fresh fake per test costs one line and cannot do that. A script that can change
after it was declared is not the script that ran. The fake also asserts nothing itself: `sent()`
answers a plain list, and the assertion library the test already has does the rest better than a
`hasSentTo(...)` here would.

Per-endpoint routing is not in this version. A sender holds exactly one `PushHttpClient`, so "a fake
per subscription" is not available to a fan-out test without a sender per subscription, which is no
longer the fan-out being tested. It is left out rather than ruled out.

## What a recorded push keeps

```java
public record SentPush(URI endpoint, Map<String, String> headers, int bodyBytes) { }
```

The endpoint, an immutable copy of the request headers, and the encrypted body's **length**. The
body itself is deliberately not kept: a test holding the ciphertext will eventually decrypt it, and
asserting on a record this library produced means either re-implementing RFC 8291 or comparing
against whatever the code currently emits. Neither is the application's test to write. The length is
kept because it is the part a consumer's own contract can reach — `PushOutcome.PayloadRejected`
speaks the same `payloadBytes` vocabulary, which is also why the component is `bodyBytes` and not a
spelling of its own.

`toString()` is written by hand, and that matters more than it sounds. A recorded push carries two
values that must not reach a CI log through a failed assertion's message: the endpoint is a
capability URL — whoever holds it can message the subscriber — and the `Authorization` header
carries a VAPID token. So the rendering passes the endpoint through the same redaction the library
logs with, which keeps the origin and replaces the capability part, and prints header *names*
without their values. A failure message still says which push service was called. The **accessors
are unredacted**: an assertion may inspect everything, and only the printed form is constrained.

## Which `PushOutcome` combinations are reachable

All eight variants have public constructors, `SignerUnavailable` and `Indeterminate` included, and
that is on purpose: an application's decision table is a unit test over values, and
`new PushOutcome.RetryableFailure(503, Optional.empty())` is a real value of the public contract
rather than a mock of one. There is no kit factory over those constructors, because a factory would
hide the status and the hint, which are the components the decision is about.

**The constructors are wider than the sender, though.** They refuse only what no HTTP exchange could
have produced — a negative status, a negative hint, a `null` — so `new PushOutcome.Accepted(500)`
constructs happily and describes nothing the library ever hands back. A decision table built out of
constructed values is still a good test; it is just not evidence about the classifier. What a real
send can produce:

| Variant | What the sender actually produces |
|---|---|
| `Accepted(statusCode)` | `statusCode` is a `2xx`, always. |
| `SubscriptionExpired(statusCode)` | `404` or `410`, and nothing else. |
| `RetryableFailure(statusCode, retryAfter)` | `408`, `421`, `429`, any `5xx` other than `501`, `505`, `506`, `508`, `511` — and `413` only when the response carried a parseable `Retry-After`, so a real `RetryableFailure(413, …)` always has the hint present. On every other status the hint is present exactly when the response carried a *parseable* one — `RetryAfter` reads delta-seconds and the three HTTP-date forms and answers empty for anything else — and it is reported with no ceiling applied. |
| `NonRetryableFailure(statusCode)` | Everything answered that no row above claims: a `3xx`, a `4xx` other than the named ones, a bare `413`, and the five carved-out `5xx`. Never a `2xx`, never `404`/`410`. |
| `SignerUnavailable(cause)` | `cause` is the `VapidSignerUnavailableException` the signer raised; `status()` and `retryAfter()` are snapshotted from it at construction. |
| `Indeterminate(cause)` | `cause` is the `PushDeliveryException` the transport raised for a POST that got no answer. |
| `PayloadRejected(payloadBytes, maximumPayloadBytes)` | `payloadBytes` strictly exceeds `maximumPayloadBytes`; both are plaintext octets. |
| `EndpointRejected(redactedEndpoint, reason)` | `redactedEndpoint` is always this library's own redaction of the refused endpoint; `reason` is whatever the policy answered, which may be the empty string. |

Where the real classification is what a test is about, the scripted transport and a real sender give
it in the application's own wiring — that is the reachable path to every row above, and it is why
the kit publishes no catalogue of the eight. A consumer needs to handle a `RetryableFailure`, not to
re-derive that `429` is one.

## What the kit does not publish

**No `VapidSigner` fake.** `SignerUnavailable` is one of the eight, and a signer that raises
`VapidSignerUnavailableException` is the only way to reach it through the real pipeline — so the
question deserves an answer rather than silence. The answer is that the fake is a short anonymous
class, nothing about it moves when the library moves, and what it simulates is the consumer's own
custodian rather than anything of this library's:

```java
VapidSigner unavailable = new VapidSigner() {
    @Override
    public byte[] sign(byte[] signingInput) {
        throw new VapidSignerUnavailableException("custodian down");
    }

    @Override
    public byte[] publicKey() {
        throw new VapidSignerUnavailableException("custodian down");
    }
};
```

**Raising from both methods is the correct form, and the trap sits the other way round from where
you would look for it.** The send validates the advertised key only *after* the signature is taken.
On the default reuse path it does read `publicKey()` first, to build the token-cache key, but it
reads it unvalidated; the shape check happens on the way into the signed token. So a fake that
*returns* from both methods has to return a structurally valid 65-byte uncompressed point: a
placeholder there ends the send as a `PushCryptoException`, with the signature already produced, and
the test never reaches the outcome it was written for. A fake that raises has no returned value read
at all.

**No `PushSender` fixture, in any spelling** — the reason is in the worked example above.

**No `PushOutcome` factory and no catalogue of the eight**, for the reason in the section above it.

**None of this library's own fixtures.** The RFC vectors, the in-process mock push receiver, its
self-signed loopback TLS identity, the shared send-pipeline helper, and the Vault module's fakes all
stay in this build. The vectors are conformance material for this library's crypto, which an
application does not re-run; the receiver and the certificate are this build's plumbing; and the
Vault pair belongs to the other trust domain entirely, the one where responses must be read.

**No second artifact.** `push2u-testkit` keeps its single coordinate. A leaner fixtures-only jar
would buy a consumer freedom from a transitive JUnit on a test classpath that has JUnit on it
already, and would cost a coordinate, a JPMS identity, a publication surface and a second thing to
keep in step — see [what the kit brings with it](#what-the-kit-brings-with-it) for what that
transitive actually does.
