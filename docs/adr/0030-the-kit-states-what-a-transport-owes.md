# ADR-030 — The kit states what a transport owes, and brings the server it needs

**Status:** Proposed

Filed as https://github.com/the13haven/push2u/issues/195, together with the endpoint policy's
contract. The two share a cause and not a design;
[ADR-029](0029-the-kit-states-what-an-endpoint-policy-owes.md) decides the other one, and neither
depends on the other landing.

`PushHttpClient` is the seam a deployment replaces to get OkHttp, Apache HttpClient 5 or its own
instrumented transport, and its obligations are the kind that pass every unit test and fail in
production:

- **redirects are not followed** — a `3xx` surfaces as a status the sender classifies, never as a
  POST to a host the endpoint policy never saw. `EndpointPolicy`'s own Javadoc lists several things a
  URI-level check cannot reach — DNS rebinding, anything the remote server does once connected — and
  says that this one, alone among them, is closed in the transport rather than lived with;
  `JdkPushHttpClient` refuses a redirect-following client at construction, and a client built on
  another stack carries the property itself. OkHttp's `followRedirects` defaults to `true`, so the
  straightforward implementation there is unsafe until someone turns it off, and its
  `followSslRedirects` with it;
- **an HTTP error status is not a transport failure** — `PushDeliveryException` means nothing
  answered, and a transport that throws on `410` turns a subscription this library classifies as
  gone into an `Indeterminate` the caller will keep repeating for the life of the row;
- **the implementation is thread-safe**, since one `PushSender` is shared and `PushSender.sendAsync`
  makes concurrent posts ordinary.

Today an implementation is verified against those sentences by its author reading them once. A
transport that quietly starts following redirects on a dependency bump has no test anywhere that
notices.

[ADR-028](0028-the-test-kit-publishes-contracts-not-conveniences.md) left this undecided and named
the reason precisely: verifying any of it needs a server, over TLS, inside a published artifact.
It has to be TLS, because push endpoints are `https`-only and a contract passed over plaintext would
clear a transport that fails at the handshake. **Nothing in ADR-028 is superseded here.** Its
ruled-out entry — "a mock push service listening on a socket, shipped as part of this decision" —
excluded such a server from *that* record so the fixtures it did decide were not held up behind this
question; it is the section named "What this record does not decide" that governs, and it invites
exactly this.

## The decision

**The kit publishes `PushHttpClientContractTest`**, a public abstract class in
`com.the13haven.push2u.testkit`, in the shape the signer's contract already has, and **brings its
own TLS server as package-private machinery of that class.**

```java
public abstract class PushHttpClientContractTest {

    protected abstract PushHttpClient transport(SSLContext sslContext, X509TrustManager trustManager);
}
```

One abstract method. The contract class is itself a new published type — there is no way to publish
a contract without publishing the class an implementor extends — and it is the only one: no helper,
no fixture, and no TLS type of this project's own joins it. The contract stands the server up,
generates a throwaway certificate for it, hands the implementor the two standard JCA objects that
trust that certificate, and receives back a transport configured to speak to it.

## The server ships in the jar, and this record says so plainly

The harness is compiled into `push2u-testkit` and travels to every consumer that puts the kit on a
test classpath. Saying that no mock push service appears would be false. What is true, and what this
record decides, is narrower and is the whole of the commitment:

**The TLS harness ships as package-private implementation machinery of the contract. Nothing about
it appears in the surface a consumer compiles against — not as public API, not as a `protected`
member a subclass inherits — and no consumer may depend on its shape, its behaviour or its continued
existence.**

What that deliberately does not claim is physical unreachability. The kit is an automatic module and
a consumer puts it on a test class path, so code declaring the same package reaches a package-private
class as it does in any jar, and reflection reaches it regardless. The commitment is about what is
supported, which is the only kind of commitment a library is able to keep; a record claiming the
stronger thing would be making a promise the platform does not let it make.

That distinction is the point rather than a technicality. ADR-028's admission test asks whether the
knowledge a member carries is the library's own and moves with it; a general-purpose mock push
service fails that test, because a consumer's own tests are served by `ScriptedPushHttpClient`, which
fakes the seam without a socket in sight. What the harness carries is the library's statement of
what a transport owes, and that statement is the abstract class. Publishing the server beside it
would freeze a second surface — ports, lifecycle, scripting, recording — that this library would then
owe compatibility on forever, in exchange for something the kit already provides.

## TLS reaches the implementor as two standard types

`SSLContext` and `X509TrustManager`, both `javax.net.ssl`, both handed to the abstract method.

The kit generates a self-signed certificate per test JVM, presents it from the server, and builds
the pair that trusts exactly that certificate — through an ordinary `TrustManagerFactory` over a
one-entry trust store, with no trust-all manager and no relaxed hostname verification anywhere.
A consumer's OkHttp client will not trust a certificate the kit invented, so the trust material has
to reach the transport under test; the implementor is the only party who knows how their stack is
configured, so the kit hands over the material and the implementor does the configuring.

**Both halves are handed over because the three stacks that matter want different ones.** The JDK's
`HttpClient` and Apache HttpClient 5 take an `SSLContext`; OkHttp's supported overload takes the
`SSLSocketFactory` *and* the `X509TrustManager` beside it. Handing over one half and making OkHttp's
author derive the other from a `TrustManagerFactory` would put the kit's own certificate handling
into their test — which is the sort of thing that gets replaced with a trust-all manager on the
second attempt. Neither type is ours, so no TLS abstraction is invented and nothing of this project's own
joins the published surface.

## The kit invents no lifecycle for the transport, and states how often it asks for one

**`transport(...)` is called once per test method, and the contract never closes what it hands
back.**

That is a decision rather than an omission, and the seam is what decides it. `PushHttpClient` is not
`AutoCloseable` and has no lifecycle at all: a `PushSender` takes a transport when it is built, holds
it for as long as it exists, and closes it never. A contract introducing a teardown step would be
stating an obligation the seam does not carry, and would leave an implementor entitled to believe
this library releases their client at some point — which it does not, anywhere.

The cost of that lands on a stack holding resources, so it is named together with its answer. JUnit
creates a new test instance per test method by default, so a subject building an OkHttp client or an
HttpClient 5 connection manager builds one per check in this contract and releases none of them. **A
subject in that position keeps the reference in its own factory method and closes it in its own
`@AfterEach`** — ordinary JUnit, needing nothing from the kit and adding nothing to the published
surface. The call count is stated here because it is the fact an implementor cannot make that
decision without.

## The server is a raw `SSLServerSocket` speaking minimal HTTP/1.1

Not `com.sun.net.httpserver.HttpsServer`, which is what this build's own `MockPushReceiver` uses.
Three reasons, and the first is about the artifact:

- **A published artifact should not raise the question of whether `jdk.httpserver` is in the
  consumer's module graph.** The kit is an automatic module and most consumers put it on the class
  path, where it does not matter — but "most" is the wrong standard for a jar that goes to Maven
  Central, and the dependency buys nothing here.
- **"Accept the connection and drop it" is not expressible through an exchange-based server**, and it
  is one of the two transport failures the contract has to produce.
- **HTTP/1.1 only is not a limitation.** A server that advertises nothing in ALPN leaves the JDK's
  client — which prefers HTTP/2 over TLS — to fall back to HTTP/1.1 by itself, which is what it
  already does against `HttpsServer`.

## What the contract checks

1. **An HTTP error status is an answer, not an exception.** A `410` comes back as a `PushResponse`
   carrying `410`, not as a `PushDeliveryException`. This is the check whose absence costs a
   deployment a subscription row that is retried forever.
2. **The response headers reach the caller**, `Retry-After` in particular.
   [ADR-021](0021-retry-belongs-to-the-caller.md) gave the caller the schedule and the library
   exactly one POST, and `PushOutcome.RetryableFailure` carries the hint the push service sent. A
   transport that returns the status and drops the headers empties that hint, silently, for every
   `429` a deployment ever receives.
3. **Exactly one request arrives, and it is the one that was handed over.** Two obligations, and
   they are one check because they are one observation of the wire. *One request*: the seam says a
   transport neither classifies nor repeats a request, and that however a repeat is scheduled each
   attempt arrives as its own `post` call — so a transport retrying inside `post` delivers the
   notification twice, and the sender it reports one outcome to never learns of the second. *That
   request*: a POST, at the URI it was given, carrying the headers it was given and the body it was
   given **compared byte for byte, not by length**. A transport that replaced every byte with a zero
   of the same length passes a length check and hands every subscriber a message their browser
   cannot decrypt. The bytes are synthetic, made by the contract for this check — nothing here holds
   or publishes a real encrypted body, and the comparison happens inside the harness and ends
   there.
4. **A redirect is not followed.** The harness answers a `3xx` whose `Location` names a **second
   listener, on another loopback port**, and the check asserts both halves: the caller was handed
   that `3xx` itself, and the second listener accepted no connection at all. The second port is what
   makes the claim the right one — a different port is a different origin, and the assertion is
   about an origin the endpoint policy never assessed, which a target path on the same server would
   weaken into a claim about a path. The host is the same one, a loopback harness being unable to
   arrange otherwise, and the record says so rather than overstating what the check pins: what it
   pins is that nothing was sent to an origin nobody vetted. The certificate is the same one and its
   subject alternative name covers
   both listeners, so a transport that does follow the redirect arrives at the second one with no
   trust error to stop it and its silence means what the check needs it to mean; the loopback-only
   rule below is not bent to arrange this.
5. **A refused connection is a `PushDeliveryException`** — a port nothing is listening on.
6. **A request sent with nothing answering it is a `PushDeliveryException`.** The harness completes
   the TLS handshake, reads the whole request, and closes the connection without writing a status
   line. That is the case the seam names and the one `PushOutcome.Indeterminate` exists for — the
   POST went out and no answer came — and it is the reason the drop is placed here rather than in
   the handshake: a connection dropped mid-handshake tests a transport that never sent anything,
   which is the fifth check again in a costume. Kept separate from the fifth deliberately: one fails
   before a byte of the request is written and one after all of it is, a caller's exposure differs
   between them, and a transport can honestly report the first while swallowing the second.
7. **A concurrency smoke check**, described below.

## The concurrency check is a smoke check, and here it has teeth

Named the same honest way as the policy contract's, and materially stronger than it.

Each concurrent caller sends a unique correlation header; the harness echoes that header back in its
own response and records what it received. The check then asserts that every caller got back the
response carrying *its own* correlation value, that the server saw exactly as many requests as there
were callers, and that no request arrived with another's headers or body length.

That finds a real class of defect rather than merely failing to find one. A transport keeping
per-request state in a field — a builder, a buffer, a header map reused between calls — hands one
caller another's response under concurrency, and the failure in production is a `201` credited to a
send that was actually refused. The seam's Javadoc puts per-request state in the call rather than in
a field and calls a pooled client the natural implementation for that reason; this is the check that
catches an implementation that did not read it.

It is still a smoke check: a passing run forces no schedule and proves nothing. It has no false
positives, which is what earns it its place.

## What the harness owes, so that the contract measures the SPI and not the JDK's client

A harness written against one transport measures that transport. These are fixed as part of the
decision, not left to the implementation:

- Both `Content-Length` and chunked request bodies are read. A transport may frame the body either
  way and both are correct HTTP.
- Header names are compared case-insensitively, as HTTP requires.
- Additional headers the transport adds of its own — `Host`, `User-Agent`, `Accept`, `Connection`,
  a content type — are permitted. The contract asserts that the headers it *gave* are present with
  the values it gave; it never asserts the exact set.
- The URI is checked through the request target, the `Host` header, the path and the query, since
  that is what a server can observe of it.
- Every listener the harness opens — the one under test and the redirect target beside it — is bound
  to the loopback address only.
- One certificate serves all of them, and its subject alternative name matches the address they are
  bound to, so the transport performs real hostname verification rather than being handed a reason
  to skip it.
- Responses close the connection unless persistent connections are the subject of the scenario, so
  that connection reuse is never accidentally part of what a check asserts.
- Every check that reaches the network carries its own test-level timeout. This is not a transport
  obligation and states nothing about `PushHttpClient` — the seam promises no timeout and this
  contract asks for none — but a subject that blocks forever has to fail a consumer's build rather
  than hang it, and a contract that can hang the build it was added to gets removed from it.

## Response-body materialisation is not in the contract

`PushHttpClient`'s Javadoc asks implementations to discard the response body without buffering it,
because the endpoint is an attacker-supplied capability URL and a hostile push service may answer
with an arbitrarily large one. **It stays a written obligation and does not become an executable
one**, in the same way ADR-028 kept determinism out of the policy contract.

The reason is that the seam offers nothing to observe it through. `PushResponse` has no slot for a
body, so nothing a transport buffers can reach the caller — structurally, the obligation is already
kept as far as the API can tell. What remains is the difference between draining a stream and
holding it in memory, and no assertion available from outside distinguishes them: a correct client
reads a large body too, so elapsed time says nothing, and no response size reliably breaks a
buffering client, because the heap a consumer runs their tests with is unknown to this kit and is
usually large enough. A check that streamed some number of megabytes would assert that a transport
survives a large response — worth having in this library's own tests of its own client, where the
number can be chosen against a known build, and not worth stating as a contract obligation that
appears to test something it does not.

Timeouts are excluded for the plainer reason: the seam does not promise one.

## The second certificate builder is deliberate

This build already assembles a self-signed certificate by hand, in `push2u-core`'s `LoopbackTls`,
because bcpkix is not a dependency here and `sun.security.*` internals would need `--add-exports`
and have moved packages before. After this record there are two such builders in the tree.

They are not consolidated, and there is no shape in which they could be. ADR-028 rules out
publishing the library's own fixtures — the receiver and the loopback certificate by name — from any
artifact, so the core's cannot become the kit's; and this record rules out publishing the kit's
harness, so the kit's cannot become the core's. The remaining option is a third artifact for shared
test plumbing, which costs a coordinate, a JPMS identity and a publication surface to remove a
duplicated encoder from a test path. **A later reader finding both should not read the duplication as
an oversight**, which is the same sentence ADR-028 had to write about this repository's two key
generators.

The kit's harness is also bound by the invariant the core's fixtures state for themselves: it names
no JCE provider, because the core puts the kit on both its `test` and its `fipsTest` classpath and
those two carry deliberately incompatible BouncyCastle flavours. Standard algorithm names, whatever
provider the environment offers.

## The library's own transport is the first subject, and one existing test's deletion has a precondition

`JdkPushHttpClient` becomes a subject of this contract in `push2u-core`'s tests. A contract nothing
in this build extends drifts from what the library actually requires, and the drift is discovered by
the first outside author who trusted it.

Its arrival makes `JdkPushHttpClientRedirectTest.theClientReturnsARedirectInsteadOfFollowingIt`
redundant — the contract's fourth check is the same assertion against the same client. **It is
deleted only after a self-test inside the kit proves that a redirect-following transport fails that
check.** Without it, the only evidence that the harness can detect a followed redirect is that the
one transport it is pointed at does not follow them, which is evidence of nothing: a harness whose
redirect never reaches the client passes every subject, including the unsafe ones it exists to fail.
The self-test is the precondition, not a nicety, and the deletion waits for it.

**Exactly one test method is deleted, and everything else in those files stays untouched** — the
sentence is about a count, not about a list. Naming a few of the survivors is only useful for the
ones a reader might expect the contract to have absorbed: the constructor's refusal of a
redirect-following `HttpClient`, and its acceptance of a conforming one, are about this class's own
invariant rather than about the seam; the redaction of the endpoint in a delivery failure's message,
the interrupt-flag restoration, the request timeout and the streamed 64 MiB response are each about
`JdkPushHttpClient` and not about what a transport owes. Those are examples of the distinction, and
not an inventory of what survives.

## Documents

`docs/TESTKIT.md` gains a section for this contract, beside the one ADR-029 adds. The kit's
`package-info.java` and its `build.gradle.kts` description name the signer contract as the kit's
contract side and take the addition; README's module table and the prose introducing the kit
describe the artifact in the same terms; `docs/DESIGN.md` describes the module layout.
`docs/SIGNER.md` is the reference for the implementor writing a `VapidSigner` and is deliberately
*not* extended to a second seam — it is named for the signer, and the kit's own reference is where a
transport's author is sent. `CLAUDE.md` and `CONTRIBUTING.md` carry a sentence about what the kit
holds.

All of it belongs to the implementation, together with this record's move to `Accepted` — except one
deletion that travels with this record instead. `CLAUDE.md` carried a range of ADR numbers, which
every record adding a file had to bump; it is removed rather than bumped, so that the next free
number is read from `docs/adr/README.md`, which is right without anyone maintaining it.
[ADR-029](0029-the-kit-states-what-an-endpoint-policy-owes.md) carries the same deletion, the two
records having arrived together.

## What this rules out

- A TLS harness published as supported fixture API, in any spelling — a public type, a public
  constructor, a `protected` accessor handing a subclass the running server, or a documented promise
  about its behaviour.
- The library's own fixtures — `MockPushReceiver`, `LoopbackTls` — published from any artifact, which
  is ADR-028's entry and stands unchanged; and equally the two certificate builders consolidated by
  publishing either one.
- A TLS private key or certificate committed to this repository, or a fixed one shipped inside a
  published artifact — the identity is generated per test JVM and never leaves it.
- `com.sun.net.httpserver` reaching a published artifact.
- A contract obligation that the response body is never materialised, in any spelling that asserts
  buffering did not happen; and a response-size check offered as one.
- A contract check for a timeout, for a retry *policy* or *schedule*, for a connection-pool property
  or for persistent-connection behaviour — none of which the seam promises. How many HTTP requests
  one `post` call may produce is not on that list and is checked, the seam promising exactly that.
- A request body compared by length rather than byte for byte, which passes a transport that
  delivers the right number of wrong bytes.
- An unanswered request modelled by dropping the connection before or during the TLS handshake,
  which tests a transport that never sent anything and leaves the case `PushOutcome.Indeterminate`
  exists for unchecked.
- A lifecycle the kit invents for the transport: a teardown hook, a `close` call on the subject, an
  `AutoCloseable` expectation, or any other obligation `PushHttpClient` does not itself carry.
- A redirect target on the harness's own listener, which would turn a check about a host the policy
  never saw into a check about a path.
- A harness asserting the exact set of request headers, or comparing header names case-sensitively,
  or rejecting a chunked request body.
- A harness listening on anything but loopback, or a certificate whose subject alternative name does
  not match the endpoint the contract hands out, which would leave hostname verification untested
  and invite a transport to disable it.
- A contract that admits a plaintext endpoint, or a check that falls back to one when TLS fails.
- Trust material narrowed to one HTTP stack's type, or an endpoint handed to the implementor without
  the material needed to reach it.
- A scripted response sequence, an assertion DSL or mutable configuration on the harness — the
  scripted sequence belongs to `ScriptedPushHttpClient`, which fakes the seam and needs no socket.
- The deletion of this build's own redirect test before a kit self-test proves a redirect-following
  transport fails the contract's redirect check.
- A JCE provider named, selected or inspected anywhere in the harness.
