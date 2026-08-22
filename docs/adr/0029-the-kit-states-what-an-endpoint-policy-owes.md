# ADR-029 — The kit states what an endpoint policy owes

**Status:** Proposed

Filed as https://github.com/the13haven/push2u/issues/195, together with the transport's contract.
The two were filed in one issue because they share a cause and not a design, and either one lands
without the other; this record decides the smaller of them and touches nothing the other needs.

`push2u-testkit` describes itself as the conformance kit for this library's extension points. There
are three, and it covers one. [ADR-028](0028-the-test-kit-publishes-contracts-not-conveniences.md)
gave the kit its charter — executable contracts, coherent values of the library's public input
contracts, correct fakes of seams that already exist — and left the two remaining contracts
undecided on purpose, in a section that says so, so that the consumer-side values it did decide were
not held up behind the transport's unsolved TLS cost. **Nothing in that record is superseded here.**
Its ruled-out entry about determinism is not narrowed either: it is executed, below, in the one place
where a contract test would otherwise have smuggled the assertion back in.

**What an `EndpointPolicy` owes is written down and nothing executes it.** The seam's own Javadoc
obliges four things: `assess` answers with a value and never `null`; a refusal is an
`EndpointAssessment.Refused` rather than an exception, because refusal is the ordinary case at a
registration boundary; implementations are thread-safe, since one `PushSender` is shared and
`sendAsync` makes concurrent calls ordinary; and a refusal's reason must not carry the raw URI,
which an implementation renders with `Endpoints.redact` instead. An implementation is verified
against those four sentences by its author reading them carefully, once, and by nothing afterwards.

**One of the four is not like the others, and it is why this record exists.** The reason travels:
`PushSender.send` turns a `Refused` into `PushOutcome.EndpointRejected`, pairing the policy's own
sentence with this library's redaction of the endpoint, and an application logs the outcome. A push
endpoint is a capability URL — the bearer credential for that subscription — so a custom policy's
refusal message is the one place in this pipeline where a capability URL can walk into a log
aggregator the whole company can search, past every redaction this library performs. The standard
allowlist gets it right — all three of its refusals render the endpoint through `Endpoints.redact`
before naming it. Nothing checks that anybody else does.

## The decision

**The kit publishes `EndpointPolicyContractTest`**, a public abstract class in
`com.the13haven.push2u.testkit`, in the shape `VapidSignerContractTest` already has: the implementor
extends it, supplies the subject through abstract methods, and gets the checks.

```java
public abstract class EndpointPolicyContractTest {

    protected abstract EndpointPolicy policy();

    protected abstract URI allowedEndpoint();

    protected abstract Optional<URI> refusedEndpoint();
}
```

Both endpoints are handed over as `URI` values the implementor chooses, because only the
implementor knows what their policy admits. The kit checks that each of them satisfies
`Endpoints.requireSecure` before it uses it: the seam's precondition — an absolute `https` URL with
a host — is part of its contract at both of its call sites, and a contract that measured a policy
against an input the seam never promises to hand it would be reporting on a question nobody asked.

## The refusal witness is optional, and the implementor writes that in their own hand

`refusedEndpoint()` returns `Optional<URI>` and stays **abstract, with no `default`**.

A required `URI` was the first shape, and it is refused. A policy that refuses nothing —
`EndpointPolicies.unrestricted()` is one, and it is a supported, documented member of this library's
public API — still owes three of the four obligations above: it must not answer `null`, it must
answer `Allowed` rather than fall over, and it must be thread-safe. A required witness would turn a
contract for the whole SPI into a contract for refusing implementations only, and would leave the
one policy this library ships for the opposite case with no executable contract at all. The issue
names `unrestricted()` among the in-tree subjects for exactly that reason.

**`Optional.empty()` is not a silent opt-out, and the absence of a `default` is what makes that
true.** An implementor cannot inherit their way past the check: the compiler requires the method,
and writing `Optional.empty()` is a sentence in their own source, visible in a diff and a review —
the same argument [ADR-016](0016-endpoint-policy-is-a-required-decision.md) makes about
`EndpointPolicies.unrestricted()` itself, applied one level up. The Javadoc fixes the sole
legitimate reason for the empty answer: a policy whose declared behaviour admits every endpoint that
satisfies the seam's precondition.

An implementor can of course write `Optional.empty()` for a policy that does refuse things, and
skip the check that matters. They can equally hand back an `allowedEndpoint()` chosen to be easy.
**A contract test protects against error, not against deliberate circumvention** — the same limit
`VapidSignerContractTest` states for itself where it notes that a signer rotating a pool of buffers
defeats this and every other check made from outside, and that the contract sentence is what binds
there.

The second candidate shape was two published types: a general `EndpointPolicyContractTest` and a
`RefusingEndpointPolicyContractTest` adding the mandatory witness. It buys the same strictness by
moving the statement from a method body into the name of the class a subject extends, and it costs a
second permanent public type in an artifact whose entire argument is to publish as little as it can.
The explicit `Optional` says the same thing at the price of a method call.

## The permitted endpoint stays required, and the asymmetry is not an oversight

`allowedEndpoint()` is a plain `URI` with no empty form, which invites the mirror of everything
above: a policy that permits nothing cannot supply one either, and the contract would then be a
contract for permitting implementations only.

The mirror does not hold, because this library has already ruled on the two extremes and ruled on
them differently. All three factories of the standard allowlist refuse an empty rule list in so many
words — an empty allowlist would reject every send, which is far more likely a wiring bug than a
policy. Deny-all is a shape this library declines to build and calls a probable defect; allow-all is
a shape it builds, documents and ships, because `EndpointPolicies.unrestricted()` exists precisely
so that a deployment can state it. A contract that treated the two symmetrically would be the thing
out of step with the seam it is testing.

The cost is real and is named rather than buried. **A policy that refuses every endpoint cannot be a
subject of this contract**: the seam constrains the type of the answer and not its content, so
writing one is legal, and its author is left exactly where every implementor stood before this
record. That is the smaller hole. A required witness would exclude a shape this library publishes;
this excludes a shape this library argues against.

## What the contract checks

1. **`allowedEndpoint()` is answered with `Allowed`** — a value, not `null`, and not an exception.
2. **`refusedEndpoint()`, where there is one, is answered with a `Refused` whose reason carries no
   capability part of the endpoint** — one check, over one call, for the reason the next section
   gives. A policy that throws on the endpoint it refuses aborts a fan-out over a subscription store
   at the first hostile row, which is the failure
   [ADR-027](0027-the-endpoint-policy-answers-with-a-value.md) moved the seam off the exception
   channel to prevent; what the reason must not contain is two sections down.
3. **A concurrency smoke check**, named as such, described three sections down.

Which endpoints a policy *ought* to refuse is not checked and cannot be: that is the deployment's
rule, and ADR-016 and [ADR-017](0017-domain-rule-in-the-endpoint-allowlist.md) are where the
library's own answer to it lives.

## One call per witness, which is what lets the determinism clause be literal

The refusal check and the leak check are one test making one `assess` call. The merge is for
correctness, not for brevity.

As two tests they would call `assess` twice on the same witness and hold both answers to one
expectation — the first refuses, and the second refuses *and* has a clean reason. That is a weak
form of the very property ADR-028 ruled out. A policy keeping a counter or a resolution cache is
permitted to answer differently the second time, and would fail a contract that never states it
requires stability; the clause further down promising that determinism is assumed nowhere would then
be true of the concurrency check and false of the refusal check itself.

So the contract makes exactly one observation per witness and asserts of that single value both that
it is a `Refused` and what its reason does not contain. The two halves are not separable anyway — a
value and its contents are one thing — and reporting "not a `Refused`" and "the reason leaked" as
unrelated failures would describe one broken policy as two unrelated ones.

The kit already has the precedent and the implementation takes it: `VapidSignerContractTest` puts
several assertions in one method wherever they form a chain rather than a list, carrying
`@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")` beside a comment saying why — the kit is a
module's `main` source set, so PMD analyses it, and this is `main` source that happens to be a test.

## The leak check needs a witness with something to leak, and that is a price

The check cannot simply assert that no part of the endpoint appears in the reason, because part of
it appears there on purpose. `Endpoints.redact` renders the origin plus a truncated SHA-256
fingerprint — `https://fcm.googleapis.com/…#a1b2c3d4e5f60718` — and drops the path, query and
fragment; the standard allowlist prints exactly that in all three of its refusals, so a check
forbidding the origin would fail this library's own policies for doing the right thing. The
fingerprint is there so an operator can correlate log lines about one subscription without holding
it, and it is likewise not a leak.

So the check searches for the capability part specifically: the full URI string, and the user-info,
path, query and fragment in both their raw and decoded forms — a policy that percent-decodes before
building its message leaks just as much as one that does not. Only components with content are
searched: an empty query and a bare `/` path are not evidence of anything, and searching for them
would match every reason ever written.

**Which is why the kit demands a witness carrying a distinctive capability-shaped component, and
fails loudly when it does not get one.** A refused endpoint of `https://blocked.example/` has no
meaningful component at all, so the check would pass without having looked at anything — the worst
outcome available, an assertion reporting success for a property it never tested. A witness whose
path is `/api` is barely better: the search then answers a question about the policy's prose rather
than about the endpoint.

**The criterion for a usable witness is fixed here rather than left to judgement, and stating it
closes a trap that would otherwise convict correct implementations.** A component qualifies when it
is meaningful *and* does not occur in `Endpoints.redact(witness)` — the exact string a conforming
policy is entitled to print about that endpoint. One half of that rules out a marker that is merely
the origin again. The other half is the trap: the redaction ends in a sixteen-character hexadecimal
fingerprint, so a witness whose path is hex-shaped matches on the fingerprint and reports a leak
against a policy that leaked nothing. Beside it the marker must be long enough that colliding with
the prose of a refusal is not plausible — the number is the implementing record's to choose and
justify, and the rule is what this one fixes.

A witness failing either half is refused **as unfit for the check**, with a message naming which
half it failed and why. It is never converted into a failure of the policy: the kit is reporting on
its own fixture there, and a contract that blamed the subject for the fixture's shape would teach an
implementor to distrust it.

This is the contract's one demand on the fixture, and it is a real cost rather than a formality: an
implementor cannot hand over an arbitrary endpoint their policy happens to refuse, and will meet the
requirement as a failing test before they meet it as a sentence in the Javadoc. It is named here so
that the next reader does not mistake it for an oversight.

**The alternative was for the kit to build its own probe** by appending a marker to the endpoint the
implementor supplied, which removes the demand entirely. It is refused: it changes the input the
policy already answered about. A policy that discriminates by path — perfectly legal, the seam
constrains nothing but the answer type — would then be assessed on a URI its author never offered,
and an `Allowed` coming back would read as a contract violation when it is an answer to a different
question.

## The concurrency check is a smoke check and is named one

A small number of threads, on an executor the check creates and shuts down itself — never the common
`ForkJoinPool`, where a rendezvous among tasks deadlocks on a runner with few cores — with a start
gate so the calls genuinely overlap rather than merely being submitted together.

It asserts three things: no call threw, no call answered `null`, and every answer is one of the two
variants of the sealed hierarchy. That is all.

**It deliberately does not assert that one URI always yields the same variant.** That is determinism
of the result, and ADR-028 ruled out a contract test asserting it, naming a resolution cache and a
counter as legitimate state for a policy to keep. A concurrency check demanding a stable subtype
would reintroduce the same assertion under a name that hides it, and would refuse an implementation
this library permits.

With the refusal and its reason merged into one observation two sections above, the clause can be
stated without a qualification: **no check in this contract observes one endpoint twice and requires
the two answers to agree.** The classification checks are one call each, in their own tests, where
the subject is classification; the concurrent one is about what happens when several threads are
inside `assess` at the same moment, and asserts only what that question can support.

What it is worth is asymmetric and the Javadoc says so. A passing run proves nothing: no schedule
was forced, and an unguarded cache can go a thousand runs without colliding. A failing run is a real
defect every time, because a correct policy cannot fail it. Having no false positives is what earns
it its place; being no proof is why it is not called one.

## The library's own policies are the first subjects

`EndpointPolicies.allowedOrigins`, `.allowedDomains` and `.allowedEndpoints` each become a subject
of this contract in `push2u-core`'s tests, as `LocalEcVapidSigner` already is a subject of the
signer contract. The dependency exists: the core declares `testImplementation(project(":push2u-testkit"))`
today.

`unrestricted()` becomes the fourth, with `Optional.empty()`. It is the smallest subject and it does
the most work of the four: a shape nothing in this build takes is a shape nothing in this build
keeps working, and the empty witness is precisely the path a later change could break without a
single test noticing.

**A contract that nothing in this build extends drifts from what the library actually requires**, and
the drift is found by the first outside author who trusted it — the one person it was written for.

## Documents

`docs/TESTKIT.md` gains a section for this contract: it is the kit's reference, named for the
artifact rather than for one audience, and it is where a reader looking at what the kit publishes
will arrive. The kit's `package-info.java` names `VapidSignerContractTest` as its contract side, and
its `build.gradle.kts` description — which becomes the published POM description — names the signer
contract alone; both take the addition. README's module table and the prose introducing the kit
describe the artifact in the same terms, and `docs/DESIGN.md` describes the module layout.
`CLAUDE.md` and `CONTRIBUTING.md` each carry a sentence about what the kit holds.

All of that belongs to the implementation, together with this record's move to `Accepted`. While it
is `Proposed` those documents are still accurate — a kit that holds one contract is what the tree
holds until the code lands. The one edit that cannot wait is `CLAUDE.md`'s range of ADR numbers,
which becomes wrong the moment this file exists rather than when its decision is implemented, and it
travels with this record for that reason.

## What this rules out

- A contract test that refuses to run against a policy which refuses nothing, and equally one that
  reaches such a policy only through a second published type.
- A `default` implementation of the refusal witness, in any spelling that lets a subject inherit
  "there is nothing to check here" without writing it.
- A contract test asserting that an `EndpointPolicy` answers deterministically — ADR-028's entry,
  executed rather than narrowed: no assertion that one URI yields one variant, in the single-threaded
  checks or hidden inside the concurrent one.
- A concurrency check presented as proof of thread safety, or one built on the common
  `ForkJoinPool`.
- A leak check forbidding the origin or the fingerprint `Endpoints.redact` prints on purpose, and
  equally one that searches only the raw spelling of a component a policy may have decoded.
- A leak check run against a witness with nothing to leak, and so a witness requirement left to the
  implementor's judgement instead of asserted with a message that says why.
- The refusal and the leak stated as two checks over two calls, which would have the contract observe
  one witness twice and quietly require the two answers to agree.
- A witness qualification rule admitting a marker that occurs in the redaction a conforming policy
  may print — the fingerprint above all — or a fixture's unfitness reported as a failure of the
  policy.
- A contract that cannot be extended by a policy which permits nothing, sought by making
  `allowedEndpoint()` optional in the name of symmetry; the two extremes have different standing in
  this library and the contract follows it.
- A kit that derives its own probe endpoint by rewriting the one the implementor supplied.
- A contract check on which endpoints a policy admits or refuses, that being the deployment's rule
  and not this library's.
- A contract check on the wording of a refusal beyond what it must not contain — the reason is prose
  for an operator, and ADR-027 rules out a program branching on it.
- An endpoint reaching the contract that the seam's own precondition does not admit.
- A second redaction scheme in the kit, or any reach from the kit into something the core keeps
  package-private.
- A published `EndpointPolicy` fake, fixture or preconfigured subject — ADR-028's admission test
  applies unchanged, and a policy is a deployment's own decision to state.
