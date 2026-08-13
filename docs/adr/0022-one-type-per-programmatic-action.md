# ADR-022 — One exception type per programmatic action

**Status:** Proposed

Reported as https://github.com/the13haven/push2u/issues/128, which is the wider review promised in
https://github.com/the13haven/push2u/issues/87 rather than a new complaint. Counted over every
`main` source set, and counting the sites that throw through a factory helper as well as the ones
that write `throw new`: 89 `PushCryptoException`, 88 `IllegalArgumentException`, six
`IllegalStateException`, three `PushDeliveryException`, three `EndpointRejectedException`, and one
`AssertionError` that dies with the retry loop. Three of those types are ours and all three already
extend `RuntimeException` directly.

The first number is the one that matters. `PushCryptoException` covers, indistinguishably from
outside and by its own Javadoc's admission — *"One type covers both on purpose; the message and the
cause chain, not the type, say which happened"* — a Vault that cannot be reached, a Vault that
answered an error status of any kind, a Vault that answered something it could not have meant, a
Transit key created with a type VAPID cannot use, a platform missing an algorithm, a request URI a
configured address made unusable, a header a trailing newline in a YAML block scalar made illegal,
and a thread that was interrupted. `PushSender.send`'s published Javadoc then tells a caller that
this type means a key service *"unreachable or refuses the operation, which may be transient"*, so a
durable retrier that believes the contract retries a wrong-typed Transit key forever.

**This record owns the exception taxonomy, entirely**: which types exist, the scope of each — what
it covers and what it no longer does — what each one carries, where each is declared, and what a
caller or a supervisor catching one is promised. Classification is ADR-021's, at the Vault
transport's seam as much as at the facade's, and so is which failure leaves a seam wearing which of
these types; a type is the channel and that record decides what goes down it. `PushOutcome` and its
variants, the two status matrices, the surfacing of `Retry-After` and the line between an outcome
and an exception are ADR-021's too. Where this record names an outcome or a classification it is
naming that record's, and a decision that moves one of those supersedes it rather than this one.
This is written down so that whoever supersedes either knows which half they are replacing.

## The decision

**A site earns its own type only if a consumer would take a materially different action on it, and
that action cannot be derived from what the consumer already holds.** That is issue #87's criterion,
quoted as it was written, and the shape of it is load-bearing: it is a *necessary* condition and not
a sufficient one. A different log line is not a different action, and a taxonomy that minted a type
per condition would answer the count without answering the complaint.

**One refinement, because ADR-021 changes who is reading.** After it, most of these failures never
reach a `catch` block in an application at all — the facade catches them and reports an outcome. The
audiences that remain are three: the facade, which switches on the type; a startup supervisor, for a
signer that reads its key inside `build()`; and whoever reads a stack trace at three in the morning.
The criterion is judged against those. It is not weakened by that: the facade's `catch` clauses are
an enumeration, so a distinction the facade does not act on still does not earn a type.

**And the axis is what the catching code does, not what went wrong.** Two failures that arise from
different causes and that one `catch` clause handles identically are one type. The question every
site is put to is *what does the code that catches this do differently* — report an outcome, retry
the boot with backoff, propagate a cancellation, fail the deployment and stop — and a site that
cannot name a different answer earns no type.

**This axis does not express who owns the fix, and does not try to.** One `PushCryptoException`
covers a defect in this library, a third-party `VapidSigner` that broke its contract, a Vault mount
that is not there, a token without the capability to use a key, and a key version Vault has trimmed
— five conditions, three different owners between them, and no two of them fixed by the same act. It
is one type because the code that catches them does one thing with all five: it stops the sender,
retries none of them, and waits for a human. Which human, and what they change, is carried by the
message and the cause chain, where it can be as specific as the site knows and as long as it needs
to be — a type carries what a program branches on, and no program branches on ownership. This is a
limit the record accepts rather than a gap it means to close later: sorting by owner would mint
types that nothing catches, which answers the count of throw sites and leaves the complaint exactly
where it was.

## What the axis produces

**ADR-021 has already drawn the sharpest line, and this review's remaining job is smaller than 89
suggests.** Its outcome-versus-exception decision moves every operational failure out of the
exception channel, and that is the transient-versus-permanent distinction issue #87 was filed about —
the one whose absence lets a durable retrier repeat a wrong key type forever. What is left on the
exception channel afterwards is a defect, a misconfiguration that recurs, a misuse, or a
cancellation.

**No configuration type is added, and the reason is the criterion rather than a shortage of cases.**
Half of the obvious candidates never reach a send, because the boundary that takes a required value
refuses it there: the Vault token carrying a YAML block scalar's newline is refused by `VaultToken`'s
own constructor, whose message names that exact case; an address that would yield an unusable request
URI is refused at the builder factory; a supplied public key that is not on P-256 is refused by the
factory that takes it. That is `CONTRIBUTING.md`'s builder convention working — a required value is
validated where it is supplied, and `build()` cannot refuse over one — and it makes those an
`IllegalArgumentException` at the boundary rather than anything a send reports.

The other half does reach a send, and saying otherwise would be false. Those checks are checks of
*form*: a mount that names no engine, a key name Vault does not hold, a token whose character set is
legal but whose capability or lifetime is not, a pinned key version Vault has trimmed — every one of
them is well-formed, passes every boundary, and comes back as a Vault error status. They are a
deployment's own to fix, and they are exactly what ADR-021's recurring list already names.

They still earn no type, and the criterion is what decides it. A consumer takes no different
programmatic action on "your token cannot read that key" than on "your platform has no `AES/GCM`":
both stop the sender until a human intervenes, and neither is retried. The difference is the sentence
in the log — and a different log line is not a different action, which is the same answer this record
gives the signer split below. A type would be minted for a distinction only a human reads, and the
message and the cause chain already carry it.

**`PushCryptoException` therefore covers everything that does not speak about the custodian's own
condition** — an answer about the request and about what this deployment supplied, an answer no
custodian could have meant, and a substrate that cannot perform the cryptography at all — and it
keeps its name because the cryptography is what could not be performed in every case. That
discriminator is ADR-021's and this record does not move it. "Until a human acts" is not the
discriminator and would sort these wrongly: an operator unseals a Vault, and a node standing by or
catching up waits on a person or a replication just as surely, yet every one of those is an outcome.
What separates them is whose state the answer describes, and with it whether a repeat can come back
different: a cluster's condition ends on its own terms — an operator, a replication, a rate window —
without this deployment changing anything it configured, where everything left here answers
identically until the deployment changes what it supplied. A platform without `AES/GCM/NoPadding`,
`HmacSHA256` or the `secp256r1` parameters; a custodian or a `VapidSigner` implementation that
answered something that is not a signature or not a key; a Transit key whose type VAPID cannot use,
a mount or key name that is not there, a token without the capability, a pinned key version Vault no
longer holds. `Endpoints`'s unavailable `SHA-256 MessageDigest` is an `IllegalStateException` today
and joins them, on a stated ground rather than on a claim of sameness. It is not the same condition:
the fingerprint hashes with the platform's own SHA-256 whatever provider is configured,
deliberately, because it is diagnostics and not protocol — so its failure means a runtime that is
not a Java SE implementation, where a missing `secp256r1` from a configured FIPS provider is an
ordinary misconfiguration of a supported kind. It joins them because an unusable cryptographic
substrate is worth one channel rather than two, and because the site is unreachable on a conforming
JVM, so the choice costs nothing either way.

So the type loses two things and no more: the operational half ADR-021 moves to outcomes, and the
cancellation the section below gives a type of its own — the interrupted custodian wait, which is
`PushCryptoException` today and is neither cryptographic nor a defect. The misconfigurations ADR-021
names beside the defects stay where that record puts them.

**The starters keep `IllegalStateException`**, and this is stated so the inventory is complete rather
than silently exempt. Their five conditions are a missing `push2u.vapid.subject`; a
`push2u.signer.vault.key-version` without a `push2u.signer.vault.public-key`; the allowlist
properties and an `EndpointPolicy` bean both present; no egress decision expressed at all; and every
configured allowlist present but empty. All five are startup failures of a Spring context, where a
failed context is what an `IllegalStateException` idiomatically means, where nothing catches by type,
and where the library's own rule is already that the message names the YAML property rather than the
builder's camelCase parameter. A library type would say less than the message does and would be
caught by nothing.

**Cancellation gets its own type**, `PushInterruptedException`, raised by the facade. It rides
`PushDeliveryException` in two places and `PushCryptoException` in a third today, and it is none of
them: nothing failed, the caller asked to stop, and the action — clear nothing, retry nothing, let
the interrupt propagate — is shared with no other failure here. **The seams are not obliged to raise
it.** ADR-021 put the recognition test on the facade, written as a disjunction over the cause chain
and the thread's interrupt status, *"precisely so that no transport has to be obliged to anything"*,
and that stands: `PushHttpClient`'s contract does not change, and the type is what `send` reports
rather than what a seam must throw. The residue is named rather than papered over: a signer that reads
its key inside `build()` is not inside a send, so an interruption during that read leaves as the
seam's own type — `VapidSignerUnavailableException`, since an interrupted exchange is an incomplete
one and the transport does not sort them — and the startup supervisor sees that type rather than this
one. Obliging the seams to tell an interruption apart would close it at a price ADR-021 declined to
pay for the send path, and it is not worth paying for one call that happens once. What it costs
instead is a sentence in the supervisor's contract, which the section below owes it anyway.

**`IllegalArgumentException` stays exactly what the JDK made it**: a value that is not a legal value
of its parameter, carrying no library semantics, handled in a generic pool. `Subscription`'s 16-byte
`auth`, a negative `ttl`, a `p256dh` that is not 65 bytes, every builder bound, and — per the
finding above — every configured value refused at the boundary that took it. It is the larger half
of #87's rule and the half that keeps the taxonomy from growing: we do not mint a type for what is
genuinely an argument defect. The two sites that were not argument defects, the size preconditions,
are already leaving as ADR-021's `PayloadRejected`.

## The signer's operational failure stays one type

A custodian reached over a network fails in two ways that are not the same event: nothing answers —
a refused connection, a failed handshake, a timeout — or the custodian answers that it cannot serve
this request now, sealed or not caught up or rate-limited. Only the second can carry a retry hint,
because only the second declared anything. That asymmetry is the case for two types, and it was
argued at length in a draft of this record. It does not survive the criterion this document adopts,
and the reasoning is set out because the question will be asked again.

The action is the same on both sides. The facade does one thing with either: it reports a
`SignerUnavailable`, with a hint and a status copied across if either arrived. What an operator then
does is the same too — wait, and look at the custodian — and it is the same operator. Whether an
answer arrived is a fact about how the failure happened, which is precisely what this document's
axis exists to stop ranking. And the shape argument proves too much: a field that is always absent
on one side would equally justify splitting a timeout from a refused connection, and nothing in the
criterion stops that regress once it is admitted.

An implementer is the second reason, and it is the one a taxonomy is most often written without.
Both halves produce one outcome and one decision, so a signer written over an HSM, a KMS or a smart
card would be choosing between two types for nothing — and choosing at a boundary where this
library's own two implementations are not the interesting sample. What an operator reads to tell an
unroutable Vault from a sealed one is the message and the cause, which both halves carry. The retry
hint, and the custodian's status beside it, are not second names for the answered half but values a
caller acts on: carried by the one type across both halves and filled only where something was
declared, which is to say on the answered one.

`PushDeliveryException` is not reused for either half, though a refused connection to a custodian is
the same shape of failure as a refused connection to a push service, and the same JDK client raises
it. That type names delivery, and nothing was delivered; it is the vocabulary of the one operation
this library performs that can duplicate a notification, and a signing call is the one that provably
cannot. Reusing it would put the two operations under one word at exactly the point where ADR-021
needs them told apart — an unanswered POST is `Indeterminate` and an unanswered signing call is
`NotAttempted`, and that difference is a fact about which operation was interrupted rather than
about how it broke.

The precedent inside ADR-021 runs the same way: it accepted `RetryableFailure(413, empty)` — a
representable pair that cannot occur — rather than pay a type for one dead combination. A record
that minted a type here while quoting that one would be applying a different rule than the one it
claims.

What the two halves do differ in is the sentence an operator reads, and the criterion answers that
directly: a different log line is not a different action. The message and the cause chain carry it,
which is the half of `PushCryptoException`'s own reasoning that survives its narrowing.

**What the outcome carries is ADR-021's and is not restated here** — that `SignerUnavailable`
reports the cause, the custodian's status and the retry hint, and is therefore a class with a written
`toString()` rather than a record, is decided there, under `Indeterminate`'s discipline and for
`Indeterminate`'s reason. What this record owes that decision is the seam: none of the three reaches
a caller unless the exception carries it across first, and the facade cannot invent what it was not
given. With nothing carried, the `IOException` under an unreachable custodian is destroyed at the
boundary and nobody can say why a send was not attempted — and that loss falls hardest on exactly
the distinction the paragraphs above leave to the message.

**So the exception is pinned here.** `VapidSignerUnavailableException` carries three things beside
its message: the cause, whatever did not complete; an `Optional<Duration>` retry hint, empty unless
the custodian declared when to come back; and an `OptionalInt` holding the status the custodian
answered with, empty for a local key, for a PKCS#11 token, and for the whole half where nothing
answered at all. Neither optional field obliges an implementer to speak HTTP — a signer over an HSM
fills neither and is conformant — which is the arithmetic ADR-021 runs for the hint and now runs the
same way for the status. It is declared in the core beside the other seam exceptions, because
`VapidSigner` is a core SPI and a module implementing it over HTTP needs a core word for this. An
interrupted custodian call carries the `InterruptedException` in its chain with the interrupt flag
re-set, which is what lets the facade's disjunction recognise one; and a signer that reads its key
inside `build()` raises the same type when its custodian is down at startup. That last clause is the
whole of what the startup supervisor named above acts on: catching this type, it retries the boot
with backoff, where catching `PushCryptoException` it should fail the deployment and stop. A record
that names an audience owes that audience a contract.

**And the contract begins with the interrupt, not with the type.** A boot interrupted while the key
is being read raises the unavailable type as well, because the transport does not sort an incomplete
exchange by what made it incomplete — so a supervisor that reads the type first answers a shutdown by
looping the boot, and every backoff it sleeps fails instantly on a flag nobody cleared. That is the
spin ADR-021 refuses on the send path, arriving at the one place there is no facade to refuse it. The
order is therefore fixed here: test the interruption first — the flag, or an `InterruptedException`
in the chain, the same disjunction and for the same reason — and only then read the type. A
supervisor of anything that blocks owes that test in any case; what this record adds is that it comes
first.

**And that order is written where a supervisor meets it**, which is the whole of what makes it worth
deciding: the Javadoc of the `build()` that reads a key over a network, and of the exception itself.
An obligation stated only in a record is one its audience never sees — the author of a supervisor
reads a factory method's contract, not `docs/adr`, and the cost of missing this one is a deployment
that loops its own boot through a shutdown. ADR-021 already carries the rule this follows, that a
fact a caller must not get wrong is stated where a caller meets it, and it names three such facts for
a sender; this is the fourth, and the only one whose reader is a supervisor rather than a caller. The
signer implementers a paragraph below get the same treatment for the same reason.

**`PushInterruptedException` promises the interrupt, and the promise is not the same on both
paths.** The action it exists for — let the cancellation propagate — needs the caller to find the
cancellation, and one draft of this record promised the flag outright. On `sendAsync` that promise
cannot be kept by anybody: the thread that was interrupted is the executor's, the future may be read
by another thread and by several of them, and an interrupt status does not travel through a
`CompletableFuture`. So there are two contracts, written as two.

*On `send`*, the full promise: the interrupt status is re-set on the calling thread before the
exception is thrown, so a caller finds the thread interrupted whether or not it looks at the cause
chain, and the `InterruptedException` is in that chain wherever one was raised. Every site that
raises one today re-sets the flag; that is a habit inherited from three separate implementations
rather than a contract, and an interruption swallowed without the flag is the oldest defect in the
genre. It becomes the type's written promise.

*On `sendAsync`*, the future completes exceptionally with this type, and the flag on whatever thread
reads the future is **not** promised. That is said in as many words rather than left for a caller to
discover in a `catch` block on a thread nobody interrupted. What travels is the type and
its cause chain, which is all a `CompletableFuture` can carry. The worker's own flag is re-set on
the worker, before the future is completed, and then dies with the task: it is owed to the executor
and to whatever else that thread runs next, not to the caller.

**The future completes exceptionally; it is not cancelled.** `isCancelled()` is false, `join()`
raises a `CompletionException` wrapping this type and `get()` an `ExecutionException` with the same
cause, and `CancellationException` is deliberately not used for it. That type is the JDK's word for
one thing — its own documentation defines it as indicating "that the result of a value-producing
task, such as a `FutureTask`, cannot be retrieved because the task was cancelled", and
`CompletableFuture` documents `cancel` as having "the same effect as `completeExceptionally(new
CancellationException())`" — so borrowing it would deliver a caller's own cancellation and an
interrupted worker into the same `catch` clause, indistinguishable. They are not the same event
here, and ADR-021 records why: `CompletableFuture.cancel` does not interrupt a running task, so a
cancelled future leaves the send running, and a send that was interrupted was cancelled by nobody's
`cancel`. A caller that has to tell "I cancelled this" from "the sender was stopped mid-flight" is
exactly the caller this taxonomy exists for.

## Where the line with ADR-021 runs, and what this costs

The two records were drafted together and decide one send between them, so the line is written out
rather than left to be inferred. **Every exception type is this record's**: which ones exist, the
scope of each, what each carries, where it is declared, the narrowing of `PushCryptoException`, the
place of `IllegalArgumentException` and of the starters' `IllegalStateException`, and the
interruption contract on both paths. **Every outcome and every classification is ADR-021's**: the
shape of `PushOutcome` and its variants, what each variant means to a caller, both status matrices —
the push service's and the custodian's — the surfacing of `Retry-After`, the line between an outcome
and an exception, which seam signal converts to which outcome, and which failure leaves a seam
wearing which type. That last one includes the Vault transport's split, which is written out there
and nowhere else: an oversized response, an unusable request URI and an illegal request header stay
`PushCryptoException` because that record classified them, not because this one enumerated them.
Neither record re-decides the other's half; where one names something on the far side of the line,
it is naming and not deciding. An ADR that moves a type supersedes this one; an ADR that moves an
outcome or a classification supersedes that one.

Two readings of that line are worth closing off, because a draft of this record proposed both.
ADR-021's *"a defect and a misconfiguration"*, in the two places it says it, is not narrowed here:
the misconfigurations it names beside the defects are the ones that reach a send, and they stay in
`PushCryptoException` for the reason set out above. And its reading of which custodian failures are
operational is not reopened either — that reading is off Vault's own published table and off RFC
9110's classes, which makes it a classification and therefore that record's. This one fixes the type
that carries the answer across the seam; it does not re-take the answer.

Every type named here is a breaking change for a consumer that catches by type. `0.x` was declared
the window for revising names and constructor shapes once real integrations exist, and each
transition is named in the release notes rather than described in the abstract. The one that bites
hardest is the narrowing of `PushCryptoException`: a `catch` clause that today swallows an
unreachable Vault compiles unchanged and silently stops catching it.

**It breaks signer implementers the same way, one seam deeper, and that half is the one nobody
would look for.** `VapidSigner`'s published contract instructs an implementation to raise
`PushCryptoException` when a remote key service is unreachable, timed out or refused the operation.
A KMS or HSM signer written against that sentence keeps compiling afterwards, and its outages then
leave `send` as permanent defects instead of becoming `SignerUnavailable` — because the facade
rightly refuses to sniff a cause chain to guess otherwise. Nothing catches this: the conformance kit
asserts no exception types on purpose, so a stale implementation passes it. The release note
therefore addresses signer implementers in their own paragraph rather than leaving them to read a
consumer's.

The name `PushCryptoException` is kept through that narrowing, and the asymmetry is worth one
sentence because ADR-021 paid the opposite price next door: it renamed `PushResult` to `PushOutcome`
for a smaller shift in meaning, arguing that the old name described something the type no longer
meant. A rename here would turn the silent break above into a compile error at every affected site,
which is a real gain. It is declined because the name is still accurate for what the type keeps — the
cryptography is what could not be performed in every remaining case — and because the candidates that
would describe the narrowing better describe the type worse. A name that has stopped being true is
worth changing; a name that is true and merely covers less is not.

**ADR-005's seams are untouched** — none added, none removed, and `PushHttpClient`'s contract in
particular is left exactly where ADR-021 left it. **ADR-002 is untouched**: an exception class is
core code, not a dependency, and every type named here lives in `push2u-core` beside the three that
are there now, because the facade must catch them and a type the core cannot see cannot be caught
there.

## What this leaves ready

Three open reports touch the failure surface without being about it. Where this record serves them
and where it merely gets out of their way is worth stating, because it becomes immutable when it is
implemented, and whoever picks those up afterwards should not have to re-derive whether the taxonomy
hemmed them in.

**A remote signer that is not up yet** — https://github.com/the13haven/push2u/issues/91 — needs no
type this record does not already have. Reading the key lazily on first use instead of inside
`build()` moves *when* the custodian is asked, not what happens when it does not answer: inside a
send that is the `SignerUnavailable` outcome, whose repeat the caller already owns, and outside one —
an explicit refresh, an application asking for the key it publishes to browsers, or this repository's
own health indicator, which probes the signer rather than a sender — it is
`VapidSignerUnavailableException`, the same answer `build()` gives. The part of that report which
made it sharp is settled here rather than deferred: a fetched-mode boot fails today with a type that
cannot be told from a Transit key of the wrong sort, so failing the deployment is the only honest
reaction available to a supervisor. After this record it can tell, which is the precondition for
anything cleverer — and the cleverer thing is a lifecycle decision that belongs to that report, not
to this one.

**Telling a deliberate silence from a broken one** — https://github.com/the13haven/push2u/issues/88 —
is outside this record entirely: no `PushSender` bean is not a failure and nothing throws. Nothing
here forecloses an explicit switch, and the starters' `IllegalStateException` goes on meaning what it
means, a context that could not be built from what was configured.

**The health indicator** — https://github.com/the13haven/push2u/issues/89 — gains a distinction for
nothing, and it is deliberately not the one that report asks for. Because the indicator probes the
signer directly rather than through a `PushSender`, it sees exception types where a caller sees
outcomes; it catches `RuntimeException` broadly and reports the exception's class as a detail while
keeping the message out of the payload on purpose. Today a custodian's failures all reach it as one
class, so a DOWN says only that signing failed, and after this record one that is down and one that
is misconfigured arrive as different ones, with no change to the indicator to show it. What that
report is about lies elsewhere and is untouched: a non-standard opt-out, and the indicator sitting in
the group a container's health check polls, so that a custodian outage marks the whole container
unhealthy. Both classes still answer `Health.down()`, and nothing here changes that.

## What this rules out

A type per throw site, which answers the count and not the complaint. A type whose only consumer
difference is the sentence it puts in a log. A type minted for who owns the fix, which is not
something a program branches on, and equally a claim that this taxonomy expresses that ownership. A
type for a configured value that the boundary accepting it should have refused.
`IllegalArgumentException` as a base class for anything the library owns, which lets an existing
`catch` keep swallowing both cases and so cancels the disambiguation it was minted for. A library
exception that does not extend `RuntimeException` directly. Message-text matching as the supported
way to tell two conditions apart — anywhere a consumer must do that, a type is missing. A
cancellation reported by `send` as the type of whatever it interrupted, and equally a seam obliged
to recognise one. A cancellation delivered as a `CancellationException`, or an interrupted send
reported by a future that answers `isCancelled()`. An interrupt-flag promise on the asynchronous
path, which no `CompletableFuture` can keep. And a taxonomy settled one exception at a time, in
whichever ADR happens to touch a failure next.

## The whole contract, in one table

The rows below are what everything above amounts to, for the reader who needs the answer rather than
the argument. The outcome column names ADR-021's variants and that record fixes what each one means
to a caller, as it fixes the classification that decides which row a failure lands in; what this
table adds is the type that leaves each seam, and what the reader does with what arrives. A row that
is hard to fill is a disagreement between two sections rather than a gap in the table, and the
sections are what to fix.

| The condition | What the seam signals | What `send` produces | What the reader does |
|---|---|---|---|
| The push service answered `2xx` | the response | `Accepted(statusCode)` | Nothing: the message was accepted for delivery, which is not a receipt |
| It answered `404` or `410` | the response | `SubscriptionExpired(statusCode)` | Delete the subscription |
| It answered `408`, `421`, `429`, a `413` carrying a parseable `Retry-After`, or a 5xx the matrix does not carve out | the response | `RetryableFailure(statusCode, retryAfter)` | Schedule a repeat, not before the hint where one arrived |
| It answered anything else — `501`, `505`, `506`, `508`, `511`, a bare `413`, any other 4xx | the response | `NonRetryableFailure(statusCode)` | Record it; repeating the identical request buys nothing |
| The POST went out and nothing answered — a timeout, a dropped connection | `PushHttpClient` throws `PushDeliveryException` | `Indeterminate` | Price a possible duplicate against a possible loss; the library will not price it for you |
| The policy refused the endpoint | `EndpointPolicy` throws `EndpointRejectedException` | `EndpointRejected` | Record the row and keep the fan-out running |
| The payload does not fit this sender's configuration | the pre-flight check, before any seam is reached | `PayloadRejected(payloadBytes, maximumPayloadBytes)` | Render the notification smaller |
| The custodian cannot sign now — unreachable, sealed, not caught up, rate-limited | `VapidSigner` throws `VapidSignerUnavailableException`, carrying the cause, the status wherever the custodian answered a number, and a hint only where one was declared | `SignerUnavailable` | Stop submitting new sends and repeat when the custodian is back |
| A cryptographic defect, an unusable provider, or a custodian misconfiguration that recurs | `VapidSigner`, the platform or the Vault transport throws `PushCryptoException` | throws `PushCryptoException` | Stop the sender; a human edits a property or files a bug |
| The sending thread was interrupted | whichever seam was blocked; the facade's disjunction recognises it | throws `PushInterruptedException` — on `sendAsync`, the future completes exceptionally with it and is not cancelled | Propagate the cancellation; retry nothing, alert nobody |
| An argument is not a legal value of its parameter | the constructor, factory or builder that took it | throws `IllegalArgumentException` | Fix the call site |
| A `null` where the contract forbids one, or a violated internal invariant | the site that finds it | it propagates as the unchecked defect it is | Fix the call site, or file a bug where the invariant is this library's |
| Any other `RuntimeException` out of a consumer-written seam | the seam throws whatever it throws | it propagates unchanged — the facade converts three types and no others | Read it as a defect in that implementation, not as an operational condition |

One row has no `send` in it and is left out on purpose: a signer that reads its key inside `build()`
is outside a send, so an interruption there arrives as `VapidSignerUnavailableException` and the
supervisor tests the interrupt before it reads the type, as the section above requires.
