---
name: push2u-review
description: Review a change, diff or pull request in the push2u Web Push library — a complete review procedure covering ordinary defects (correctness, concurrency, resources, error paths, git history) plus the commitments this repository holds itself to — RFC conformance pinned by published test vectors, the trust boundaries around attacker-supplied endpoints and Vault, key material and tokens leaking into diagnostics, published-API compatibility, ADR conformance and the zero-dependency core. Use this for any request to judge code already written here rather than write new code, however it is phrased and in whatever language — "review my changes", "look over this PR", "is this ready to merge", "anything I missed", "did I break anything", "anything wrong with how I did it", "second opinion before I push", "check my changes for problems", "do these commits follow the project conventions", "is this still backwards compatible for consumers", or a security, design or API check of a diff, branch or commit range.
---

# Reviewing a change in push2u

This is the whole review procedure for this repository — it does not assume any other review tool
has run or exists. Work through it in order: understand the change, let the build do the mechanical
half, look for ordinary defects, then check the commitments that only this repository's context can
tell you about.

That last part is the reason a reviewer here matters. push2u claims conformance to five RFCs, draws
two deliberately opposite trust boundaries, publishes an API to Maven Central that can never be
withdrawn, and records its settled decisions as ADRs. No tool enforces any of it.

If you hand part of this review to a subagent, remember that it starts with a fresh context and does
not inherit this skill — it gets the repository's `CLAUDE.md` and nothing else from here. Either
give it the relevant rules in the delegation prompt, or tell it to read
`.claude/skills/push2u-review/SKILL.md` first. A subagent asked to "review these files" without that
will review them as generic Java.

## 1. Understand the change first

`git diff main...HEAD` for a branch, `gh pr diff <n>` for a pull request. Read all of it before
judging any hunk. The send pipeline is ordered on purpose (size checks → endpoint policy → crypto →
signature → POST), so a hunk that looks wrong alone is often right in place, and one that looks
harmless can be fatal three steps later. `docs/DESIGN.md` §4 and §5 describe that order and the SPI
seams; read them if they are not already in context.

Then ask what the change is *for*. A review that never forms a view on the intent can only check
mechanics, and mechanics are the part the build already covers.

## 2. Let the build do its half

If any code changed, run `./gradlew qualityCheck`. Spotless, Checkstyle, PMD, SpotBugs, Error Prone
and NullAway all fail the build, so anything they catch is not a review finding — raising it adds
noise and buries the findings that matter. This is why nothing below mentions formatting, import
order, missing Javadoc, naming or nullness annotations.

If the gate is red, say so before anything else: the rest of the review is provisional until it
passes.

## 3. Ordinary defects

Trace the changed code rather than reading it. Most real bugs here live in one of five places.

**Byte and index arithmetic.** This library does a lot of it — the RFC 8188 header layout, DER
parsing, base64url, key coordinates. Check offsets and lengths against the format, check that a
length taken from input is validated before it is used to allocate or slice, and check for
overflow: the size sums in the send path are computed in `long` precisely because a payload above
`Integer.MAX_VALUE - 103` wraps negative in `int` and sails past any limit.

**Concurrency.** `PushSender` is stateless and meant to be shared across threads, and `sendAsync`
runs the same synchronous pipeline on a library-owned virtual-thread executor unless the application
supplies its own. So: a new mutable field on a shared object is a finding unless its publication is
argued; a cached or coalesced value (the health indicator caches its probe) needs its visibility and
its failure behaviour checked, not just its happy path; and an application-supplied executor must
never be shut down by the library, while a library-owned one must be.

**Resources.** Every path, including the ones an exception unwinds through, must close what it
opened. A bounded read stays bounded when it fails. Nothing holds a Vault token, a private scalar or
a decoded key longer than it needs to.

**Error paths.** Which channel a failure leaves by is a contract, not a style choice, and the line
runs between two of them. **An outcome** describes what became of a requested send, whether or not a
POST was reached — an expired subscription (ADR-007), a policy refusal, a payload that does not fit,
a custodian that cannot sign now, an unanswered POST. **An exception** is reserved for using the API
wrongly, for a defect the caller cannot act on per send, and for cancellation:
`PushCryptoException` for a failure that recurs, `PushInterruptedException` for an interruption,
`IllegalArgumentException` for an illegal argument (ADR-021, ADR-022). The seams keep their own
vocabulary — `PushDeliveryException`, `EndpointRejectedException`,
`VapidSignerUnavailableException` — and **exactly those three convert**; anything else out of a
consumer-written seam is a defect and must propagate rather than be laundered into a value. Check
that a new failure lands in the right channel and the right type, that the recurrence axis is what
sorted it rather than "does a human have to act", that a cause is preserved unless a suppression
explains why not, and that no failure is quietly turned into a default that looks like success.

**What the diff does not contain.** Changes here tend to imply work in more than one place: a new
`PushSender.Builder` option usually needs a `push2u.*` property in the starter, startup validation
whose message names the YAML property rather than the camelCase parameter, a README entry and often
a line in the protocol-limits table; a new outcome variant or public exception needs a row in the
status-mapping table, in `README.md` and in `docs/DESIGN.md` alike; a new module needs publication
wiring. Ask what the change implies and check it is there.

## 4. History and comments as constraints

This codebase explains *why* in its comments far more than most, and those comments are load-bearing
— they record decisions that look arbitrary without them. When a change contradicts the reasoning in
a comment near it, one of the two is now wrong; say which. When a change makes a comment stale,
that is a finding, not a nitpick.

Run `git log -L <start>,<end>:<file>` or `git blame` over the touched lines when the code looks
odd. The most valuable catch a reviewer makes here is a change that silently reverts a deliberate
earlier fix — reintroducing `resolutionStrategy.force`, dropping one of the three public-key
validation steps, truncating a coordinate again. Each of those was a real fix; each looks like a
simplification to someone who has not read the history.

## 5. The project lenses

Work through the ones the change touches. A lens with nothing to say is worth one line in the
"Verified" section, not silence — the author cannot otherwise tell "checked, fine" from "not looked
at".

### 5.1 Conformance — the vectors are the specification

The published vectors define correct behaviour: RFC 5869 HKDF, the RFC 8291 worked example, RFC 8292
VAPID structure. If a change alters output, the vectors must still pass; if a change *edits* a
vector, that is a must-fix unless it cites a published erratum. Vectors do not move because code
moved.

Check against the clause, not against intuition:

- **Body limit** — RFC 8030 §7.2. The 103-byte `aes128gcm` overhead is derived from the format the
  encryptor emits (86-byte header + 1 padding delimiter + 16 tag), not written as a constant, so the
  plaintext maximum tracks a configured limit. A newly hardcoded 3993 is a defect.
- **Record size** — RFC 8291 §4 requires `rs > payload + 1 + 16`, RFC 8188 §2 requires `rs ≥ 18`.
  There is one implementation of that rule, the inverse pair
  `WebPushEncryptor.maxPlaintextForRecordSize` / `recordSizeForMaxPlaintext`: `checkRecordSize`,
  the encryptor's own last-moment refusal, reads the first, and the sender derives its `rs` from
  the second — once, at `build()`, as the body ceiling less 103 plus 18, exact rather than floored.
  A second copy of the rule is a defect even if it is correct today, and so is `rs` reappearing as
  configuration in any form — a builder step, a Spring property, a floor or historical constant
  (4096 has no special status) applied to the derived value, or a derivation per message rather
  than per sender.
- **VAPID** — `aud` is the RFC 6454 §6.1 Unicode serialization produced by `Origin.serialize`;
  `java.net.URI` performs none of that normalization, so a change that "simplifies" this by using
  URI accessors breaks the claim. `sub` is required and non-blank — a push2u contract stricter than
  RFC 8292 §2.1, deliberately. JWT expiry must be positive and at most 24 hours.
- **Topic** — at most 32 URL- and filename-safe base64 characters (RFC 8030).
- **Content coding** — `aes128gcm` only (ADR-006). Reintroducing `aesgcm` is out of scope for this
  library, not an improvement.
- **Retry-After** — delta-seconds or any of the three HTTP-date forms RFC 9110 requires, reported to
  the caller **with no ceiling applied**, on `RetryableFailure` and on `SignerUnavailable`. A cap
  reintroduced anywhere between the parser and the outcome is a defect: the caller's scheduler is
  the only place a bound can be right, and the library owes it the value that actually arrived.

### 5.2 The two trust boundaries

The endpoint in a `Subscription` is attacker-influenced: a public registration endpoint accepts the
browser's `PushSubscription` JSON verbatim. Everything below follows from that.

- **The endpoint policy must run before any cryptography or I/O**, on `send` *and* `sendAsync` (the
  async path runs the same pipeline precisely so the control cannot be bypassed). A new code path
  that reaches the network without passing `EndpointPolicy` is a must-fix — without it every send is
  a blind SSRF oracle through the status code an answered outcome carries, an unanswered
  `PushOutcome.Indeterminate`, and timing.
- **`Endpoints.requireSecure` is a protocol check, not a security control.** Which hosts a
  deployment may contact is policy and lives in `EndpointPolicy`. Conflating them weakens both.
- **The push transport must not read the response body**, so a hostile service cannot create memory
  pressure by answering with a huge one. **Redirects must not be followed**, and this no longer
  rests on a JDK default: every `HttpClient` the library builds sets `Redirect.NEVER` explicitly,
  and both `JdkPushHttpClient(HttpClient, Duration)` and the `JdkVaultHttpTransport` constructor
  reject a supplied client whose `followRedirects()` differs. Code that builds an `HttpClient`
  anywhere in the library must keep setting the policy rather than inherit it, and a new transport
  seam or a new implementation of an existing one is a place to check the property holds — a
  followed `3xx` re-sends the encrypted body and the request headers past the `EndpointPolicy`
  that vetted the original URI, and turns the redirect target's answer into a delivery result.
- **The Vault transport faces the opposite way** and must read responses — bounded and timed. The
  streamed byte count is authoritative, not a declared `Content-Length`; exceeding the cap fails the
  whole call rather than truncating, because the targeted JSON extraction could otherwise find a
  complete-looking `data.signature` before the cut. A per-request timeout is required, not just a
  connect timeout: in fetched mode a Vault that accepts and never answers would hang startup.
- The two seams stay separate (ADR-005). Unifying them is a design change needing a new ADR that
  supersedes ADR-005, not a refactor — and not an edit to ADR-005 either (§5.6).

### 5.3 Secrets and capability URLs in diagnostics

For every message, log statement, `toString`, exception and health field the change adds or touches,
ask what it can carry when things go wrong:

- the Vault token (`X-Vault-Token`) and the Vault address;
- the path and query of an endpoint — the capability part. `Endpoints.redact` exists for this;
- `p256dh`, `auth`, private scalars, or anything derived from them;
- URI userinfo, which is rejected rather than echoed.

`EndpointRejectedException` extends `RuntimeException` rather than `IllegalArgumentException` on
purpose: web frameworks commonly map IAE to a 400, which would echo a redacted-but-fingerprinted
message back to whoever registered the subscription. A change to that hierarchy needs the same
reasoning, explicitly.

### 5.4 Cryptographic invariants

- **Public-key acceptance is three independent checks**: the advertised key type, the domain
  parameters compared *by value* against `secp256r1`, and the point satisfying `y² = x³ + ax + b
  (mod p)` with both coordinates in `[0, p)`. None implies another, and the JCA validates neither —
  SunEC will happily import a "key" at `(1, 2)`. Dropping one is a must-fix.
- Coordinates are never truncated or padded away to fit 32 bytes.
- A fresh ephemeral key pair and salt per message, from `SecureRandom`. There is no reuse inside a
  send to except: one send is one POST, so a body encrypted under one ephemeral pair is used once
  and a repeat is a second `send` that rebuilds everything. The one deliberate reuse is the VAPID
  token, and it spans *different* sends to one origin (ADR-019). A change that carried an encrypted
  body across attempts would be rebuilding the mechanism this library deleted.
- **ES256**: native `SHA256withECDSAinP1363Format` preferred; the DER fallback takes
  `SHA256withECDSA` from the *same* provider and converts strictly. Provider lookup must never widen
  on the fallback path — that would silently change which implementation signs.
- Comparisons over secret-derived bytes should not short-circuit where an attacker can observe the
  outcome.

### 5.5 The published API

Anything `public` here ships to Maven Central and cannot be withdrawn without a breaking release.
Nothing in the toolchain checks this, which makes it the easiest thing to lose.

- Is the new surface as narrow as the use case requires? A method added "because it might be useful"
  is a permanent commitment.
- Would a recompiled consumer break — a changed return type, a narrowed parameter, a new checked
  exception, a removed overload?
- `--release 21`: no API from a newer JDK, however tempting.
- `@Nullable` placement is a contract: NullAway enforces that the annotations are *consistent*, not
  that they are *right*.
- A new SPI meets the ADR-005 bar or it does not exist: an articulable difference the library cannot
  decide on behalf of the deployment.

### 5.6 ADR conformance

If the change touches architecture, module boundaries, an SPI, the dependency posture or the release
process, check it against the ADRs in `docs/adr/` — and read
`.claude/skills/push2u-review/references/adr.md` for how to review against them. A change that
contradicts an ADR is not automatically wrong; a change that contradicts one *silently* is, because
it leaves the documents describing a design the code no longer follows.

Two edits are findings on sight: an ADR whose decision is implemented being reworded or amended
(immutable — a moved decision is a new ADR, and the old one only ever gets `Superseded by ADR-NNN`
on its status line, or, for a decision superseded only in part, `Accepted; one clause superseded
by ADR-NNN` beside the full form — either is legal, a third spelling is not), and a description of
how the code currently works being added to an ADR instead of to `docs/DESIGN.md`.

### 5.7 Dependencies and supply chain

- `push2u-core` declares no runtime implementation dependency; JSpecify (annotations only) is the
  single exception (ADR-002). Read the build-file diffs, not just the Java.
- Test fixtures: the published conformance kit is the `push2u-testkit` module; every set of
  `testFixtures` in this build is internal scaffolding, and both `push2u-core` and
  `push2u-signer-vault` explicitly skip their fixture variants from publication so an internal
  helper does not become frozen API. Removing a skip publishes API by accident — including, in the
  core's case, a mock push service and a self-signed-certificate factory.
- A vulnerable transitive is pinned with a dependency **constraint** carrying its advisory ID and
  reason — never `resolutionStrategy.force`, which leaves the originally requested version in the
  submitted dependency graph as a phantom node Dependabot then alerts on.
- In the starters, framework artifacts stay BOM-managed, and anything needed only to compile stays
  `compileOnly` so it does not become a runtime dependency of consumers.

### 5.8 Tests as evidence

- Does a new test fail without the change? If it passes either way it proves nothing.
- For security-relevant behaviour, does the test demonstrate that the bad outcome is now
  *impossible*, or only that the good path still works? The second is the more common mistake.
- BC-FIPS tests belong in the `fipsTest` source set and nowhere else: `bc-fips` and stock `bcprov`
  ship incompatible `org.bouncycastle.crypto` classes and cannot share a classpath. A BC-FIPS test
  added to `test` may appear to pass while exercising the wrong provider.
- A new `VapidSigner` implementation extends the published conformance kit,
  `com.the13haven.push2u.testkit.VapidSignerContractTest`, from the `push2u-testkit` module.
- Aggregated coverage must stay ≥ 80 %, but the threshold is a floor, not a target — a large
  untested branch is a finding even when the number holds.

### 5.9 Process

Cheap to check, silently wrong when missed: the pull request carries a changelog label (the label
workflow derives `enhancement`/`bug`/`documentation` from the title, but `security` and, on a title
without `!`, `breaking-change` stay manual); `docs/DESIGN.md` is updated if architecture moved, and
a new file in `docs/adr/` (never an edit to an existing one) if a decision did; `README.md` — or
`docs/SPRING.md` / `docs/VAULT.md` / `docs/HEALTH.md` / `docs/VAPID.md` — is updated if
consumer-facing API, properties or limits changed, and `docs/VAPID-KEY-ROTATION.md` if the VAPID
identity's lifecycle did — how or *when* a signer pins a key version (a new fetch mode moves that
moment as surely as a new accessor would), anything that re-reads a key on a live signer, a
key-version accessor — or if outcome classification moved, since that runbook diagnoses a wrong
identity by `401`/`403` arriving as `NonRetryableFailure` and never as `SubscriptionExpired`, and
reclassifying either would falsify its whole diagnosis section without touching a signer. Each of
those falsifies that document rather than merely dating it; a new suppression or rule exclusion
states its reason next to it.

## 6. Calibrate before reporting

A review is judged by whether its findings are real, not by how many there are. Five confirmed
findings are worth more than twenty plausible ones, because the author has to spend time on each.

- **Verify in the file.** An untraced suspicion is a hypothesis. Either confirm it, mark it plainly
  as needing a check, or drop it.
- **Name the failure.** A finding with no concrete input, sequence or consumer that breaks is a
  "consider" at most.
- **Leave pre-existing problems alone** unless the change makes them worse or touches that exact
  line — and say which when you raise one.
- **Skip what the build catches**, per step 2.
- **Skip what a senior engineer would not raise.** Restructuring that only reflects taste, a rename
  that is merely different, a test that could be marginally tidier.

Severity, in the vocabulary this repository already uses:

- **must-fix** — breaks a protocol claim, a security property, published API compatibility, or an ADR.
- **should-fix** — correct today but leaves a real hazard: an unbounded read, a message that could
  grow to carry a secret, a test that passes for the wrong reason.
- **consider** — judgement: structure, naming, a simpler formulation.

## 7. Report

```markdown
## Verdict
One sentence — mergeable, mergeable after the must-fixes, or not yet, and why.

## Must-fix
- `file.java:120` — what breaks, and the concrete input or sequence that breaks it.

## Should-fix
- `file.java:44` — the hazard, and what makes it reachable.

## Consider
- Brief.

## Verified
What you checked that holds: the vectors that still pass, the boundary still enforced, the API
surface unchanged, the gate green. Without this the author cannot tell what was examined from what
was skipped.
```

Anchor every finding to `file:line`.
