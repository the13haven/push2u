# ADR-023 — One configured size limit, answerable before a send

**Status:** Accepted

A `PushSender` takes two size parameters. `maxEncryptedBodyBytes` bounds the encrypted entity body,
which is what RFC 8030 §7.2 lets a push service refuse; `recordSize` is the `rs` advertised in the
RFC 8188 header, which RFC 8291 §4 requires to be strictly greater than the plaintext plus the
padding delimiter plus the authentication tag. Both are configurable, independently, and the
pre-flight check takes the smaller of what each permits.

They are not independent enough to be two. `rs` occupies four octets of the header whatever its
value — 4096 and 16777216 cost the same four — so it is a declaration about record length, not a
budget the body draws down. The body is `plaintext + 103` either way. Which means the second
parameter is satisfiable from the first by arithmetic the library already performs: a sender that
can never carry a plaintext above `maxEncryptedBodyBytes − 103` needs no `rs` above
`maxEncryptedBodyBytes − 85`, and nothing about a deployment can make that untrue.

What being two costs, in the tree as it stands:

- `README.md` documents raising the limit as a two-line block whose second line restates the first
  — `.maxEncryptedBodyBytes(8192)` followed by `.recordSize(8192)`, with a comment explaining that
  `rs` must cover the payload as well.
- Both builder setters carry a cross-reference warning about the other. A warning in the
  documentation, sitting exactly where a value could have been computed, is what a false separation
  looks like.
- Raising the body limit alone leaves the budget where it was — 4078 where 8089 was intended — and
  nothing rejects that configuration. Every oversized message is refused one at a time instead.
- ADR-021 had to argue why a refusal collapses the two preconditions back into one statement,
  because a caller shortening a notification cannot act on the difference between them.

The second half of this record answers a question ADR-021 left open and
https://github.com/the13haven/push2u/issues/87 was reopened on: whether the refusal should also be
answerable *before* a send, so an application that renders a notification can shorten it rather
than discover the limit by outcome. The case that made it concrete is translation — the same
notification fits in one language and not in another, and which one overflows is discovered in
production.

**This record owns the size configuration and the pre-flight question**: that one number is
configured and the other derived, that the derivation is exact rather than floored, and that the
budget is reachable only through a typed assessment. It does not touch what a refusal *is* — that
is ADR-021's `PayloadRejected`, unchanged — nor where the limit is expressed, which is ADR-011.

## One configured limit, and `rs` derived from it

`maxEncryptedBodyBytes` stays, alone. `recordSize` stops being a builder step and stops being
`push2u.record-size`. The sender computes, once, at `build()`:

```text
maximumPayloadBytes = maxEncryptedBodyBytes − BODY_OVERHEAD      (103)
recordSize          = maximumPayloadBytes + RECORD_OVERHEAD + 1  (17 + 1)
```

The invariant is one sentence with no "except": **`rs` declares exactly the plaintext capacity this
sender is able to use.** Across the range, including both ends the builder admits:

| `maxEncryptedBodyBytes` | `maximumPayloadBytes` | `rs` |
|---|---|---|
| 103 (the minimum the builder accepts) | 0 | 18 |
| 2048 | 1945 | 1963 |
| 4096 (the default) | 3993 | 4011 |
| 8192 | 8089 | 8107 |
| 2147483647 (the maximum an `int` carries) | 2147483544 | 2147483562 |

The last row is the one to check rather than read: the derived `rs` is `maxEncryptedBodyBytes − 85`
for every configuration, so it stays below `Integer.MAX_VALUE` by construction and cannot wrap —
the same boundary the surrounding code computes in `long` for.

The second addend is written as the record overhead plus the one octet by which RFC 8291 §4
requires `rs` to exceed it — not as `MIN_RECORD_SIZE`, whose value is the same 18 for a different
reason (it is the smallest legal `rs`, which is that rule applied to an empty plaintext). Both
spellings of the rule already run through a single implementation, `maxPlaintextForRecordSize`, and
the derivation is its inverse: it belongs beside it, as `recordSizeForMaxPlaintext`, so one place
still decides the rule in both directions.

**The pre-flight maximum becomes a single subtraction, and its `min` goes with the parameter.**
`maxPlaintextBytes` takes the smaller of what each precondition permits; under this derivation its
two operands are *equal* on every configuration — `maxPlaintextForRecordSize((body − 103) + 18)` is
`body − 103` identically — so the `min` is degenerate, and a branch no input can select is worse
than no branch, because it reads as a live guard. The maximum is the body ceiling less the fixed
overhead, clamped at zero.

`DEFAULT_RECORD_SIZE` disappears with the parameter; as an `rs`, 4096 survives only in the RFC 8291
§5 worked vector, which fixes its own. (4096 remains the *body* default, a different constant.)
`WebPushEncryptor.encrypt` keeps its `rs` parameter — production passes the derived value on every
send — and `checkRecordSize` keeps guarding it, since a direct caller can still hand it an `rs` too
small for its plaintext.

### No floor at 4096

A derivation of `max(4096, maximumPayloadBytes + 18)` was considered, to keep the header byte-identical
to what ships today. It is rejected. It introduces a constant that means nothing after the parameter
it preserved is gone, and it misbehaves at the small end: for a body limit of 2048 it advertises a
record larger than the entire body, and for the minimum of 103 it advertises 4096 against a
103-octet body — a number unrelated to anything in that message, handed to a decoder that may size
a buffer from it. The wire value changes in any case, since this is a breaking change by
construction; 4011 in place of 4096 is legal under RFC 8188 §2, and no implementation known to this
project requires `rs` at or above any particular value. A hardcoded floor is also the thing ADR-011
set out to avoid, in its own words: the plaintext maximum is computed from the format the encryptor
emits, never a constant written into the code.

### Derived per sender, not per message

The other form considered derives `rs` from the payload in hand — `rs = payload + 18`, computed per
send. It is the tighter declaration: a decoder sizing a buffer from `rs` would allocate exactly what
this record needs rather than what the sender's configuration allows, which for a small
notification under a large ceiling is a real difference.

It loses on two counts. It makes `rs` a function of the message rather than of the sender, so the
*declared record length* stops being a property of the configuration: two identical senders emit
different headers for different notifications, and what a deployment advertises can no longer be
read off what it configured. The budget is untouched by this — under `rs = payload + 18` the
record-size precondition is vacuous by construction, leaving `maxEncryptedBodyBytes − 103`, the
same maximum the per-sender form produces — so the pre-flight would work either way, and the
objection is about the header rather than about the bound. And the form as written is incompatible
with padding — a record padded to hide its length is by definition not sized to its payload — where
the per-sender derivation already admits it, as the section below works out. That second count is
weaker than the first and is stated as what it is: a padding feature would redefine the derivation
in either case, so this is a reason to prefer the form that needs no redefinition, not a claim that
the per-message one could never be revisited.

The disclosure argument does not separate them: the plaintext length is already derivable from the
body length, so a varying `rs` reveals nothing a length-counting observer did not have.

### What this does not give up: padding

The `aes128gcm` format allows padding beyond the delimiter, and a sender that padded its records to
a fixed width would make its messages indistinguishable by length to a push service that sees every
body a deployment sends. That is a genuine privacy property, and the obvious worry about removing
`recordSize` is that it is the knob such a feature would need. It is not, and the arithmetic says
so.

RFC 8291 §4 requires `rs` to be strictly greater than the plaintext plus the padding delimiter plus
the authentication tag, so a conforming single record is at most `rs − 1` octets. Under this
derivation `rs = maxEncryptedBodyBytes − 85`, which puts that ceiling at
`maxEncryptedBodyBytes − 86`, and adding the 86-octet header gives a body of exactly
`maxEncryptedBodyBytes`. **The derived `rs` already admits padding up to the configured body
ceiling** — the unpadded maximum this sender accepts produces a record of precisely `rs − 1`, so
the room padding would consume is room the declaration already covers.

What a padding feature would need is a parameter naming the *intent*: the body size every message
is padded to, or a policy that chooses one. `rs` stays derivable from that, as it is derivable from
the body ceiling now. So nothing here forecloses the feature, and the rule-out below is about `rs`
as a refusal threshold rather than about any future length-hiding knob.

### What this does to ADR-011 and how ADR-021 reads afterwards

ADR-011 stands, except for one clause. Its decision — that the *configured* limit is expressed on
the encrypted body rather than on the plaintext, so an operator raising it for a push service
documented to accept more converts nothing by hand — is untouched and is the reason
`maxEncryptedBodyBytes` is the parameter that survives. Its third paragraph, that `recordSize`
stays an independent parameter and is never adjusted to follow the body limit, does not: the
parameter is removed rather than quietly re-aimed, which is the distinction that decides this. When
this ADR is implemented, ADR-011's status line takes the narrow form —
`**Status:** Accepted; one clause superseded by [ADR-023](0023-one-size-limit-answerable-before-a-send.md)`
— and the index cell follows in the index's own link spelling,
`Accepted; one clause superseded by [023](0023-one-size-limit-answerable-before-a-send.md)`.

ADR-021 is not edited, and one of its sentences has to be read with this record beside it. It says
`PayloadRejected` covers both size preconditions — the configured body ceiling and the RFC 8291 §4
record-size rule — because both state that this payload does not fit this sender's configuration.
That remains true of the variant's meaning. What changes is reachability: with `rs` derived, the
record-size bound can no longer be the one that binds on a send, so through `PushSender` the variant
now reports one rule rather than the smaller of two. The rule itself stays enforced inside the
encryptor, where a direct caller can still violate it. Nothing about the outcome's shape, its
numbers or their unit moves.

## The budget is reachable only through a typed assessment

The sender publishes one method for the question:

```java
public PayloadSizeAssessment assessPayloadSize(byte[] payload);
```

```java
public sealed interface PayloadSizeAssessment {
    record WithinLimit() implements PayloadSizeAssessment {}
    record ExceedsLimit(int payloadBytes, int maximumPayloadBytes) implements PayloadSizeAssessment {}
}
```

It reads the array's length, copies nothing and retains nothing. It takes the serialized octets
rather than a length, so the unit is not something the caller converts to; and it takes them rather
than a `PushMessage`, so a payload that will not fit costs no message construction. A caller
holding a built message asks through `payload()`, which copies — accepted, because the reference
flow serializes, asks, and only then builds.

**`WithinLimit` carries no components, and that is settled here rather than deferred.** A payload
that fits needs no number to act on: the action is to send it. The alternative,
`WithinLimit(payloadBytes, maximumPayloadBytes)`, is symmetric and would serve an application
packing a notification to fill its budget — digest lines, list items — which under the chosen shape
has to overshoot deliberately to learn how much room there was. That case is not one this project
has been shown, and it is decided against now because it cannot be decided later cheaply: adding a
component to a record changes its canonical constructor, its accessors and the record patterns
written against it, so the addition is a breaking change and not a compatible one. A record with no
components is also not a singleton — its canonical constructor is public and a caller may create as
many instances as it likes — and nothing here depends on it being one; all instances are equal, and
that is the whole of what the variant carries.

Both numbers on `ExceedsLimit` earn their place: `payloadBytes` is what the caller handed over, and
`maximumPayloadBytes` is the budget for the next render — the same pair, in the same unit
(plaintext octets), that `PayloadRejected` reports, for the same reason ADR-021 gives. Its
compact constructor enforces what its name asserts, in the style `PayloadRejected`'s already does:
neither number is negative, and `payloadBytes` is strictly greater than `maximumPayloadBytes` —
a variant that says a payload exceeds a limit may not be constructed to say the opposite.

**A bare `int maximumPayloadBytes()` on the sender is deliberately not published**, and this is the
part that took two revisions to settle. The obvious minimal answer is a number the caller compares
against, and it exposes two failure modes this library cannot detect afterwards:

- **Units, and this is the argument that carries the decision.**
  `notificationString.length() <= sender.maximumPayloadBytes()` compiles and reads correctly, and
  compares UTF-16 code units against serialized octets. Any non-ASCII notification then passes a
  check it should have failed, and nothing downstream detects it — the send simply reports
  `PayloadRejected` for a payload the application believed it had verified.
- **Direction, which is the weaker half and is stated as such.** The strictly-greater rule of RFC
  8291 §4 is already folded into the computed maximum, so the caller's comparison is the ordinary
  inclusive one and an inverted boundary costs one octet of unnecessary compaction rather than an
  oversized send.

**What the chosen shape achieves is narrower than removing those mistakes.**
`ExceedsLimit.maximumPayloadBytes()` is a published `int`, so from the second iteration onward a
caller can compare against it by hand and make either mistake. What the absence of an accessor on
the sender changes is that the number cannot be obtained *before* one guarded comparison has
happened: the first question about a payload is always answered by the library.

**The price is a one-pass budget-aware renderer, and it is a real capability rather than a
hypothetical one.** With no accessor, an application cannot ask for its budget and render to fit in
a single pass; it must render, serialize, be told it does not fit, and render again. The judgement
this record makes is that a mandatory first guarded comparison is worth more than that pass, because
the mistake it prevents is silent while the extra pass is merely wasteful. The reference case
renders and shortens in any case. If a deployment shows that one-pass rendering matters more, the
accessor is a compatible addition later — unlike the record components above, adding a method
breaks nothing — and that asymmetry is why the two questions are settled differently.

For a related reason no public `PushMessage.payloadBytes()` is added — the accessor does not exist
today and this record does not mint it: it would publish the other operand of the same unguarded
comparison, while the length the pipeline needs is reachable inside the package.

### What the assessment is not

- **Not `Optional<PushOutcome.PayloadRejected>`.** An outcome describes what became of a requested
  send, and a question sends nothing. Reusing the variant would put a `NotAttempted` value in the
  hands of a caller who attempted nothing, and would make the pre-flight's answer switchable
  against branches — `Accepted`, `Indeterminate` — that cannot occur.
- **Not a `boolean`.** On the fitting branch it would say as much as `WithinLimit` does, and the
  objection is to the other one: `false` leaves the budget unobtainable rather than one call away,
  since no accessor publishes it. A caller told only that its notification does not fit has nothing
  to render against.
- **No `excessBytes()`.** It is a subtraction of two published numbers, and it suggests a model
  that does not hold: shortening the source text by the difference does not reduce the serialized
  payload by it, since JSON and UTF-8 make the relation non-linear. The action is to render again
  against `maximumPayloadBytes` and ask again. An application that wants the difference for a log
  line can subtract; ADR-022's criterion is that a different log line is not a different action.
- **Not a replacement for the refusal.** `PushOutcome.PayloadRejected` stays exactly as ADR-021
  defined it, and `send` keeps checking. Asking is optional; being told is not. A caller that never
  asks is where it was, and a caller that asks and then mutates its payload is caught anyway.

## A note on the copy this removes, which is not part of the decision

Recorded here because it arose with the pre-flight and would otherwise be reconstructed from a
diff, **not as a constraint this ADR imposes**: nothing above depends on it, and it can be dropped
or reversed without a superseding record.

`send` is called per subscription, so a message reused across a fan-out is copied once per
subscription inside the library's own code, which only reads it. `PushMessage` keeps its defensive
snapshot at construction and its copying public `payload()`, and the pipeline reads the array
through a package-private accessor instead. The saving is modest — a ciphertext array of the same
order is allocated per send in any case — but it is a copy that protects nothing. The immutability
it relaxes is tested rather than merely documented: a send must leave the message's payload
byte-for-byte unchanged.

## Migration

Removing a builder step and a Spring property is a breaking change, in the window `0.x` was
declared for. The release note names the transition; `README.md`, `docs/SPRING.md`,
`docs/DESIGN.md` and `docs/MIGRATION.md` lose the parameter with it.

The parameter is also load-bearing as an *example*: `.claude/skills/push2u-implement/SKILL.md` uses
`recordSize` / `push2u.record-size` as the worked case for both the one-rule-one-implementation
convention and the recipe for adding a configuration option, and the Spring starter and its tests
cite the property as a naming precedent. A recipe teaching a parameter that no longer exists is
wrong in a way nothing fails on, so those examples move to a parameter that survives.

`push2u.record-size` left in a YAML file after the upgrade must fail the context at startup, naming
the property and where its effect went: binding ignores an unknown key silently, which would leave
an operator believing a setting applies. **The refusal must not be built from a retained property
component** — `Push2uProperties` is a public record, so a component kept only to be rejected freezes
a public accessor that configures nothing into the starter's API. The check belongs on the bound
environment at context refresh, in the spellings relaxed binding accepts; it publishes nothing.
`ignoreUnknownFields = false` is refused for its blast radius over every unrelated typo under
`push2u.`.

**A tombstone like that has an end, and the release that adds one opens the work item that removes
it.** It exists to catch a configuration written against the previous release, not to be carried
for the life of the library, and this one is the first of a family — the same mechanism answers for
every property a release removes afterwards, so without an end date they accumulate as permanent
code that refuses keys nobody has written in years. The window is one minor release after the one
that removed the property. It is stated that way rather than as a number because the version this
work ships in does not exist until the release cuts its tag, and the removal issue names it
afterwards, when it does.

## What this rules out

- Two configurable size parameters, or any second knob whose value is derivable from the first.
- `recordSize` as public API **in its role as a refusal threshold** — a builder step, a Spring
  property, or a properties component retained so that a removed key can be refused. A length-hiding
  feature would configure a padded body size rather than `rs`, and is not what this forbids.
- Data on the assessment's fitting branch: `WithinLimit` carries no components, and adding them
  later is a breaking change rather than a compatible one.
- `rs` derived per message rather than per sender.
- A floor, default or historical constant applied to the derived `rs`.
- A degenerate `min` left in the pre-flight after its second operand became derivable — a branch no
  input can select, reading as a live guard.
- A hardcoded plaintext maximum, or a plaintext limit as the configured knob — ADR-011 unchanged in
  that respect.
- A bare numeric budget on the public API, in any spelling that lets a caller reach the number
  without one guarded comparison first.
- A pre-flight answer typed as a `PushOutcome`, or an outcome variant reused to answer a question
  that sent nothing.
- A derived component published on an assessment because it shortens a log line.
- A pre-flight that replaces the refusal, or a `send` that trusts an earlier assessment.
- A tombstone over the removed property carried without an end, or one whose end is written as a
  version number that does not exist yet.
