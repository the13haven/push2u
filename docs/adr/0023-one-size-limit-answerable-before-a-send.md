# ADR-023 — One configured size limit, answerable before a send

**Status:** Proposed

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

The second addend is written as the record overhead plus the one octet by which RFC 8291 §4
requires `rs` to exceed it — not as `MIN_RECORD_SIZE`, whose value is the same 18 for a different
reason (it is the smallest legal `rs`, which is that rule applied to an empty plaintext). Both
spellings of the rule already run through a single implementation, `maxPlaintextForRecordSize`, and
the derivation is its inverse: it belongs beside it, as `recordSizeForMaxPlaintext`, so one place
still decides the rule in both directions.

`DEFAULT_RECORD_SIZE` disappears from the production configuration with the parameter. The value
4096 survives only where it is part of a specific example — the RFC 8291 §5 worked vector, whose
`rs` is fixed by the vector rather than chosen by this library. `WebPushEncryptor.encrypt` keeps its
`rs` parameter for exactly that reason, and `checkRecordSize` keeps guarding it: reachable
directly, it must still refuse an `rs` too small for the plaintext it is handed.

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

### What this does to ADR-011 and how ADR-021 reads afterwards

ADR-011 stands, except for one clause. Its decision — that the *configured* limit is expressed on
the encrypted body rather than on the plaintext, so an operator raising it for a push service
documented to accept more converts nothing by hand — is untouched and is the reason
`maxEncryptedBodyBytes` is the parameter that survives. Its third paragraph, that `recordSize`
stays an independent parameter and is never adjusted to follow the body limit, does not: the
parameter is removed rather than quietly re-aimed, which is the distinction that decides this. When
this ADR is implemented, ADR-011's status line takes the narrow form,
`Accepted; one clause superseded by ADR-023`, and the index cell follows.

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

It reads the array's length, copies nothing and retains nothing. `WithinLimit` is a singleton
constant rather than an allocation per question, because a fan-out asks it once per notification.

Both numbers on `ExceedsLimit` earn their place: `payloadBytes` is what the caller handed over, and
`maximumPayloadBytes` is the budget for the next render — the same pair, in the same unit
(plaintext octets), that `PayloadRejected` reports, for the same reason ADR-021 gives.

**A bare `int maximumPayloadBytes()` on the sender is deliberately not published**, and this is the
part that took two revisions to settle. The obvious minimal answer is a number the caller compares
against. It loses to the typed form on two counts, and they are the failure modes this library
cannot detect afterwards:

- **Units.** `notificationString.length() <= sender.maximumPayloadBytes()` compiles and reads
  correctly, and compares characters against octets. Any non-ASCII notification then passes a check
  it should have failed.
- **Direction.** `>` against `>=` is a one-octet error at exactly the boundary where RFC 8291 §4's
  strictly-greater requirement already proved how easy that is to get wrong.

Publishing the number *beside* the assessment would not fix either: both mistakes stay expressible,
and the library would be offering the right path next to the wrong one. So the number is published
only as a component of the answer that already made the comparison. The cost is real and accepted:
the budget cannot be learnt without a serialized payload to ask about, so an application discovers
it by asking once and rendering again, rather than by consulting a configuration value before it
renders anything. The reference case works that way in any case — a notification is rendered, then
shortened when it does not fit.

For the same reason `PushMessage.payloadBytes()` is not public: it is the third spelling of the
same unguarded comparison, and the length is available inside the package where the pipeline needs
it.

### What the assessment is not

- **Not `Optional<PushOutcome.PayloadRejected>`.** An outcome describes what became of a requested
  send, and a question sends nothing. Reusing the variant would put a `NotAttempted` value in the
  hands of a caller who attempted nothing, and would make the pre-flight's answer switchable
  against branches — `Accepted`, `Indeterminate` — that cannot occur.
- **Not a `boolean`.** It would answer whether the payload fits without saying what it must fit
  into, forcing a second call for the number that makes the answer actionable.
- **No `excessBytes()`.** It is a subtraction of two published numbers, and it suggests a model
  that does not hold: shortening the source text by the difference does not reduce the serialized
  payload by it, since JSON and UTF-8 make the relation non-linear. The action is to render again
  against `maximumPayloadBytes` and ask again. An application that wants the difference for a log
  line can subtract; ADR-022's criterion is that a different log line is not a different action.
- **Not a replacement for the refusal.** `PushOutcome.PayloadRejected` stays exactly as ADR-021
  defined it, and `send` keeps checking. Asking is optional; being told is not. A caller that never
  asks is where it was, and a caller that asks and then mutates its payload is caught anyway.

## The message's array is read without a copy inside the package

`PushMessage` keeps its defensive snapshot at construction and its copying public `payload()`. It
gains a package-private reader that returns the array itself, and the pipeline uses that.

The reason is the fan-out: `send` is called per subscription, so a message reused across a hundred
thousand of them is copied a hundred thousand times, inside the library's own code, which only
reads it. The saving is modest — the ciphertext array of the same order is allocated per send in
any case, and ECDH dominates both — but it is a copy that protects nothing.

The immutability it relaxes is not merely documented, it is tested: a send must leave the message's
payload byte-for-byte unchanged. That is what keeps the relaxation from becoming a defect the day
some later step wants to pad, zero or otherwise touch the buffer it was handed. The reader is named
so the call site says what it is (`payloadNoCopy`), and the analyser suppression it needs states the
reason in place.

## Migration

Removing a builder step and a Spring property is a breaking change, in the window `0.x` was
declared for. The release note names the transition; `README.md`, `docs/SPRING.md`,
`docs/DESIGN.md` and `docs/MIGRATION.md` lose the parameter with it.

`push2u.record-size` left in a YAML file after the upgrade must fail the context at startup, naming
the property and where its effect went. Binding ignores an unknown key silently, which would leave
an operator believing a setting applies; the starter's existing habit is to reject a configuration
it cannot honour and to name the YAML spelling when it does.

## What this rules out

- Two configurable size parameters, or any second knob whose value is derivable from the first.
- `recordSize` as public API, in the builder or as a Spring property.
- A floor, default or historical constant applied to the derived `rs`.
- A hardcoded plaintext maximum, or a plaintext limit as the configured knob — ADR-011 unchanged in
  that respect.
- A bare numeric budget on the public API, in any spelling that lets a caller write the comparison
  itself.
- A pre-flight answer typed as a `PushOutcome`, or an outcome variant reused to answer a question
  that sent nothing.
- A derived component published on an assessment because it shortens a log line.
- A pre-flight that replaces the refusal, or a `send` that trusts an earlier assessment.
