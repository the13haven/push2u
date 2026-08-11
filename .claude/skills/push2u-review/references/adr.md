# ADRs: reviewing a change against them

Read this when a change touches architecture, a module boundary, an SPI, the dependency posture, the
nullness contract or the release process — or when a review needs to say whether a change is allowed
to do what it does.

**The decisions themselves live in `docs/adr/`, one file each, indexed with a one-line "what it
rules out" per decision in `docs/adr/README.md`.** Read that index rather than a copy of it: an
index kept in two places drifts, and the one that drifts is the one nobody publishes. The ADRs are
the settled decisions — not documentation of the code, but the reasons the code is shaped the way it
is. `docs/DESIGN.md` is the companion piece and describes the architecture as it stands.

## Reviewing against them

Ask two questions, in this order.

**Does the change contradict an ADR?** Not "does it feel unusual" — does it do the thing the ADR
rules out. Adding `com.fasterxml.jackson` to the core contradicts ADR-002. Adding a
`PayloadEncryptor` interface contradicts ADR-003 and ADR-005. Making `sendAsync` cache a
subscription contradicts ADR-004.

**If it does, does it say so?** A contradiction is not automatically wrong — the ADRs were written
by people who could not see every future requirement. The requirement is that the change carries the
new decision in the same pull request, with the reasoning. A silent contradiction is a must-fix,
because every later reader of the documents will be misled by it.

Watch for the quiet version of this: a change that does not violate the letter of an ADR but hollows
it out. A core that declares no dependency but requires one on the consumer's classpath to work still
breaks ADR-002.

## What a change to the record is allowed to look like

**An ADR whose decision is implemented is immutable.** A change that edits one — rewording it,
bringing it up to date with the code, appending an amendment — is a finding, whatever the edit
improves. What it should have done instead:

- a decision that *moves entirely*: a new file with the next free number, stating the new decision
  and what it replaces, plus one edit to the old file — its status line becomes
  `**Status:** Superseded by [ADR-NNN](NNNN-slug.md)`. The superseded file is never deleted; its
  number is cited from other ADRs, from `docs/DESIGN.md` and from the code review procedure;
- a decision that *moves only in part*: the same one-line edit, in a narrower form beside the full
  one rather than replacing it — `**Status:** Accepted; one clause superseded by
  [ADR-NNN](NNNN-slug.md)`. *Which* clause is superseded belongs in the new ADR, not in this one's
  status line — naming it here would smuggle the new decision's reasoning into a file that may not
  carry it. ADR-004's status line, pointing at ADR-019, is the case to check this against;
- a description of how things now *work*: that belongs in `docs/DESIGN.md`, the document meant to
  be rewritten as the code moves. An ADR describing the present tense goes stale and may not be
  edited to catch up, which is precisely why the split exists;
- a decision that was never implemented: still a draft, still freely editable, and its status line
  says `Proposed`.

`docs/adr/README.md` carries the full procedure and the house style for a new one.

## Two things no ADR states, and a reviewer has to

`docs/RELEASING.md` is the operational companion to ADR-013 — a release-process change usually
touches both, and only one of them is an ADR.

Published sources cite no ADR at all. Every module ships a `sources.jar`, so a comment saying
"(ADR-014)" or "see `DESIGN.md`" reaches a consumer with no repository to follow it into; the
reasoning goes into the sentence instead. `checkstyleReferences` fails the build on it, so it is not
a review finding — but a change that *weakens or excludes* that rule is.
