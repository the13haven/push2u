# ADR-033 — A tombstone is retired by the next release, not the one after

**Status:** Proposed

[ADR-025](0025-delivery-is-off-by-statement.md) settled what the Spring starters refuse at startup
and in what order, and one row of its table is unlike the rest: the tombstone over a property a
release removed. Every other refusal is about this deployment's own state and lasts as long as the
starter does. A tombstone is about *the upgrade*, and it has an end. ADR-025 named that end in one
clause — "the tombstone is carried for one minor release after the one that removed the property" —
and this record replaces the clause with a shorter window, on evidence that arrived when the first
set of tombstones actually reached its retirement and nobody could say from the documents alone
whether it had.

## What the clause says, and what it turns out to mean

Six `push2u.*` keys were removed and their tombstones shipped in the same release. Reading the
clause against that fact produces two answers rather than one, and both are defensible:

- the tombstone shipped *in* the removing release, so "one minor release after" it means the
  **next** release still carries it and the one after that deletes it — a life of two releases;
- the tombstone exists "to catch a configuration written against the *previous* release"
  (`docs/RELEASING.md`'s own words for it), and once the removing release has shipped, the previous
  release for everything that follows is the one where those keys were already gone — a life of one
  release.

A rule that a careful reader cannot apply is not a rule. Worse, the two answers differ in the one
direction that matters: the longer one keeps executable code alive for an extra release on the
strength of a sentence, and code that refuses keys nobody has written in years is the exact failure
ADR-025 wrote the clause to prevent.

## The decision

**A tombstone is carried by the release that removes the property and retired by the next release,
whatever its size.** One release, counted from the tag that shipped the tombstone, and the count is
of *releases* rather than of minor releases — a patch release retires a tombstone as readily as a
minor one, because nothing about the retirement is a change a version number is protecting.

Three things follow, and they are the whole of it:

1. **The window is a release, not a minor release.** Waiting for the next *minor* meant a tombstone
   could outlive its purpose by an arbitrary number of patch releases, which is neither what the
   clause intended nor something anybody was tracking.
2. **A tombstone is still not permanent, and still ends by someone's hand.** ADR-025's other half
   stands: the release shipping a tombstone opens the work item that retires it, and
   `docs/RELEASING.md` carries that step.
3. **The upgrade that skips a release is served by the migration document, not by a startup
   check.** This is what the shorter window costs and where the cost is paid; the next section is
   about that.

## What the shorter window costs, stated rather than implied

An operator who upgrades **across** the removing release — from the version that still had the keys
straight to the version that no longer refuses them — never meets the tombstone. Their dead keys
are bound away in silence, and for three of the six keys retired under this record that silence
changes *delivery* rather than a diagnostic: a deployment that configured several attempts starts
clean and sends one POST per message.

The longer window does not remove that operator, it moves them: under two releases they can skip
two and land in the same silence. **There is no window that catches a version-skipping upgrade,
because the mechanism is a check that runs in one version and the upgrade does not stop there.**
What serves that reader is `docs/MIGRATION.md`, which is per source version, which they read
because it is written for the version they are leaving, and which can say "delete these by hand,
nothing checks that you have" in a way a check that is not running cannot.

So the trade is not "protection against no protection". It is one release of an executable check —
which serves the upgrade that goes one step at a time, and which that upgrade has already had —
against a document that serves every upgrade including the ones no check reaches. The record buys
the second and stops paying for a second release of the first.

## What this rules out

- A tombstone carried past the release after the one that shipped it, for any reason, including
  that no release has happened in a while.
- A window counted in minor releases, or in any unit that lets a patch release pass without the
  count advancing.
- A tombstone with no work item behind it — ADR-025's other clause, unchanged and not superseded.
- A permanent startup refusal over a removed key, under any name.
- Relying on a startup check to serve an upgrade that skips a release. The migration document is
  where that reader is answered, and a removal whose migration section does not name every key it
  removed is not finished.
- Restating this window anywhere but in `docs/RELEASING.md`, which is where the procedure lives.
  A second copy in a source comment or a design document is a copy that goes stale on its own.

## Documents

`docs/RELEASING.md` step 5 states the window and is the one place it is written down;
`docs/DESIGN.md` describes the mechanism as it stands. ADR-025 keeps its number, its title and its
body, with its status line taking the partial form and its window clause superseded here.
