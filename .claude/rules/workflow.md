# Workflow

How work gets from a request to `main` in this repository. It applies to this session and to any
subagent doing the work.

## Whatever the size of the task

Work happens on a branch, never directly on `main` — the ruleset refuses a direct push in any case,
and merges are squash-only.

Review is a step, not a formality. Every finding it produces is either fixed or answered with the
reason it is not a defect; skipping one silently is how a review stops being worth running. The work
is done when a review comes back with nothing reasonable left to fix.

**Merging into `main` is the user's decision.** Ask, and wait for the answer. An approval of the
code is not an approval to merge — they are separate, and only the second one lets you merge.

## A small task, done in one pass

1. Branch from `main` for the task.
2. Implement it — in this session or in a subagent, whichever fits.
3. Review the change in a separate subagent, never in the one that implemented it.
4. Fix every reasonable finding. Review again if the fixes were substantial enough to introduce
   something new.
5. Report the outcome and ask the user before merging.

## A large task

1. Plan it first, and split it into subtasks that can be implemented independently.
2. Create the feature branch from `main`.
3. Give each subtask to a subagent. Subagents branch **from the feature branch**, not from `main`,
   so the work converges where it belongs.
4. Each subtask runs its own review-and-fix loop, exactly as a small task does — reviewed by a
   subagent other than the one that implemented it — and merges into the feature branch only once
   its review is clean.
5. When every subtask is merged, review the feature as a whole. Individually correct changes can
   still be wrong together — a shared assumption that drifted, a boundary crossed in two places, a
   limit now checked twice and enforced nowhere.
6. Fix what that review finds, then ask the user for the final approval.

Parallel subagents cannot share one working tree; they would be checking out over each other's
branches. Give each one `isolation: "worktree"` so it works in its own checkout.

## Work that starts from a tracker issue

Someone filed it, and they are the one person guaranteed to want to know what became of it. Two
places carry the reference, and both are written while the work is still open.

**The pull request into `main` says `Closes #N` in its description.** Not only in a commit message:
a closing keyword in a commit closes the issue but leaves the pull request unlisted as a linked one,
which costs the reporter the single hop that leads them from the issue to the release the fix
shipped in. Several issues take one keyword each. Work that advances an issue without finishing it
says `Refs #N` instead — a plain mention, carrying the traceability without the close.

**The closing keyword goes on the pull request into `main` and on no other**, and the reason is
sharper than tidiness:
a closing keyword is interpreted only when the pull request targets the default branch. On a pull
request into a feature branch it is ignored outright — no link is created, and merging does nothing
to the issue — so a subtask pull request carrying one is not noise but a silent no-op that reads
exactly like a job done. The reference can be added afterwards by editing a merged pull request's
description and the link does appear; doing it up front is what makes the close automatic and keeps
anyone from closing the issue by hand and inventing a mechanism for it.

**An ADR that comes out of an issue names it, and names it while the ADR is `Proposed`.** Once its
decision is implemented the ADR is immutable, so a reference added later cannot be added at all. A
plain URL is the form — the `checkstyleReferences` ban is on `main` sources, not on `docs/`.

**No document, label, milestone or comment names the version the work will ship in.** That number
does not exist until the release cuts the tag, the release notes are generated from the pull request
labels at that moment, and a number written in advance is a guess that outlives the guessing. The
issue links to the pull request; the pull request shows its release once there is one. If an issue
has to state the release in its own words, that is said after the tag, never before.

None of this applies to a vulnerability: there is no public issue to reference, and
`.claude/skills/push2u-advisory/SKILL.md` carries that path instead.

## Work that has to file one

The mirror of the section above. A change that leaves a debt behind opens the issue that collects
it, and does so in its own pull request. The shape this repository has is a **tombstone**: the
startup refusal a release leaves over a configuration property it removed, so that an operator
upgrading with the dead key still in a YAML file is told where the setting went instead of having it
ignored in silence — binding drops an unknown key without a word.

A tombstone has an end. It is there to catch a configuration written against the *previous* release,
and one carried indefinitely becomes code refusing keys nobody has written in years. The window is
one minor release after the one that removed the property.

**The change that writes the tombstone opens the issue that removes it**, in the same pull request,
referenced with `Refs #N`. Not the release that ships it: filing there makes the obligation depend
on whoever cuts a release recalling, months later and for an unrelated reason, what a change
contained — which has already failed here once, and the tombstone was retired on time only because
someone happened to be holding it in their head. Written at the change instead, the debt and its
record are made by the same hand in the same hour.

The issue states the window as that rule and never as a number: the version this work ships in does
not exist yet, and the section above forbids guessing it. It does not need one — the issue links its
pull request, and that pull request shows its release once there is one, which is the release the
window runs from. One issue covers every key the same change removed.

`docs/RELEASING.md` keeps a check after the tag rather than the obligation itself, so a tombstone
that reached a release without an issue is still caught.

## Delegating

A subagent starts with a fresh context. It inherits `CLAUDE.md` and these rules, but **not** the
skills. So when you delegate implementation or review, tell it to read the file first —
`.claude/skills/push2u-implement/SKILL.md` or `.claude/skills/push2u-review/SKILL.md` — otherwise
the work comes back missing exactly what those files exist to carry.

**Implementation and review go to different subagents, with separate contexts.** A reviewer that
shares the implementer's context inherits its assumptions along with its blind spots — it checks the
code against what the author meant rather than against what the code says, and the defects worth
catching are precisely the ones the author could not see. The reviewing agent therefore gets the
change and the repository, not the implementer's reasoning, and it is a fresh subagent rather than a
fork of the one that wrote the code, since a fork inherits the parent's context by definition.

The same holds when this session wrote the change itself — review it in a subagent that has to read
the code rather than remember writing it.

**Every subagent is spawned by this session, and a subagent spawns none.** Tell the implementing
agent what it does when the work is done — open the pull request, report back — and that reviewing
is not its job. A reviewer it spawns itself reports to it, so its findings reach this session as the
author's summary of them: the one who is checked and the one who retells the check become the same
agent, and a finding can be softened without anyone intending it. Keeping every spawn here also
keeps the choice of who is asked, and with what brief, where the decisions are made.

## Choosing the model for a subagent

| Kind of task | Model |
|---|---|
| Critical — cryptography, the endpoint policy, key and token handling, anything where a mistake is a security defect | `fable` |
| Complex — a change spanning modules, a new SPI or signer, a design decision, a review with real judgement in it | `opus` |
| Ordinary — a mechanical edit, a documentation change, a test that follows a pattern already in the suite | `sonnet` |

The user may name a different model for any task, and their choice wins. When it is genuinely
unclear which tier a task belongs to, choose the more capable one and say why — the cost of the
larger model is small next to the cost of a subtle defect in this particular library.
