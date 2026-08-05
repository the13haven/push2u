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
