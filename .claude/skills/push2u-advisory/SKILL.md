---
name: push2u-advisory
description: Handle a vulnerability report about push2u's own code — triage it, fix it without disclosing it, and publish the advisory with the release. Use this the moment a security defect in this library is reported, suspected or found, whether it arrived through GitHub's private advisory reporting, by email, as a suspicion raised in conversation, or under your own hands while working on something else entirely — a defect nobody reported needs this procedure exactly as much, and is the one most likely to be written straight into a public pull request as an ordinary fix. Use it also whenever the work involves a temporary private fork, a coordinated disclosure date, crediting a reporter, or deciding whether a report is in scope. Not for a vulnerable third-party dependency — pinning one is an ordinary change covered by the push2u-implement skill.
---

# Responding to a vulnerability in push2u

This is the maintainer's side of `SECURITY.md`. That document tells a reporter what to send and what
to expect; this one is what happens next.

It applies to a defect in this library's own code — the encryption, the VAPID signature, key
handling, the endpoint policy, secret exposure in diagnostics — and it applies to one found in
house exactly as it applies to one somebody sent in. Nothing below turns on who noticed first;
what a public pull request discloses is the same either way. A vulnerable *dependency* is a
different thing and an ordinary change: pin it with a constraint, per the recipe in
`.claude/skills/push2u-implement/SKILL.md`. The exception is a dependency flaw that is exploitable
*through* push2u's own API in a way consumers cannot mitigate — then it needs an advisory of its
own and belongs here.

## The habit to suppress first

The normal workflow in this repository is to branch, commit with a descriptive message, push, and
open a pull request explaining the reasoning. Every step of that publishes. Applied to an unfixed
vulnerability in a public repository, it is the disclosure itself, and it cannot be taken back —
forks, mirrors, notification emails and the events API have already seen it.

So, until the advisory is published:

- No public branch, no push to `origin`, no pull request, no issue.
- No commit message on a public branch that describes the defect, even obliquely. "Harden the key
  parsing" next to a diff is a map for anyone reading commits.
- No test committed publicly that demonstrates the flaw. A test named for what it exploits is the
  disclosure with a reproduction attached.
- Nothing in a public discussion, release note draft or README while the fix is pending.

If the work has already leaked into a public branch before this was noticed, say so immediately and
plainly rather than trying to quietly rewrite history: force-pushing does not unpublish anything,
and the response now has to assume the defect is known.

## Triage

**Reproduce it before anything else.** Write the failing test in your local working tree — not
committed to a public branch — that demonstrates the bad outcome. Until that test exists, the scope
is guesswork, and scope is what every later decision depends on.

Then establish, in this order:

- **Is it real, and is it ours?** Check it against the scope list in `SECURITY.md`. A misconfigured
  application is not a library vulnerability — unless the configuration surface makes the unsafe
  outcome the silent default, which is.
- **What is reachable, and in what configuration?** A defect on a path that requires an explicit
  non-default option is a different severity from one on the default `send` path. Say which.
- **Which versions?** Before the first release this is simply `main`; afterwards, name the range,
  because that is what goes in the advisory and what consumers filter on.
- **What must an application do besides upgrade?** Rotate a VAPID key, invalidate subscriptions,
  rotate a Vault token. If the answer is anything but "upgrade", it belongs in the advisory
  prominently — a fix nobody knows they must act on is half a fix.

If the report turns out to be out of scope or not a defect, answer the reporter with the reasoning
rather than a bare rejection, and say what would change the answer. They spent effort, and the next
report from them is worth having.

## Fixing it privately

Work in the temporary private fork GitHub creates from the draft advisory: open the advisory under
*Security → Advisories*, then *Start a temporary private fork*. It appears as a private repository
named `push2u-ghsa-xxxx-xxxx-xxxx`, visible only to advisory collaborators. Clone it and work there.

Three properties of that fork change how you work, and all three are easy to be caught out by:

- **CI does not run.** Integrations cannot access temporary private forks, so no workflow fires and
  no status check reports. The quality gate — the thing this project leans on to catch the
  mechanical half of every change — is simply absent, in the one situation where a mistake is most
  expensive. Run `./gradlew qualityCheckCi` locally and record the result in the advisory notes so
  the next person can see it was run rather than assumed.
- **Branch protection is not enforced** when the advisory's changes are merged. The rules that
  normally make it impossible to land something unreviewed do not apply here.
- **Only one pull request may target the fork's `main`.** A second one blocks merging entirely, so
  keep the fix as a single branch rather than splitting it the way you might normally.

Merging happens from the advisory page — *Merge pull request(s)* — not from the pull request itself.

The fix itself follows the ordinary standards of this repository, with one emphasis: the test must
demonstrate that the bad outcome is now impossible, not that the good path still works. That test is
the durable part. The advisory expires from attention; the test is what stops the same defect
returning in a year.

## Publishing

Publish the advisory together with the release that fixes it, not before. In the advisory:

- describe the defect accurately, including what an application must do beyond upgrading;
- credit the reporter unless they asked otherwise — `SECURITY.md` promises this;
- request a CVE if the defect affects released versions, so downstream scanners can see it.

Then the public artefacts stop being coy. Once the advisory is out the commit message and release
notes should describe the fix plainly — the repository's own history already does this, and a
security fix disguised as a refactor is worse than useless to anyone auditing later. Label the pull
request `security`, which the release-notes workflow routes to its own section; the automatic
labeller will not infer it from a `fix:` title, because whether a fix is a security fix is a
judgement about impact, not a prefix.

Afterwards, check whether `SECURITY.md`'s supported-versions table still says something true.

## Keeping the reporter informed

`SECURITY.md` states targets — acknowledgement within three business days, an assessment within ten,
and a coordinated disclosure window defaulting to 90 days. Those are a commitment made in public.
Agree the disclosure date explicitly rather than leaving it implied, and tell the reporter when the
fix is released even if they have gone quiet. A reporter who is kept informed usually waits; one who
is ignored publishes.
