# Releasing push2u

This document describes how push2u releases are produced: the one-time publishing setup, the
repository secrets the workflows depend on, and the release procedure itself. The design
rationale behind this process is recorded in
[ADR-013](adr/0013-release-and-publication-process.md).

In short: the version is derived from git tags (`vX.Y.Z`) by the
[axion-release plugin](https://axion-release-plugin.readthedocs.io/); artifacts are signed with
GPG and published to Maven Central through the
[Central Portal](https://central.sonatype.org/publish/publish-portal-upload/) under the
`com.the13haven` group ID; a release is started manually from GitHub Actions.

## One-time setup

These steps are already done for this repository. They are recorded here so the setup can be
reproduced — after a key rotation, a fork, or a move to another namespace.

### 1. Verify the namespace in the Central Portal

1. Sign in at [central.sonatype.com](https://central.sonatype.com).
2. Add the namespace `com.the13haven` (*View Namespaces → Add Namespace*).
3. The Portal issues a verification key. Prove ownership of `the13haven.com` by adding a DNS
   `TXT` record containing that key to the domain, then start verification in the Portal.
   Central checks the record on the exact domain the namespace reverses to — this is why the
   group ID must be a domain the project actually owns (see [ADR-013](adr/0013-release-and-publication-process.md)).

### 2. Generate a Central Portal user token

Publishing authenticates with a user token, not with the account password.

1. In the Portal: account menu → *View Account* → *Generate User Token*.
2. The Portal shows a username/password pair once. Store them as the
   `MAVEN_CENTRAL_USERNAME` and `MAVEN_CENTRAL_PASSWORD` repository secrets.

### 3. Generate and publish a GPG signing key

Central requires every published file to carry a detached GPG signature and verifies it against
a public keyserver.

Generate an RSA 4096 key (choose *RSA and RSA* when asked for the kind of key):

```bash
gpg --full-generate-key
# Kind of key: RSA and RSA
# Key size: 4096
# Use a real name/email for the release identity and set a passphrase.
```

Find the key ID:

```bash
gpg --list-secret-keys --keyid-format=long
# sec   rsa4096/<KEYID> ...
```

Publish the public key to the keyservers Central checks against:

```bash
gpg --keyserver keys.openpgp.org --send-keys <KEYID>
gpg --keyserver keyserver.ubuntu.com --send-keys <KEYID>
```

Note: `keys.openpgp.org` only serves the identity (name/email) of a key after the address is
confirmed via the verification e-mail it sends; the key material itself is served regardless.

Export the private key in ASCII armor for the `SIGNING_KEY` secret:

```bash
gpg --armor --export-secret-keys <KEYID>
```

Store the full armored block (including the `BEGIN`/`END PGP PRIVATE KEY BLOCK` lines) as
`SIGNING_KEY`, and the key's passphrase as `SIGNING_PASSWORD`.

#### Check the key before it is needed

Signing runs inside Gradle: the `signing` plugin's `useInMemoryPgpKeys` uses the BouncyCastle
implementation shipped in the Gradle distribution, so no `gpg` binary, keyring or agent is
involved — on a developer machine or on a CI runner alike. The build reads the key from
`SIGNING_KEY` / `SIGNING_PASSWORD`, so the exact release-time signing path can be exercised
anywhere those two variables are set.

The Release workflow already runs this check on the runner before it pushes a tag, so a broken
key stops the release rather than stranding a version. Running it locally is therefore optional
— useful when a key is being replaced and the round trip through GitHub is not worth it:

```bash
export SIGNING_KEY="$(gpg --armor --export-secret-keys <KEYID>)"
export SIGNING_PASSWORD='<passphrase>'
./gradlew nmcpZipAggregation
unzip -l build/nmcp/zip/aggregation.zip | grep -c '\.asc$'   # expect one per artifact
```

If this fails to decrypt the key, the two usual causes are the export format of a recent GnuPG
and a key whose signing capability sits on a *subkey* rather than on the primary key. In the
latter case the two-argument `useInMemoryPgpKeys(key, password)` call in
`build-logic/src/main/kotlin/push2u-publish.gradle.kts` picks the wrong key and has to become
the three-argument form that names the key ID.

### 4. Generate the release bot's SSH deploy key

The release workflows push back to the repository — the release commit onto `main` as well as the
tags. `GITHUB_TOKEN` cannot be handed to axion's JGit transport, so the push goes over SSH with a
dedicated deploy key:

```bash
ssh-keygen -t ed25519 -C "release-bot@noreply.the13haven.com" -f push2u-deploy-key -N ""
```

1. Add the public key (`push2u-deploy-key.pub`) in the repository's
   *Settings → Deploy keys → Add deploy key* and check **Allow write access**.
2. Store the private key (`push2u-deploy-key`) as the `ACTIONS_WRITE_KEY` secret.
3. Delete both files locally once the secret is stored.

### 5. Let the release bot past the branch ruleset

A release does not only push a tag. axion's `preRelease` hook rewrites the Maven coordinates in
`README.md` and commits them as `Release vX.Y.Z`, then tags that commit and pushes both to `main`
— a direct push to the protected default branch.

The repository's ruleset **Protected main** (*Settings → Rules → Rulesets*) targets the default
branch and would reject it. It requires a pull request to change `main` (squash the only allowed
merge method, code-owner review), requires the `quality`, `Analyze java-kotlin` and
`Analyze actions` status checks, and blocks branch deletion and non-fast-forward pushes. A release
commit pushed straight from a runner satisfies none of that.

So the ruleset carries one bypass entry: **Deploy keys**, with bypass mode *Always*, added under
*Bypass list* in the ruleset editor. Two consequences worth knowing before reproducing this:

- **The entry is the deploy-key class, not a named key.** GitHub has no way to grant the bypass to
  one specific deploy key, so *every* deploy key with write access on this repository can push
  directly to `main`. That is why the repository has exactly one — `release-bot`, the key from
  step 4 — and why adding a second write-enabled deploy key is a decision about who may bypass the
  ruleset, not a piece of housekeeping.
- **Nothing else bypasses.** No role, team or app is on the list, so every human change to `main`
  still goes through a pull request and the required checks, including one made by a repository
  administrator.

Tags are not covered by any ruleset here, so the tag push itself needs no bypass; the bypass exists
for the release commit that precedes it.

The configuration can be read back without touching the UI — the reply lists the rules and a
`bypass_actors` entry of type `DeployKey`:

```bash
gh api repos/the13haven/push2u/rulesets
gh api repos/the13haven/push2u/rulesets/<id>
```

If the release fails at *Perform release* with a push rejected by a rule
(`refusing to allow ... push`, `Changes must be made through a pull request`), this bypass is what
is missing — on a fork, on a restored repository, or after the ruleset was edited.

## Repository secrets

| Secret | Purpose | How to obtain |
|---|---|---|
| `ACTIONS_WRITE_KEY` | Private SSH deploy key; the workflows use it to push the release commit to `main`, the release tag, and the next-version marker tag — the commit is why it needs the ruleset bypass | `ssh-keygen` as above; the matching public key must be a repository Deploy key with write access |
| `SIGNING_KEY` | ASCII-armored GPG private key that signs every published artifact | `gpg --armor --export-secret-keys <KEYID>` |
| `SIGNING_PASSWORD` | Passphrase of the GPG signing key | Chosen when the key was generated |
| `MAVEN_CENTRAL_USERNAME` | Username half of the Central Portal user token | Central Portal → *View Account* → *Generate User Token* |
| `MAVEN_CENTRAL_PASSWORD` | Password half of the Central Portal user token | Same token generation step |

## Cutting a release

### Freeze main while a release runs

**Nothing merges into `main` from the moment the Release workflow is started until it finishes.**
The run takes tens of minutes, most of it the quality gate, and it is working from the commit it
checked out at the start. A pull request merged into `main` in the meantime makes axion's push
non-fast-forward — and that fails *after* the release commit and the tag have been created, which
is the expensive half: a version number burnt, nothing on Maven Central, and the recovery
procedures below to work through.

Say so in the pull requests that are waiting, or leave them until the release is out. The rule is
not enforced by the ruleset — there is nothing in GitHub that closes merging for the duration of a
workflow run.

What *is* enforced is that a release cannot proceed on a stale `main`: the workflow records the
commit it was cut from and, in the last step before the tag, checks `origin/main` still points at
it. If it moved, the run fails with both SHAs and nothing has been tagged or published — start the
release again on the new `main`.

### 1. Make sure pull requests are labeled

GitHub Release notes are generated automatically from the merged pull requests since the last
tag, grouped by PR labels as configured in `.github/release.yml`. Before releasing, check that
every merged PR carries the right label:

- `breaking-change`
- `security`
- `enhancement`
- `bug`
- `dependencies`
- `documentation`

They are listed in the order `.github/release.yml` matches them, which is a priority order: a PR
carrying two of them appears under the first, and under that one only.

A PR that should not appear in the notes at all carries `ignore-for-release` — housekeeping, and
anything merged before the first tag, where "what changed" is a question about code no consumer
has seen.

### 2. Write the notes, if the release needs words of its own

Optional, and usually skipped: the generated list of pull requests is the changelog. But a release
whose changes need framing — the first one, a migration, a deprecation with a story behind it —
gets a hand-written introduction from `.github/release-notes/<tag>.md`, for example
`.github/release-notes/v0.1.0.md`. Commit it to `main` before releasing.

Both *Release* and *Publish Existing Tag* pick the file up by tag name and pass it to
`gh release create --notes-file … --generate-notes`, which **prepends** it: the hand-written text
sits at the top and the generated categories follow underneath, so adding a file never costs the
changelog. No file, and the notes are generated exactly as before.

Write any version number in it by hand: the pre-release hook that rewrites Maven coordinates
(`build.gradle.kts`) touches `README.md` only, so a snippet in these notes is nobody's job but
yours.

The hook matches any `X.Y.Z` in those coordinates rather than the version axion reports as the
previous one, and that is deliberate. At the first release there is no *release* tag: axion computes
`previousVersion` with `ignoreNextVersionTags`, so the `vX.Y.Z-SNAPSHOT` marker pushed by *Setting
the next version* is skipped and the value falls back to `initialVersion`, `0.0.0` — a string
`README.md` does not contain. A literal pattern would have matched nothing exactly once, on the
release where the coordinates matter most, and without saying so.

The notes can also be edited on GitHub afterwards — a GitHub Release is mutable, unlike the
artifacts on Maven Central. The file exists so the text is reviewed with the code and is there the
moment the release goes public, not so editing later becomes impossible.

### 3. Run the *Release* workflow

*Actions → Release → Run workflow* (on `main`). The workflow then:

1. refuses to run on any branch other than `main`, and verifies that all five secrets below are
   present;
2. runs the full quality gate (`qualityCheckCi`: compilation, all test suites including
   `fipsTest` and the Testcontainers-backed Vault test, static analysis, coverage threshold);
3. builds and signs the deployment bundle **without uploading it**, and fails unless every
   artifact carries a signature;
4. checks that `origin/main` still points at the commit the run was cut from, and fails if it
   moved (see *Freeze main while a release runs* above) — the last step that can still fail
   without consequences;
5. has axion write the `Release v<X.Y.Z>` commit (the `preRelease` hooks rewrite the README
   coordinates), create the tag `v<X.Y.Z>` from it, and push **both the commit to `main` and the
   tag** over SSH with the deploy key — the commit is what needs the ruleset bypass above;
6. creates a **draft** GitHub Release for the tag, with notes generated from the merged pull
   requests — prefixed by `.github/release-notes/<tag>.md` when that file exists (step 2);
7. in a fresh Gradle invocation (so the version resolves from the new tag, not as a snapshot),
   builds each module's `jar`, `-sources.jar` and `-javadoc.jar`, signs everything with the GPG
   key, and uploads the bundle to the Central Portal via `publishAggregationToCentralPortal`.
   The publishing mode is AUTOMATIC: once the Portal's validation passes, the deployment is
   released to Maven Central without any manual step;
8. takes the GitHub Release out of draft, now that the artifacts it describes actually exist.

The order is deliberate. Steps 1–4 run entirely on the runner, so a failure there leaves nothing
behind at all. Step 5 pushes a commit and a tag: the tag can simply be deleted, the commit cannot
— the ruleset blocks non-fast-forward pushes to `main`, so only the deploy key could rewrite it,
and in practice you move forward rather than back. Step 6 creates a draft, which can still be
deleted. **Step 7 is where reversibility ends entirely** — after it the artifacts are on Maven
Central, which is immutable.

### 4. Verify the result

- **Maven Central:** the deployment appears under *Publish → Deployments* in the
  [Central Portal](https://central.sonatype.com/publishing), and the artifact page
  ([central.sonatype.com/artifact/com.the13haven/push2u-core](https://central.sonatype.com/artifact/com.the13haven/push2u-core))
  shows the new version. Availability on `repo1.maven.org` follows shortly after a successful
  deployment; search indexing can lag behind actual availability.
- **GitHub:** the *Releases* tab shows the new release with its generated notes, and the
  `v<X.Y.Z>` tag exists.

### 5. Check that every tombstone this release shipped has its removal issue

A release that *removes* a configuration property leaves a tombstone behind it — a startup refusal
that fails the context while the dead key is still in a YAML file, so an operator who upgrades is
told where the setting went instead of having it ignored in silence. Binding drops an unknown key
without a word, which is why the refusal exists at all.

A tombstone is not permanent. It is there to catch a configuration written against the *previous*
release, and one carried indefinitely becomes code that refuses keys nobody has written in years.
The window is **one minor release after the one that removed the property**, and closing it is a
piece of work somebody has to be holding.

**The change that writes a tombstone is what opens that issue**, in its own pull request, where the
debt and its record are made by the same hand — `.claude/rules/workflow.md` and `CONTRIBUTING.md`
carry that rule. This step is the net under it rather than the rule itself, and it is a question
about this release and not a sweep of the tree: did anything merged since the previous tag remove a
`push2u.*` property? If so, each removal has a startup refusal naming the key and an open issue that
retires it. Open the issue here if one is missing.

Such an issue states the window as that rule rather than as a version, and links the pull request
that wrote the tombstone. From this tag onward that pull request shows the release it went out in,
which is the release the window runs from — so the issue needs no version number of its own, and it
would take one only after a tag, never before.

## Setting the next version

Axion derives the next version on its own, once a tag exists: it increments the **patch** number,
so after `v0.1.0` the build reports `0.1.1-SNAPSHOT` and the next release is `0.1.1`.

Before the first tag it behaves differently. `scmVersion.tag.initialVersion` in the root
`build.gradle.kts` is pinned to `0.0.0`, and that is the version *released first* rather than a
base the incrementer starts from: an untagged repository reports `0.0.0-SNAPSHOT`, and `release`
would create the tag `v0.0.0`. The patch incrementer only engages afterwards.

**This is why a minor or major bump needs an explicit version.** Left alone, axion only increments
the patch from the last tag — the version it derives without a Setup Next Version run is a patch
release, never a minor or major one. On a repository with no tags at all, there is no last tag to
increment from, and the version released would be `initialVersion` (currently `0.0.0`, set in
`build.gradle.kts`'s `scmVersion` block) rather than whatever the README documents — the sharpest case of this rule,
since every version an untagged repository could fall back to is wrong. So before a Release that
should land a minor, a major, or the very first version, run:

*Actions → Setup Next Version → Run workflow*, entering the intended version as `nextVersion`
in `X.Y.Z` form (e.g. `0.2.0`).

The workflow validates the input against SemVer and runs axion's `markNextVersion`, which
pushes a marker tag; from that point every build reports `X.Y.Z-SNAPSHOT` and the next release
becomes `X.Y.Z`. Choose deliberately: the marker is a pushed tag that all future version
derivation builds on.

## Troubleshooting

### Central Portal validation failed

If the *Publish to Maven Central* step fails, open *Publish → Deployments* in the
[Central Portal](https://central.sonatype.com/publishing) and read the per-file validation
errors. Typical causes: a missing `-sources.jar` or `-javadoc.jar`, an incomplete POM (Central
requires name, description, URL, license, developers, and SCM information), a missing
signature, or a signing key that cannot be found on a public keyserver — re-check step 3 of the
one-time setup in that case.

Because the publishing mode is AUTOMATIC, a failed validation means **nothing was released**:
Maven Central is unchanged. The tag and the draft release, however, already exist.

> **Do not re-run the Release workflow to recover.** axion would see the tag, move on to the next
> version number, and publish the same tree twice under different coordinates. GitHub's "re-run
> failed jobs" is no help either: Actions re-runs whole jobs, never individual steps, so it would
> repeat the tagging as well. Use one of the two workflows below instead.

Pick by what you want to happen to the version:

**Finish this release** — *Actions → Publish Existing Tag*, entering the tag (e.g. `v0.1.0`). It
checks out that tag, verifies the resolved version matches it, uploads to Central, and takes the
draft release live.

It also covers the narrower failure where the upload succeeded but the release was left as a
draft: before uploading it asks `repo1.maven.org` whether the version is already there and skips
the upload if it is, so the run reaches the step that takes the release live instead of dying on
a duplicate rejection.

That check cannot see a deployment Central has accepted but not yet mirrored. If the workflow
still tries to upload, read the Portal's *Deployments* page and go by the deployment state:

| State | What to do |
|---|---|
| `PENDING`, `VALIDATING`, `VALIDATED`, `PUBLISHING` | **Wait.** The deployment is still in flight and can still end `FAILED`. |
| `PUBLISHED` | Re-run with **`skipCentralUpload`** ticked; it will only finish the GitHub Release. |
| `FAILED` | Fix the cause and re-run normally — nothing was published. |

`PUBLISHED` is the only terminal success state. Taking the GitHub Release live while a deployment
is `PUBLISHING` would announce artifacts that may never arrive, which is why the input is not a
shortcut for "probably fine". Once the state reaches `PUBLISHED`, repo1 usually catches up within
minutes, and a plain re-run without the tick works too — the 200 check then finds the version by
itself.

**Abandon this release** — *Actions → Delete Draft Release*, entering the tag. It removes the
draft release and refuses to touch one that is already published. The tag and the release commit
axion made on `main` stay, so the next release simply takes the following version number.

Either is equivalent to doing it by hand:

```bash
# finish
git checkout v0.1.0
export SIGNING_KEY="$(gpg --armor --export-secret-keys <KEYID>)"
read -rs -p "GPG passphrase: " SIGNING_PASSWORD && export SIGNING_PASSWORD
export MAVEN_CENTRAL_USERNAME=... MAVEN_CENTRAL_PASSWORD=...
./gradlew publishAggregationToCentralPortal --no-daemon
gh release edit v0.1.0 --draft=false

# abandon
gh release delete v0.1.0 --yes
```

### Reusing a version number

The workflows never delete a tag, so a failed release consumes its version number and the next one
moves on. That is the cheap and correct default: version numbers are free, and a gap in the
sequence costs nothing.

Reclaiming a number is a manual operation on purpose, because no automated check can establish
that a version did *not* reach Central. The Portal's API reports deployment state by deployment
id, which a later workflow run does not have, and offers no endpoint answering "is this version
published"; a 404 from `repo1.maven.org` proves nothing, since the repository lags behind a
deployment that may still be in `PUBLISHING`.

So verify with your own eyes first — open *Publish → Deployments* in the
[Central Portal](https://central.sonatype.com/publishing) and confirm there is no deployment for
that version in any state other than `FAILED`. Only then:

```bash
git push --delete origin v0.1.0
```

If you get this wrong, the outcome is two different trees claiming one immutable version. Central
will refuse the second upload, which limits the damage — but the repository is then lying about
what `v0.1.0` was.

### A published version is wrong

Maven Central is immutable: a published version can never be deleted, replaced, or re-uploaded.
The only fix is forward — correct the problem and release the next version. This is also why
the release workflow is a deliberate manual trigger
([ADR-013](adr/0013-release-and-publication-process.md)).
