# Releasing push2u

This document describes how push2u releases are produced: the one-time publishing setup, the
repository secrets the workflows depend on, and the release procedure itself. The design
rationale behind this process is recorded in [`DESIGN.md`](DESIGN.md), ADR-013.

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
   group ID must be a domain the project actually owns (see ADR-013).

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

### 4. Generate the release bot's SSH deploy key

The release workflows push tags back to the repository. `GITHUB_TOKEN` cannot be handed to
axion's JGit transport, so the push goes over SSH with a dedicated deploy key:

```bash
ssh-keygen -t ed25519 -C "release-bot@noreply.the13haven.com" -f push2u-deploy-key -N ""
```

1. Add the public key (`push2u-deploy-key.pub`) in the repository's
   *Settings → Deploy keys → Add deploy key* and check **Allow write access**.
2. Store the private key (`push2u-deploy-key`) as the `ACTIONS_WRITE_KEY` secret.
3. Delete both files locally once the secret is stored.

## Repository secrets

| Secret | Purpose | How to obtain |
|---|---|---|
| `ACTIONS_WRITE_KEY` | Private SSH deploy key; the workflows use it to push the release tag and the next-version marker tag | `ssh-keygen` as above; the matching public key must be a repository Deploy key with write access |
| `SIGNING_KEY` | ASCII-armored GPG private key that signs every published artifact | `gpg --armor --export-secret-keys <KEYID>` |
| `SIGNING_PASSWORD` | Passphrase of the GPG signing key | Chosen when the key was generated |
| `MAVEN_CENTRAL_USERNAME` | Username half of the Central Portal user token | Central Portal → *View Account* → *Generate User Token* |
| `MAVEN_CENTRAL_PASSWORD` | Password half of the Central Portal user token | Same token generation step |

## Cutting a release

### 1. Make sure pull requests are labeled

GitHub Release notes are generated automatically from the merged pull requests since the last
tag, grouped by PR labels as configured in `.github/release.yml`. Before releasing, check that
every merged PR carries the right label:

- `breaking-change`
- `enhancement`
- `bug`
- `security`
- `dependencies`
- `documentation`

### 2. Run the *Release* workflow

*Actions → Release → Run workflow* (on `main`). The workflow then:

0. refuses to run on any branch other than `main`, and verifies that all five secrets below are
   present — both checks happen before anything is tagged or uploaded;

1. runs the full quality gate (`qualityCheckCi`: compilation, all test suites including
   `fipsTest` and the Testcontainers-backed Vault test, static analysis, coverage threshold);
2. has axion create the release tag `v<X.Y.Z>` from the current version and push it over SSH
   with the deploy key;
3. in a fresh Gradle invocation (so the version resolves from the new tag, not as a snapshot),
   builds each module's `jar`, `-sources.jar` and `-javadoc.jar`, signs everything with the GPG
   key, and uploads the bundle to the Central Portal via `publishAggregationToCentralPortal`.
   The publishing mode is AUTOMATIC: once the Portal's validation passes, the deployment is
   released to Maven Central without any manual step;
4. creates a GitHub Release for the tag with auto-generated release notes.

### 3. Verify the result

- **Maven Central:** the deployment appears under *Publish → Deployments* in the
  [Central Portal](https://central.sonatype.com/publishing), and the artifact page
  ([central.sonatype.com/artifact/com.the13haven/push2u-core](https://central.sonatype.com/artifact/com.the13haven/push2u-core))
  shows the new version. Availability on `repo1.maven.org` follows shortly after a successful
  deployment; search indexing can lag behind actual availability.
- **GitHub:** the *Releases* tab shows the new release with its generated notes, and the
  `v<X.Y.Z>` tag exists.

## Setting the next version

Axion derives the next version on its own. The build pins its starting point to `0.0.0`
(`scmVersion.tag.initialVersion` in the root `build.gradle.kts`), and after every release it
increments the **patch** number — so with no tags at all the first release would be `v0.0.1`,
and after `v0.1.0` the build becomes `0.1.1-SNAPSHOT` and the next release `0.1.1`. When the
next release should be a different number — a minor or major bump, or **the very first release,
which is meant to be `0.1.0` rather than the derived `0.0.1`** — set the version explicitly:

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
Maven Central is unchanged. The release tag, however, has already been pushed by the previous
workflow step. After fixing the cause, either publish that same tag manually (check out the
tag, export the four publishing secrets as environment variables, and run
`./gradlew publishAggregationToCentralPortal`), or delete the tag — safe only because nothing
reached Central under that version — and run the *Release* workflow again.

### A published version is wrong

Maven Central is immutable: a published version can never be deleted, replaced, or re-uploaded.
The only fix is forward — correct the problem and release the next version. This is also why
the release workflow is a deliberate manual trigger (ADR-013).
