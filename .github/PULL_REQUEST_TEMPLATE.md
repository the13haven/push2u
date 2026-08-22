<!--
Security fixes do not start here — see SECURITY.md. Does anything you are about to write here
describe a way for a remote peer — a push service, whatever answers on the Vault address, an
endpoint arriving in a subscription — to reach a secret or a key, forge or evade the VAPID
signature, get past the endpoint policy to the network, write into a log some other system trusts,
or exhaust memory or time? And does a released version of this library complete that path? Then
this pull request discloses it, whether or not the fix travels with it, and whether the defect was
reported to you or found by your own hands. Stop and report it privately instead. An ordinary bug
is not this, neither is a dependency pin naming its own advisory, and neither is hardening that
closes a path no released version completes.

Label this pull request: the release notes are generated from labels (.github/release.yml), and an
unlabeled one lands in "Other Changes". Use breaking-change / security / enhancement / bug /
dependencies / documentation — they are matched in that order, and a pull request appears under
the first of them it carries and under that one only, so a security fix wants `security` even when
it already has `bug`. Housekeeping takes ignore-for-release instead, which drops the pull request
from the notes altogether rather than filing it anywhere.

-->

## What this changes

<!-- The behaviour before and after. Link the issue it closes, if there is one. -->

## Why

<!-- The reasoning a reviewer would otherwise have to reconstruct. If an RFC section, an advisory
     or an ADR drives the change, cite it. -->

## Checklist

- [ ] `./gradlew qualityCheck` passes locally (`build` alone does not run the analysers).
- [ ] A test fails without this change — and, for security-relevant behaviour, demonstrates that
      the bad outcome is now impossible.
- [ ] No new runtime dependency in `push2u-core` (ADR-002).
- [ ] New packages carry `@NullMarked`; new public API carries Javadoc.
- [ ] Any new suppression or rule exclusion states its reason next to it.
- [ ] `docs/DESIGN.md` updated if the architecture moved, and a *new* file in `docs/adr/` if a
      decision did (an implemented ADR is never edited); `README.md` updated if the consumer-
      facing API or limits changed, `docs/SPRING.md` / `docs/VAULT.md` if a starter or Vault
      property did, `docs/HEALTH.md` if the health indicator did, `docs/SIGNER.md` if the
      `VapidSigner` contract did (the shape checks, which exception a custodian failure leaves in,
      what the conformance kit asserts), `docs/TESTKIT.md` if the test kit's fixtures or its
      transport fake did — what `ScriptedPushHttpClient` answers, what `SubscriptionFixture` or
      `VapidKeyPairFixture` publishes, what `SentPush` keeps — `docs/VAPID.md` if the
      key-generation recipe did,
      `docs/VAPID-KEY-ROTATION.md` if the identity's lifecycle did — how or when a signer pins a
      key version, anything that re-reads a key on a live signer, a key-version accessor, or a
      change to how `401`/`403` is classified.
