<!--
Security fixes do not start here — see SECURITY.md. A pull request describing an unfixed
vulnerability discloses it.

Label this pull request: the release notes are generated from labels (.github/release.yml), and an
unlabeled one lands in "Other Changes". Use breaking-change / enhancement / bug / security /
dependencies / documentation, or ignore-for-release for housekeeping.
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
      property did, `docs/HEALTH.md` if the health indicator did, `docs/VAPID.md` if the
      key-generation recipe did.
