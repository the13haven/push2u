# Health indicator

This is the reference for the health indicator `push2u-spring-boot-starter` registers —
[`SPRING.md`](SPRING.md) carries every `push2u.*` property the sender itself takes, and
[`README.md` → Spring Boot](../README.md#spring-boot) the dependency coordinate and the Spring Boot
version the starters need.

The document is in two parts. The first is the indicator itself: what it probes, what that asserts
and what it does not, the two keys that configure it, and when it is registered. The second is
Spring Boot's own health-group machinery — the routes that keep a signer's backend out of a
container health check, and what the framework validates about a group. Much of that second part is
framework behaviour that would read the same for any contributor at all, and the two are not
separated: the third recipe writes `push2u` into a group's YAML, and one subsection is about this
contributor from its heading down. It does not divide into a part to read and a part to skip.

## The probe

When Spring Boot health support is present, the starter also exposes
a health indicator that exercises the configured signer end to end: it signs a probe input and
verifies the resulting 64-byte ES256 signature locally against the signer's advertised public
key — so a signer that returns bytes which do not verify (a mispinned Vault `public-key`, for
instance) reports `DOWN` instead of failing every real send with `401`/`403`. On the rare JVM
whose providers offer no ES256 verification primitive at all, the probe degrades to checking the
signature length only and says so in the payload with a fixed `verification: unavailable` detail
(plus a one-time WARN); the detail's absence means the `UP` went through full verification.

**What it asserts is exactly that, and nothing beyond it.** The signer signs, and what came back
verifies against the public key that signer itself advertises — which catches a credential that no
longer authorises signing (an expired or revoked token, a key renamed or deleted, a permission
withdrawn) and a signature that does not belong to the advertised key. It asserts **nothing about
push services**: not that any of them is reachable, not that a stored subscription is still valid,
not that a send would be accepted. `UP` here means this application can produce a VAPID signature,
and a push service can still refuse every message you send afterwards.

Because the health endpoint is polled (Kubernetes probes commonly hit it every ~10 seconds per
pod) and each probe of a remote signer is a full backend round-trip — against Vault Transit, one
sign operation that is written to every audit device, counted against rate-limit quotas and, for
`managed_key`-backed keys, billed as an HSM operation — the probe result is cached per process:

```yaml
management:
  health:
    push2u:
      enabled: true      # default — the standard switch, see below
      cache-ttl: 30s     # default — how long a successful probe result is reused
```

**Both keys are where Spring Boot puts a health contributor's own settings**, and the switch is the
framework's rather than one of ours: `enabled: false` removes the indicator entirely, so health
never touches the signer, and `management.health.defaults.enabled: false` — the setting that turns
every contributor off wholesale — reaches this one too. Both are answers to the coupling described
below, at the cost of having no probe at all. Earlier versions spelled these two keys
`push2u.health.enabled` and `push2u.health.cache-ttl`; **both now fail the context at startup**, in
any spelling relaxed binding accepts, with a message naming the replacement. They are refused rather
than ignored for the reason the removed `push2u.record-size` is: an ignored `enabled: false` would
have the deployment that switched the probe off quietly probing its signer again, and an ignored
`cache-ttl` would restore the default TTL under a deployment that had lengthened it. Both refusals
are transition aids, carried for one minor release after the release that removed the properties,
and then removed themselves. A context holding several removed keys at once — the released guide
printed `record-size` beside the `push2u.health` block — is refused once, naming every one of them,
so the whole of the edit is visible on the first failed start.

**One change at the upgrade has no dead key to refuse, and it is the one to check by hand.** Earlier
versions of this indicator ignored `management.health.defaults.enabled` entirely, so a deployment
that turned every contributor off wholesale kept the push2u probe; it now honours that setting like
any other contributor and the probe goes, silently, with nothing left in the configuration for a
startup check to object to. If you were relying on it, name it back with
`management.health.push2u.enabled: true`. Either way, check any health group that mentions `push2u`
before upgrading: a group naming a contributor that is no longer registered stops the context
starting, with the framework's validator message below — which names the group's entry and nothing
about what removed the contributor, least of all a setting that was doing something else yesterday.

A successful result is served from cache for `cache-ttl`; a *failed* result for at most 5 seconds
(the shorter of `cache-ttl` and 5s), so recovery is noticed quickly even under a long TTL.
Concurrent health evaluations are collapsed into a single signing operation. `cache-ttl: 0s`
disables caching entirely; negative values fail startup naming the property. The cache is
per-process by design — probes ask about the pod they run in.

The indicator participates in the health endpoint's primary group, and no configuration takes it out
of that one: `management.endpoint.health` has no top-level `include`/`exclude` — those exist only
under `group.<name>.*` — so the root `/actuator/health` holds every registered contributor. Spring
Boot's `liveness` and `readiness` groups are assembled separately and hold, by default, only the
application's own availability state, so a signer outage does not restart pods — an unreachable
Vault is not something a container restart fixes. That default is what keeps them apart, not a rule:
declare a group of either name including `push2u` and it lands there, so `liveness` in particular is
a group to leave alone.

The indicator is registered when a `VapidSigner` bean exists, and asks about nothing else: the
signer is the only part of a send that can stop working while the application runs — it reaches a
backend that can go down, holds a token that can expire, names a key that can be deleted — while
the rest of a `PushSender` is configuration the builder validated at startup.

While the main autoconfiguration is active, a signer bean gives you a `PushSender` bean as well (or
a startup failure naming `push2u.vapid.subject` or the allowlist properties), so this changes
nothing there. Where it matters is a context that *excludes* `Push2uAutoConfiguration` and wires its
own `PushSender` around a signer kept as a bean: the probe then applies to exactly the signer that
sender uses.

An application that supplies its own `PushSender` and no `push2u.vapid.*` therefore gets no
indicator: that sender's signer lives inside it, where the starter cannot reach it, and an
indicator reporting health it never established would be worse than its absence. When the entry is
missing and you expected it, `/actuator/conditions` (or starting with `--debug`) names the bean the
condition did not find. Note the flip side of probing a bean: an application that supplies both its
own `PushSender` *and* `push2u.vapid.*` gets an indicator that exercises the signer built from
those properties, not the one inside its sender.

## Keeping the probe out of a container health check

**The root endpoint is the one to think about.** With a remote signer this probe is a
dependency-availability check, so a container `HEALTHCHECK` on `/actuator/health` reports the whole
container unhealthy for as long as the signer's backend is unreachable, and everything gated on
`depends_on: service_healthy` waits behind a notification channel. A deployment for which push
delivery *is* the product may want precisely that; one for which it is a secondary channel points
the check at a group instead. Three ways to do that, in the order to try them, and a fourth setting
that is not one of them.

**Whichever you pick, the YAML alone changes nothing.** A group is a second endpoint beside the root
one, so the container check has to be pointed at it explicitly; the `healthcheck` line is part of
each recipe below and not an afterthought.

**1. Spring Boot's own `readiness` group, where its meaning fits.**

```yaml
healthcheck:
  test: ["CMD", "curl", "-fsS", "http://localhost:8080/actuator/health/readiness"]
```

It is there by default (`management.endpoint.health.probes.enabled` defaults to on) and, unless you
declare a group of that name yourself, is assembled by the framework rather than from
`management.endpoint.health.group.*` — so it names no contributor, and nothing done to this
indicator can break it. The short `/readyz` path is a separate switch and is *not* on by default:
without `management.endpoint.health.probes.add-additional-paths`, the group answers on
`/actuator/health/readiness` only.

The price is that it asserts only the application's own readiness state — not the database, not
whatever else the root endpoint was asserting for you. **Answering that price is what ends the
immunity**: the moment you write `management.endpoint.health.group.readiness.include`, the group
comes from properties like any other, the membership check below applies to every name in it, and
this has become the second recipe with the first recipe's name on it.

**2. A group naming what the check is meant to assert.**

```yaml
management:
  endpoint:
    health:
      group:
        container:
          include: db,diskSpace     # contributors this deployment guarantees
          additional-path: "server:/healthz"
```

```yaml
healthcheck:
  test: ["CMD", "curl", "-fsS", "http://localhost:8080/healthz"]
```

It never mentions push2u, so no way of removing the indicator can break it, and `additional-path`
puts it on the application's own port so the check need not know Actuator's paths. Two prices. It is
a closed list, so a contributor added later does not join it. And every name in it carries the
presence requirement below — including the part of it that catches people out: **a contributor's
name is its bean name minus a `HealthIndicator`/`HealthContributor` suffix, which is not always how
its property is spelled.** Disk space registers as `diskSpace` while its switch is
`management.health.diskspace.enabled`; names are matched exactly, case included, so the property
spelling in a group is the failure below.

**3. `exclude: push2u`, where the indicator's presence is guaranteed.**

```yaml
management:
  endpoint:
    health:
      group:
        container:
          exclude: push2u
```

```yaml
healthcheck:
  test: ["CMD", "curl", "-fsS", "http://localhost:8080/actuator/health/container"]
```

Membership is "included and not excluded", and an empty `include` includes everything, so this reads
"everything but push2u" — the shortest form, and the only one that keeps picking up contributors
added later. It is also a claim about push2u, which is what the presence requirement below is about.
The same machinery in reverse gives the monitoring side a group that *does* watch the probe:

```yaml
management:
  endpoint:
    health:
      group:
        push:                       # not push2u — see below
          include: push2u           # /actuator/health/push
```

**Excluding this probe is not the same as keeping its backend out of the verdict.** The exclusion
removes one contributor from one group. A deployment that also carries some other contributor
reaching the same backend — a Vault health indicator from another starter, say — still has that
backend in the group, and an outage still marks the container unhealthy through the other entry. If
that is what the exclusion was for, the contributors actually in the group are what to check, not
this one.

### A group that names `push2u`

**A name in a group's `include` or `exclude` is a claim that the contributor exists.** Spring Boot
4.1 validates both sides while the context starts, and fails it with

```
Health contributor 'push2u' defined in 'management.endpoint.health.group.container.exclude' does not exist
```

By the conditions above, the `push2u` contributor is absent from a deployment that set
`management.health.push2u.enabled: false`, from one that set
`management.health.defaults.enabled: false` and did not name this indicator back in, from one that
stopped configuring a signer, and from one that dropped the starter — and a group naming it stops
all four from starting. The message names the framework's validator rather than anything done to
push2u, which is why it is worth knowing in advance: a group that names this contributor is edited
in the same change that removes it. The edit is the same one in every case, and it is the right one
on its own terms — the exclusion was there to keep a signer probe out of the check, and there is no
probe left to keep out.

**That assumes one party owns both, and an application distributing push2u is where it stops being
true.** A health group shipped inside an image is a build artifact; the deployment that switches the
probe off has properties and environment variables and no way to edit it. So the rule for anyone
*shipping* a group is the stronger one: **do not name `push2u` in a group you distribute** — you are
writing a claim that someone else will be refused for, in a message naming neither you nor them. The
deployment left holding such an image is often not stuck: the group's key can be overridden from the
environment like any other, and an explicitly empty value clears the list and passes the check
(`MANAGEMENT_ENDPOINT_HEALTH_GROUP_CONTAINER_EXCLUDE=`). Often, because that spelling works for a
single-word group name — an environment variable is read on its `_` boundaries, so a group named
`container-check` is not reachable this way and a variable naming it lands on a different key
entirely. It is a repair, and one the deployment did not choose the conditions of.

**Empty there means empty, not blank.** A single space, or a lone comma, is not an empty list: the
conversion from a delimited string counts only a zero-length value as nothing, so a space arrives as
one element and is then trimmed to `""`, and the check goes looking for a contributor named `''`.
The context fails exactly as it was failing before, this time naming an empty string, which carries
nothing at all to reason from. "I cleared it" and "I blanked it" are the same intention, and only
one of them starts.

### Where the membership check stops, and the validator beside it

**A `*` in a group's `include` or `exclude` switches that check off for everything written after
it.** The validator walks a group's names in the order they were written and stops at the first `*`,
leaving the rest of that list unchecked. `include` and `exclude` are walked separately, so a `*` on
one side says nothing about the other.

So the wildcard's position, and nothing else, decides whether a mistake beside it is caught:
`include: "*,diskspace"` starts cleanly while `include: "diskspace,*"` refuses over `diskspace` —
the misspelling from the second recipe — although the two are the same list and do the same thing
once running, since a name written beside a `*` is already matched by the `*`, wherever it sits.
Such a name is therefore always inert, and checked only where it stands before the wildcard. This
is why the second recipe above spells its list out: an explicit list is the one the framework
actually checks for you.

**Do not name a group after a contributor.** A dedicated `/actuator/health/push2u` is the obvious
thing to want here, and it does not start. A *second* validator, beside the membership one, refuses
a contributor whose name equals a group's, and the registration fails with `HealthContributor with
name "push2u" clashes with group`. This one is not raised through the framework's failure-analysis
machinery, so it arrives without a line telling you what to do about it. Name the group after the
question it answers, as the `push` group above does.

**`management.endpoint.health.validate-group-membership: false` is the escape hatch from the
membership check, and not a fourth recipe.** It points no check anywhere and moves no contributor
between groups; it stops that one check from failing a context, for every group and every name at
once, and with it goes the catch for a name misspelled the way `diskspace` is. There is no per-name
form of it — and it does not reach the name clash just above, which has no switch at all. The group
whose name collides has to be renamed.
