# Spring Boot integration

`push2u-spring-boot-starter` binds the `push2u.*` properties to an autoconfigured `PushSender`.
This is the configuration reference — [`README.md` → Spring Boot](../README.md#spring-boot)
carries the dependency coordinate, the Spring Boot version the starters need, and the minimal
working configuration.

## The minimum Spring Boot

The starters state a **minimum** Spring Boot version and nothing else about which one you run.
[`README.md` → Requirements](../README.md#requirements) carries the number.

What travels in the published metadata is one ordinary dependency: `spring-boot-autoconfigure` at
that version. In Gradle's vocabulary that is a `require` — a floor that another *ordinary*
requirement may raise and none may lower — so a build already on a newer Spring Boot resolves its
own, and a build below the minimum is raised to it, along with what that version of
`spring-boot-autoconfigure` brings with it: `spring-boot`, `spring-core`, `spring-context`,
`spring-beans`, `spring-aop`, `spring-expression`, `commons-logging`, `micrometer-observation` and
`micrometer-commons`. Measured, without naming versions that would go stale here rather than in
README: a Gradle build declaring a Spring Boot below the minimum resolves the minimum, and one
declaring anything at or above it keeps its own.

"Ordinary" is doing work in that sentence, and the table below is where it is paid: a build that
*forces* versions — `enforcedPlatform`, an explicit `force`, the `io.spring.dependency-management`
plugin — overrules this requirement in either direction, downwards included. Nothing published here
can prevent that, and nothing published here tries to.

No Spring Boot BOM is published from either starter, and that is the wider half. **Everything the
BOM used to manage that these starters do not themselves depend on — Jackson, Netty, Tomcat,
Hibernate, the rest of the manifest — is no longer spoken about at all.** Earlier versions did
export that BOM on `api`, and a Gradle consumer who added a starter had all of it raised to
whatever this project happened to build against, silently; [`MIGRATION.md`](MIGRATION.md) has the
note for a deployment that was on the receiving end of it.

**No upper bound is published in any form** — not a range with a closed right end, not a rejection
of future versions, not a "tested up to" presented as a ceiling. When you upgrade Spring Boot is
your decision, and nothing here has an opinion about it.

**Where the minimum is a constraint, and where it is only a statement.** This is worth knowing
before you rely on it:

| Your build | Is the minimum enforced? |
|---|---|
| Gradle, with `platform("org.springframework.boot:spring-boot-dependencies:…")` | **Yes** — resolution takes the higher of the two requirements, which is this one |
| Gradle, with the `io.spring.dependency-management` plugin | **No** — the plugin *forces* its managed versions, in either direction |
| Maven | **No** — a POM has no way to say "not below"; the number is a plain version, your own `dependencyManagement` overrules it outright, and without one it is subject to nearest-definition-wins like any other |

There is no spelling of "not below X" that a POM carries, so for the last two rows the minimum is
documentation and a version resolution is free to overrule. A Maven build that manages no Spring
Boot of its own will in practice resolve the minimum, because nothing competes with it — but that
is an outcome, not a floor: another dependency declaring Boot nearer in the graph takes it at any
version, as does one declaring it at the same depth but earlier in your POM. **Nothing in the library reads Spring Boot's version at runtime either**, deliberately: a
starter below the minimum is not refused at startup, and what happens instead is whatever the
missing API does at the point it is reached.

**Spring Boot 3.x is not supported.** That is a statement about what this project builds against,
tests and answers for — not a claim that these modules cannot run on it.

**The minimum moves for two reasons only**: a starter needs an API the older version does not have,
or a published vulnerability sits in the graph that version resolves and a patch of the same line
fixes it. A newer Spring Boot merely existing is not one. Either move narrows the set of
deployments this library answers for, so either one is written up in
[`MIGRATION.md`](MIGRATION.md) — including in its silent-break section, since a raised floor can
meet a lockfile or a `strictly` constraint you declared yourself.

## Properties

Configure a local VAPID signer:

```yaml
push2u:
  enabled: true                       # default — see Does this deployment send? below
  vapid:
    public-key: "${VAPID_PUBLIC_KEY}"
    private-key: "${VAPID_PRIVATE_KEY}"
    subject: "mailto:ops@example.com"
  jwt-expiry: 12h
  jwt-renew-before: 5m
  jwt-reuse: true
  jwt-cache-size: 64
  default-ttl: 24h
  max-encrypted-body-bytes: 4096    # defaults, shown for reference
  allowed-origins:                  # one of the two is required, unless an EndpointPolicy bean
    - "https://fcm.googleapis.com"  # supplies the allowlist instead
    - "https://updates.push.services.mozilla.com"
  allowed-domains:                  # a whole DNS zone per entry — see Endpoint policy below
    - "push.apple.com"
    - "notify.windows.com"
```

The starter creates a `VapidSigner`, `PushHttpClient`, `PushSender`, and — when the allowlist
properties have an entry — an `EndpointPolicy` bean holding the allowlist they express (see
[Endpoint policy](#endpoint-policy)). Application beans of the same types take precedence.

`push2u.vapid.subject` is required to build the *autoconfigured* `PushSender`, regardless of where
the `VapidSigner` comes from; leaving it unset fails the context with a message naming the
property. The endpoint policy is required in the same way, from one of its two sources — see
[Endpoint policy](#endpoint-policy). Neither is required when the application supplies its own
`PushSender` bean — that bean bypasses the starter's checks entirely.

A signer is required in a way of its own: see
[Does this deployment send?](#does-this-deployment-send) — a context that is on and holds neither a
`VapidSigner` nor a `PushSender` bean fails at startup, and `push2u.enabled: false` is the line
that answers it.

That is every key the sender itself takes. The health probe's two keys are not under this prefix at
all — they are Spring Boot's, under `management.health.push2u.*`, see
[`HEALTH.md`](HEALTH.md) — and the Vault signer starter carries its own
`push2u.signer.vault.*` ([`VAULT.md`](VAULT.md) is their reference). One of those is worth naming
here because it decides *when* a boot can fail: `push2u.signer.vault.public-key-fetch` takes
`eager` — the default, and what an unset or blank value means: the fetched mode's Vault read
happens during context refresh and a Vault that cannot serve it fails the boot — or `deferred`,
which moves that read to the signer's first use, so the application starts while Vault is still
coming up ([`VAULT.md` → When boot must not depend on
Vault](VAULT.md#when-boot-must-not-depend-on-vault)). It takes nothing else: an unrecognised value
fails the context naming the key, and any written value beside a supplied
`push2u.signer.vault.public-key` fails it naming both keys, because the supplied mode performs no
metadata read whose moment the property could choose. Those refusals are raised while the signer
bean is built — step 6 of [the order below](#which-refusal-an-operator-reads-first), on the
delivery-path side of `push2u.enabled` by construction — so they hold no position of their own in
that list. **There is no `push2u.retry.*` block**: the library performs one POST per
send and schedules no repeat, so there is nothing under this prefix to configure — see
[The outcome a Spring caller reads](#the-outcome-a-spring-caller-reads).

**If you are upgrading from a version that had one, delete it from your YAML by hand — nothing
warns you.** `push2u.retry.max-attempts`, `push2u.retry.initial-backoff` and
`push2u.retry.max-backoff` are bound away in silence now, like any key nothing reads. The release
that removed them refused a context still holding one, and that refusal was a transition aid and
has been retired. This is the sharpest case of a leftover key there is: the block still reads as
though it were in force, while a deployment that configured three attempts starts cleanly and makes
one — nothing at startup and nothing at run time says otherwise. Grep every configuration source,
inactive profiles included, in every spelling relaxed binding used to accept.

`jwt-expiry`, `jwt-renew-before`, `jwt-reuse`, `jwt-cache-size`, `default-ttl` and
`max-encrypted-body-bytes` are optional; unset, they leave `PushSender`'s defaults untouched (12h,
5m, `true`, 64 entries, 24h and 4096 bytes respectively — see
[`README.md` → Payload size limits](../README.md#payload-size-limits) for the size property).
`max-encrypted-body-bytes` is the one size key: the `aes128gcm` record size (`rs`) is derived from
it, so raising the ceiling is the whole of raising the limit.

Setting any of them to a value the builder rejects (`jwt-expiry` not strictly positive or over 24h,
`jwt-renew-before` negative, `jwt-cache-size` below 1, `default-ttl` negative, or
`max-encrypted-body-bytes` below the fixed 103-byte `aes128gcm` overhead) fails the context
with the builder's own message, prefixed by the YAML property name — the builder names only its
Java parameter, and the operator wrote the property.

**`push2u.record-size` no longer exists, and a leftover one is ignored rather than reported** — in
any spelling (`push2u.record-size`, `push2u.recordSize`, `PUSH2U_RECORD_SIZE`). The release that
removed it refused such a context, and like the retry block's refusal above that was a transition
aid and has been retired. It named a limit, and a limit silently out of force is exactly what an
operator must not go on believing in, so delete the key; if it was raised to carry larger payloads,
raise `max-encrypted-body-bytes` instead, which the derived record size now follows.

**The three `jwt-*` reuse properties are the ones to know about before something surprises you.**
With `jwt-reuse` at its default, an autoconfigured sender signs one VAPID token per push-service
origin and reuses it for every later message to that origin until it is within `jwt-renew-before`
of expiry, holding at most `jwt-cache-size` of them and evicting the least recently used.
`jwt-reuse: false` restores a fresh signature per message.
[`README.md` → VAPID token reuse](../README.md#vapid-token-reuse) says what each of the three is
for and when a deployment reaches for it. All three are builder values, and the starter builds the
`PushSender` once when the context starts, so a change to any of them — `jwt-reuse: false` included
— reaches sending only on the next start: a redeploy, or whatever restart a configuration refresh
amounts to in your deployment. Plan the switch as one, since the situations it answers are the ones
met while the application is running.

Neither `jwt-renew-before` nor `jwt-cache-size` is validated against `jwt-expiry` or against the
other: a margin at or above `jwt-expiry` is not an error but simply means every send signs afresh,
and a cache bound is never a second way to spell `jwt-reuse: false`, which is why below 1 is
refused rather than read as "cache nothing".

## Does this deployment send?

**A deployment states that it does not send, or the autoconfigured delivery path is present and
usable.** `push2u.enabled` is that statement, it defaults to `true`, and the third state — on, with
neither a `VapidSigner` nor a `PushSender` bean in the context — fails at startup.

```yaml
push2u:
  enabled: false        # this deployment deliberately sends nothing
```

**Why it is a failure and not a warning.** A deployment that mistypes a property prefix binds
nothing, validates nothing, boots green and never sends. Nothing in the process can tell it from a
correctly configured deployment that has had nothing to send yet, and the first symptom is a
notification a user did not receive — which nobody reports. For a library whose whole subject is
delivery, "silently does not deliver" is the state it should be least able to enter, and a WARN in
a log aggregator is a line a deployment finds after the notifications it lost.

**The refusal names every way to answer it**, and any one of them is enough:

- `push2u.enabled: false`, if this deployment deliberately does not send;
- `push2u.vapid.public-key` and `push2u.vapid.private-key`, the two keys this starter owns;
- a signer starter's own configuration — the Vault one's `push2u.signer.vault.*`, or any other
  starter that contributes a `VapidSigner`. The refusal does not name those prefixes: a message
  that spelled another module's activation rules would go stale the day that module changed them,
  and each starter answers for its own keys;
- an application `VapidSigner` bean, or an application `PushSender` bean. Both stand the refusal
  down, from anywhere in the context.

It also points at the framework's condition report, by the **startup flag** that prints it
(`--debug`) rather than at `/actuator/conditions` — a context that failed to start serves no
endpoint.

**Only `true` and `false` are values.** Anything else fails the context naming the property. The
framework's usual reading of an `enabled` key — anything not literally `false` is on — is the safer
of the two directions and still not good enough here: it turns `flase` into a deployment that sends
although it said not to. Absent is not a value: it is the default, and the default is on. A
**blank** value is refused like any other unrecognised one — `PUSH2U_ENABLED=${SOMETHING:}`
resolving to nothing would otherwise have to be read as one of two opposite statements, and the
whole point of the key is that neither guess is acceptable.

### What `false` withdraws, and what it does not

| | `push2u.enabled: false` | `true`, or unset |
|---|---|---|
| The `VapidSigner` this starter builds, the `PushHttpClient`, the `PushSender` | not contributed | contributed |
| The health indicator | not registered | registered (subject to its own key) |
| Every signer starter's signer — including the Vault one's eager startup read | not contributed | contributed |
| An application's own `PushSender` bean | untouched | untouched |
| The `EndpointPolicy` bean the allowlist properties express | **contributed** | contributed |

Startup checks sort by what each one is *about*, never by where it happens to be implemented. Five
of them need a row, and they are the whole of this table — every other refusal the starters raise
happens *while a bean the switch withdraws is being constructed*, so it is on the delivery-path side
by construction and could not be anywhere else: the signer's own key material, every builder value
the sender translates from a property, and every per-property translation in a signer starter.

| Startup check | `push2u.enabled: false` | `true`, or unset |
|---|---|---|
| The value of `push2u.enabled` itself | runs | runs |
| A malformed allowlist entry | runs | runs |
| An allowlist stated beside an application policy bean | runs | runs |
| A signer starter's partial-configuration diagnostic | skipped | runs |
| The general refusal over a missing signer | skipped | runs |

The first three are about a *value*: an entry that is not an origin is not an origin in a context
that sends nothing either. The last two are about the *delivery path* — each asks, in its own
words, whether this deployment can sign, and a deployment that has said it does not send has
answered that already.

**The switch does not reach the endpoint policy**, and that is the point of the row above. A
service that accepts subscriptions and leaves the sending to another one has no signer and wants
none; it is exactly the deployment the policy bean exists for, and `push2u.enabled: false` is the
statement it can make truthfully while keeping the allowlist it states. Being outside the
auto-configuration that carries the sender is *not* what makes the policy safe — the health
indicator is outside it too and is withdrawn all the same.

### A signer starter's own diagnostic

A starter that contributes a signer answers for its own properties. The Vault one refuses a context
whose `push2u.signer.vault.*` block is stated by halves — some of `address`, `key-name` and `token`
present, not all — naming which it found and which are missing, since that shape contributes no
signer and would otherwise say nothing at all. It **stands down** when a `VapidSigner` or a
`PushSender` bean exists from anywhere: a deployment sending through the local signer with a
half-written Vault block left over has a stale property, not a broken deployment. And it is skipped
with `push2u.enabled: false`, because the beans its stand-down looks for are exactly what the
switch removes.

### Blank counts as unset, for the properties that activate a signer

Spring treats an empty property as a present one, so `public-key: "${VAPID_PUBLIC_KEY:}"` beside a
private key defaulted the same way would activate the signer and then be refused — not for its
encoding, since an empty string is valid base64url, but for the length of the point it did not
carry. For the properties that *activate* a signer — this starter's two `push2u.vapid.*` keys, and
each signer starter's own activating set — **a blank value counts as unset**, so what the
deployment reads is the refusal above, naming the configuration that is missing.

Nothing is lost by it: no blank value of any of them could have produced a signer, so the only
outcomes traded are two failures. It is a deliberate divergence from the framework's reading of
"set", and it belongs to activation only — it says nothing about the allowlist properties, where an
explicitly empty value is a statement with a meaning of its own (see
[the escape hatch](#what-fails-at-startup-and-from-where)).

### Which refusal an operator reads first

One context can earn several refusals at once, and what arrives is whichever is declared first.
The order, most specific first, is:

1. the value of `push2u.enabled`;
2. a malformed allowlist entry;
3. an allowlist stated beside an application policy bean;
4. a signer starter's partial-configuration diagnostic;
5. the general refusal over a missing signer;
6. everything else, which is ordinary bean creation — every refusal raised while a bean is being
   built, including what the autoconfigured sender refuses on its own.

Steps 2 to 5 are specific before general, a value before the path. Step 1 sits ahead of all of it
because it decides whether the configuration underneath it can be read at face value at all. It is
about which message arrives first and nothing more: no later step's *condition* depends on an
earlier step's outcome.

### A bean condition on these beans answers "absent" in every deployment

Every refusal above needs something in the context for a check to read — a value, a bean, two
statements contradicting each other. This is the one route into "boots green,
sends nothing" that leaves the context indistinguishable from a working deployment's, so no startup
check can see it:

```java
@Configuration                              // the application's own, or one it @Imports
class NotificationConfiguration {

    @Bean
    @ConditionalOnBean(PushSender.class)    // false in every deployment, silently
    NotificationChannel webPushChannel(PushSender sender) { ... }
}
```

An application's `@Configuration` is parsed before any auto-configuration has registered anything —
that is what deferring them means, and an `@Import`ed class is parsed as user configuration like any
other. The condition is evaluated against a context that does not hold this starter's beans yet, and
answers "absent" however correctly push2u is configured. `@ConditionalOnMissingBean` fails the same
way in the other direction: a fallback registered "only if push2u contributed none" is registered
always, and an application bean is exactly what this starter's own `@ConditionalOnMissingBean`
stands down for — so the fallback silently becomes the sender the deployment actually uses. On the
policy that same mistake is loud rather than silent, and deliberately: a bean beside a stated
allowlist is the contradiction this starter refuses the context over, under [What fails at startup,
and from where](#what-fails-at-startup-and-from-where). Spring Boot documents both annotations as
intended for auto-configuration classes; it is said here because this is the guide that has just
told you to inject these beans, and the failure surfaces nowhere near the annotation that caused it.

**Inject them as ordinary dependencies.** Both beans exist under the rules stated above — the sender
whenever the delivery path is autoconfigured, [the policy](#the-policy-is-a-bean) whenever the
allowlist is expressed — and either one that is genuinely absent is reported by this starter's own
analysis of the injection failure, which answers in the terms of this context rather than leaving a
bean that quietly never appeared.

For a `PushSender`: the contradiction with a stated `push2u.enabled: false`, a signer registered too
late for the sender's condition to see it, or the enumeration of every way to configure one. For an
`EndpointPolicy`: which of the three states the allowlist is in — never decided, every set property
emptied, or stated in a context that excluded the auto-configuration turning it into a bean — in the
words the sender's own refusal uses, out of one text rather than a second copy of it. That second
analysis is the one a registration-only service reads, because it builds no sender for the sender's
refusal over the same absence to run inside; and where such a deployment states `push2u.enabled:
false`, the analysis says in one clause that the switch is *not* why the policy is absent, since
turning delivery back on would not produce it.

For a component that has to disappear along with delivery, condition it on the **property** instead
of on the bean:

```java
@ConditionalOnProperty(name = "push2u.enabled", havingValue = "true", matchIfMissing = true)
```

`matchIfMissing = true` is not optional: absent is not a value, the default is on, and the starter's
own auto-configuration carries exactly this condition. A property is read from the `Environment`, so
there is no ordering to get wrong.

Note which question that answers. `push2u.enabled` is about *sending*, and the policy bean survives
`false` — a component that assesses the endpoints of subscriptions where they are registered is
one a registration-only deployment wants precisely when the switch is off, so whether it exists is
not a question that property answers. For a component that exists in both deployments and does
less in one, inject an `ObjectProvider<PushSender>` and ask it.

`@ConditionalOnBean` is reliable in an auto-configuration of your own, `@AutoConfigureAfter` the
class that contributes what you are asking about — `Push2uAutoConfiguration` for the sender,
`Push2uEndpointPolicyAutoConfiguration` for the policy. That is the case the annotation exists for.

## The outcome a Spring caller reads

The autoconfigured bean is an ordinary `PushSender`, so `send` returns a `PushOutcome` and
`sendAsync` a `CompletableFuture` of one.
[`README.md` → What a send reports](../README.md#what-a-send-reports-and-what-it-still-throws) has
the variants, the classification behind them and the short list of what still throws; three things
about it are worth stating where a Spring deployment meets them.

**Retrying is the application's, and Spring deployments usually already own a retrier.** Spring
Retry, a `@Scheduled` sweep over a store, a queue with redelivery — feed any of them the
`RetryableFailure` whole. The `Retry-After` it carries is reported exactly as it arrived with no
ceiling applied: neither the starter nor the core applies one, so the bound is whatever the
retrier's own configuration says, and that is the only place it can be right. *Useful* is that
variant's whole verdict — it never says a repeat is *safe*, since a `502` or `504` may cover a POST
an upstream applied — so pricing a possible duplicate, and holding a `507` that answered a user
action until a fresh one asks as RFC 4918 §11.5 requires, comes before anything is scheduled; the
`statusCode()` on the outcome is what that last rule reads, which is why the whole value goes in.

**A repeat re-bases the message's lifetime**, since RFC 8030 §5.2 counts `TTL` from receipt. A
`@Scheduled` retry an hour later carries a fresh `default-ttl` unless the application decrements the
`ttl` it puts on the `PushMessage`.

**A fan-out that meets `SignerUnavailable` should stop**, which under Vault Transit is the case to
plan for: the signer's custodian is down, no POST was made, and every remaining subscription would
make its own round trip to it. The health indicator below reports the same condition, but it does
not gate a send in progress — stopping the loop, or stopping submission on the async path, is the
application's.

## Endpoint policy

The endpoint policy is one value applied at both points of a subscription's life: where a
subscription is accepted, and before every send. Every `PushSender` needs one, because which
endpoints a deployment may POST to is a decision it has to express, and a subscription's endpoint
is attacker-influenced wherever subscriptions are registered by clients. See
[`README.md` → Endpoint policy (SSRF hardening)](../README.md#endpoint-policy-ssrf-hardening) for
the threat model and the limits of a URI-level check.

The starter takes that decision from one of two **sources**, and exactly one of them:

- **The allowlist properties**, `push2u.allowed-origins` and `push2u.allowed-domains`. An origin
  entry is one origin, matched exactly; a domain entry is a whole DNS zone, the apex and every
  subdomain at any depth, over `https` on the default port only.
  [`PUSH-SERVICES.md`](PUSH-SERVICES.md) has the four browser push services in this form — two
  origins, and two domains for the two services that publish a zone rather than a host.
- **An application `EndpointPolicy` bean**, which suppresses the starter's own. This is the route
  for anything the properties cannot express — a corporate egress rule, a custom check, or
  `EndpointPolicies.unrestricted()`. The seam answers with a value, so such a bean is still one
  lambda: it returns `new EndpointAssessment.Allowed()` to permit the endpoint, or
  `new EndpointAssessment.Refused("…")` carrying its own account of the refusal. Both are records
  and both are constructed — there is deliberately no shared constant to reach for. Returning
  `null`, or throwing anything at all, is a defect in the policy rather than a refusal, and reaches
  the caller as one.

**The two properties are not two sources.** They are two halves of one statement, and a context
setting both gets one allowlist holding all of their entries — which is exactly the shape a
deployment naming the browser push services needs, since some of them publish a host and some a
zone. The decision is *expressed* when at least one of them is non-empty.

### The policy is a bean

The allowlist the properties express is published as an `EndpointPolicy` bean the moment it is
expressed — at least one of the two properties has an entry — and the autoconfigured `PushSender`
takes that bean from the context like any other collaborator. The bean's condition is deliberately
the allowlist and not the signer: a service that accepts subscriptions and leaves the sending to
another one has no signer and needs exactly this bean, while a deployment that merely carries the
starter without configuring web push gets no bean and no demand for one. The bean is built from
the two properties and from nothing else, so there is still no configuration-only path to
unrestricted egress.

The *obligation* to express the decision stays with the sender: a deployment that sends and has
expressed nothing — both properties unset and no bean, or every set property empty and no bean —
fails at startup exactly as before, with a message naming the ways to fix it. A registration-only
deployment that expresses nothing simply holds no policy bean, and starts — until it injects that
bean, at which point the unsatisfied dependency is answered with the same three states in the same
words: [Inject them as ordinary
dependencies](#a-bean-condition-on-these-beans-answers-absent-in-every-deployment).

**A bean condition on this bean is subject to the same ordering trap as one on the sender**, and to
the same silence: see [A bean condition on these beans answers "absent" in every
deployment](#a-bean-condition-on-these-beans-answers-absent-in-every-deployment).

### Assessing where subscriptions are accepted

A policy refusal is not a `410`: nothing marks the stored row as dead, so a subscription whose
endpoint the policy refuses fails at every send, forever, while the subscriber's browser reports a
healthy subscription. Applying the same policy at registration keeps such rows out of the store —
and because both points read one bean, the two cannot drift: a domain rule added for Edge is
honoured at registration the day it is honoured at send, with no consumer change.

```java
@RestController
class SubscriptionController {

    private final EndpointPolicy endpointPolicy;   // the bean — the starter's, or your own
    private final SubscriptionStore store;

    SubscriptionController(EndpointPolicy endpointPolicy, SubscriptionStore store) {
        this.endpointPolicy = endpointPolicy;
        this.store = store;
    }

    @PostMapping("/subscriptions")
    ResponseEntity<Void> register(@RequestBody SubscriptionRequest request) {
        Subscription subscription;
        try {
            // 1. Build the Subscription first: the RFC 8030 endpoint rules plus the
            //    key-material and length checks. A refusal here is a malformed subscription.
            subscription = Subscription.fromBase64(request.endpoint(), request.p256dh(), request.auth());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();   // malformed — store nothing
        }
        // 2. Apply the deployment's policy to the endpoint the Subscription carries, and act
        //    on what it answers — the assessment is the whole of the check here.
        switch (endpointPolicy.assess(URI.create(subscription.endpoint()))) {
            case EndpointAssessment.Refused refused -> {
                // refused.reason() is the policy's own account of it, written for the log line
                // this application keeps; it does not go into the response.
                return ResponseEntity.badRequest().build();   // policy refuses — store nothing
            }
            // 3. Store only what both accepted.
            case EndpointAssessment.Allowed() -> store.save(subscription);
        }
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
```

**The order is the seam's contract, not the application's preference.** `assess` documents its
argument as an endpoint that already satisfies `Endpoints.requireSecure` — an absolute `https` URL
with a host — and building the `Subscription` first is what establishes that, together with the
key-material and length rules. So: the `Subscription` first, the policy on the endpoint it carries
second, the row stored third.

**The answer has to be read, and here that is the only thing enforcing anything.**
`endpointPolicy.assess(uri);` on a line of its own is legal Java: javac reports nothing about a
discarded return value, `-Xlint:all` included, so the verdict is thrown away and every endpoint that
got past step 1 is stored — `https://10.0.0.5/notify` included, since step 1 checks the shape of the
URL and not where it points. Inside a send that slip cannot open the network: `send` performs the
assessment itself, on every send, and acts on the value. At this boundary nothing stands between the
discarded answer and `store.save` — the row is written on the strength of this one reading, and a
row the policy would have refused is exactly the dead row the paragraph opening this section is
about. So the `switch` above — or an `if`, or any other reading of the returned value — is not a
style choice, it is the control itself.

The language will not tell you it is missing, but a static analyser can, and this call site is
already marked for one: `assess` carries an annotation that analysers matching such a mark by its
*simple name* — Error Prone's
[`CheckReturnValue`](https://errorprone.info/bugpattern/CheckReturnValue) check among them — read
straight out of the class file, so a build already running one has the bare statement fail as an
error, with nothing to configure and no dependency of yours to add. A build running none is
unaffected: an annotation type it does not know is ignored. What it does not cover is a call made
through your own `EndpointPolicy` implementation type, whose overriding `assess` does not inherit
the mark — so a search of your own sources for `assess(`, checking that every hit is read, is still
the one command that catches everything.

What the application does choose is what each refusal answers to its client. A malformed
subscription — the `IllegalArgumentException` from step 1 — and a policy refusal can both sensibly
answer `400` with no body, and neither message was written for the client to read. The assessment's
`reason` is prose for an operator's log line, and a policy of the deployment's own — a corporate
egress rule — may put whatever it finds useful there, short of the raw endpoint the seam forbids,
which is reason enough not to hand it back to whoever posted the subscription. The standard
allowlist is sparing on its own account: its refusals carry the endpoint the client itself sent,
redacted, and never say which rule came closest.

The two refusals arrive in different shapes, and the difference is worth stating, because a policy
refusal used to be an exception here as well. That exception deliberately did not extend
`IllegalArgumentException`, so that no framework's exception handling could turn it into a `400`
echoing its message on the application's behalf — and that requirement is met more completely by a
value than it ever was by an ancestry: there is no exception for a mapping to see, so nothing
translates a refusal for you and nothing can echo the reason unless the application writes it into
the response itself. What the shape does move is the other way round, and it is the discarded answer
above: an unhandled exception could not pass unnoticed, and a discarded value can — in a build with
no analyser reading the mark, which is what the annotation narrows rather than closes.

The registration check does not replace the send-time one. The policy is configuration and can
change after rows were stored, so `send` assesses every send regardless and reports a refusal as the
`EndpointRejected` outcome — this library's own redaction of the endpoint beside the same `reason`
the policy wrote — where a fan-out flags or removes the row and carries on.

Across two services — one registering, one sending, each with its own context — what the bean
guarantees is one *interpretation*: both build their policy from the same two properties through
the same code, so the rules can differ only where the configured values differ. Keeping those
values in step between the services is configuration delivery, the same problem a deployment
already solves for every other setting they share.

### What fails at startup, and from where

Expressing the allowlist **and** supplying a bean fails the context, naming whichever property is
non-empty and naming the bean — they express the same security control, and silently preferring
one would leave the other believed-active but ignored. This refusal is a startup check of the
context, **whether or not the deployment sends**: in a registration-only service the application
bean would otherwise suppress the starter's policy while the stated allowlist was ignored without
a word. Which bean is the starter's own is decided by where its definition came from, never by its
name — an application bean that happens to be named `push2uEndpointPolicy` is an application bean,
and a non-empty allowlist property beside it still fails the context.

A malformed entry fails the context named exactly — the property it came from and its index in
that property's list, `push2u.allowed-origins[2]`, since the starter builds each rule itself from
one entry of one named property. It, too, fails **whether or not the deployment sends**, from a
startup check that runs ahead of the property-beside-a-bean contradiction above and ahead of every
bean-creation failure — so of the allowlist's own complaints, the value to fix is the message that
arrives; only the activation switch's own value outranks it. The entry appears in the
message the way an endpoint appears in a rejection: an origin entry with its path and query
stripped, because a pasted capability URL is precisely the mistake being reported, and a domain
entry verbatim only when it is a plain host-shaped token.

Expressing **neither** — both properties unset, no bean — fails only a context that builds the
autoconfigured sender, with a message naming the three ways to fix it: the obligation is the
sender's, and a deployment that does not send is owed no demand for an allowlist it has no use
for.

Emptying every property that *is* set, with no bean, is the same silence said differently and fails
the same context — the per-property escape hatch below cedes an emptied key to a bean or to its
sibling property, and here there is neither to receive it. Its message names both keys rather than
one: the emptiness is a fact about the pair. These two are one pair of refusals, not two unrelated
ones, and neither of them fails a deployment that does not send.

One more refusal completes the list: a non-empty allowlist property in a context that has
**excluded** the auto-configuration publishing the policy bean fails when the autoconfigured
sender is built, naming the non-empty property and `Push2uEndpointPolicyAutoConfiguration`. The
sender does not rebuild the policy from the properties — the allowlist is one definition, and a
second construction inside the sender would be a second place the same rule is stated.

**Those last three are the sender's own** — nothing expressed, everything emptied, and an allowlist
with no auto-configuration left to turn it into a bean — and a service that only registers
subscriptions meets none of them, because all three fail where the sender is built and it builds no
sender. Which is awkward, since that service is the one holding the policy for a living. What it
gets instead, the moment it injects the bean and the bean is not there, is those same three states
as an analysis of the unsatisfied dependency, from the text the refusals are written in rather than
a copy of it, so what a registration-only service reads and what a sending one is refused with
cannot come apart. It arrives with one answer more than the refusals carry, because an injection
failure has one they do not: stop requiring the bean, through an `ObjectProvider<EndpointPolicy>` or
a component that is itself conditional.

**Excluding an auto-configuration removes its contribution, and the checks are placed so that this
stays true.** The two value refusals above are hosted in `Push2uStartupChecksAutoConfiguration`,
apart from the bean they guard, because a check riding in the bean's own class would vanish with
the bean the moment an operator excluded it — silencing exactly the refusal they were owed. So
excluding `Push2uEndpointPolicyAutoConfiguration` removes only the bean, and both checks keep
running. Excluding `Push2uStartupChecksAutoConfiguration` is the one deliberate way to switch the
checks off — visible in the exclusion line that names them — and what it leaves reachable is
stated here rather than left to be discovered: with the checks excluded, a non-empty allowlist
beside an application bean boots, the bean in force and the properties read by nothing, in sending
contexts as well as registration-only ones; a malformed entry is then refused only where the
policy bean is actually built, as that bean's creation failure, and in a context that builds no
policy bean it goes unreported — which for a senderless context is exactly the behaviour that
predates the bean, when nothing outside the sender read these properties at all. That exclusion now
also takes the two refusals from
[Does this deployment send?](#does-this-deployment-send) with it — the value of `push2u.enabled`,
and the general refusal over a missing signer — since all of them are hosted there. An application
that requires a `PushSender` from such a context still gets an explanation rather than the
framework's generic one: the missing-bean failure is analysed, and what it says depends on which of
the three causes applies — the deployment stated `false` and something still requires a sender,
the checks were excluded, or the question is simply unanswered.

One escape hatch, and it is per property: a service that *inherits* `push2u.allowed-origins` from
a shared configuration it does not own cannot unset the property, so setting it to an explicitly
**empty** value means "deliberately not using this property here" — beside a bean, the bean wins;
beside the other property, that property carries the allowlist alone. Where neither is there to
receive it, what is left is the refusal above over an allowlist emptied to nothing — a
sender-building context, both keys named, no single entry left to refuse on its own terms.

**Empty means empty, and a blank is not one.** Where the value arrives as one delimited string —
an environment variable, `PUSH2U_ALLOWED_ORIGINS=`, is the case this hatch exists for — only a
zero-length value is no entries at all. A single space is one entry; a lone comma is two, one either
side of it. None of them is a name, but the property now *expresses* an allowlist, which is the
opposite of what was meant by typing it. Wherever the blank lands, it is refused as the malformed
entry it is, by property and index — `push2u.allowed-origins[0]`, an entry that shows nothing of
itself but still has a position — and that refusal outranks the property-beside-a-bean
contradiction and every bean-creation failure, so the message points at the blank rather than at a
bean that was configured on purpose. Only the activation switch's own value outranks it.

### No property turns the restriction off

There is deliberately no `push2u.*` flag for unrestricted egress. Sending anywhere is a legitimate
choice where subscriptions never arrive from untrusted clients, but under Spring it is expressed as
a bean:

```java
@Bean
EndpointPolicy endpointPolicy() {
    // Subscriptions here are entered by operators, never registered by clients.
    return EndpointPolicies.unrestricted();
}
```

A YAML flag reaches production by copying a dev profile; a bean is a code change that passes a
review. A property could be added later without breaking anyone, and could not be removed after a
release — so the asymmetry decides it.

`push2u.allowed-domains` is not a hole in that. What the refusal is about is a *mode*: a flag whose
danger is that it removes the control and travels between profiles as one copied line. A domain list
is data — every value it can hold is a restriction, and there is no value of it that turns the
restriction off. The asymmetry above still argues, as it always does, that withholding a property is
the cheap default, and what overrides it here is the pressure withholding puts on a Spring
deployment serving the two services that publish a zone rather than a host — Safari's and Edge's, a
major browser's users each. A bean is exclusive with the properties, so reaching for one to express
those two zones costs every ordinary origin its place in YAML too: what is left is a `@Bean`
carrying the hostnames *and* the matching rules, or one of two bad answers the starter can otherwise
give — `EndpointPolicies.unrestricted()`, which is unrestricted egress, or an origins-only
allowlist, which can express neither zone.

That second answer is the quieter failure, and it is quiet in two different ways. Edge's endpoints
sit on varying subdomains, so an origins-only allowlist refuses them now: the subscription is
registered and then refused at every send for the rest of its life, and the application sees an
`EndpointRejected` outcome per send and nothing else, since the core has no logger of its own — a
value it may well be discarding, which makes this quieter still. Safari's sit on one host today, so
naming that host works — until Apple uses the rest of the zone its own documentation reserves, and
those subscriptions then fail the same way. Neither is unsafe and neither fails a startup, so there
is nothing in a review to notice; the feature simply stops working for those users. The property
exists so that the safe answer is reachable by the route operators already use.

## Health indicator

When Spring Boot health support is present, the starter also registers a health indicator, under the
contributor name `push2u`, that exercises the configured signer: it signs a probe input and verifies
the result against that signer's own advertised public key. Its two keys are Spring Boot's own,
`management.health.push2u.enabled` and `management.health.push2u.cache-ttl`, and not `push2u.*` —
earlier versions spelled them `push2u.health.enabled` and `push2u.health.cache-ttl`, and a leftover
one of those is now ignored in silence rather than reported, so delete it by hand.

`push2u.enabled: false` removes the indicator too, and its own key cannot bring it back: the switch
sits upstream of it, so a deployment that has turned delivery off has no probe left to opt out of.
**A health group naming `push2u` is edited in the same change** — the framework validates group
membership and refuses a context naming a contributor that does not exist, in a message naming
neither the switch nor anything else done to push2u.

[`HEALTH.md`](HEALTH.md) is the reference — what the probe asserts about the signer and what it
deliberately does not, the two keys with their cache, what became of the `push2u.health.*` keys
they replaced now that the refusal over those has been retired, when the indicator is registered and
when it is not, and the health-group routes that keep a signer's backend out of a
container health check.

## Two identities during a key rotation

Replacing the VAPID pair is a migration that runs two identities side by side until the
subscriptions created under the old one are gone —
[`VAPID-KEY-ROTATION.md`](VAPID-KEY-ROTATION.md) is the runbook, and all of it applies here. What
this starter adds is that it autoconfigures **one** signer and **one** sender, and both of the
conditions it does that under work against a second identity added to a properties-configured
context.

**A second `VapidSigner` bean does not join the starter's — it replaces it.** The signer beans of
both starters are conditional on *no* `VapidSigner` bean being present, and that condition asks
whether a bean of the type exists, not whether it is the one they would have built. So a deployment
that keeps `push2u.vapid.*` (or `push2u.signer.vault.*`) for the old identity and declares a bean
for the new one ends up with the new one alone: the properties stop contributing, silently, and the
old cohort is left with no signer at all — the one failure this migration exists to avoid, arriving
through the framework rather than through a rotation. **Both identities are application beans for
the duration**, with the properties that used to name one of them removed.

**Two `VapidSigner` beans then need one marked `@Primary`.** Two injection points take a single
`VapidSigner` by type: the autoconfigured `PushSender`, and the health indicator when Spring Boot
health support is present. Declaring both `PushSender`s yourself removes the first — an application
`PushSender` bean makes the starter's back off, and that is what you want anyway, since a sender the
starter built would be signing with whichever bean won the injection. The indicator stays, so mark
one signer primary; without it the context fails to start with an unsatisfied-dependency error
naming both beans.

**The indicator then probes that one signer.** `UP` says the primary identity can sign and says
nothing about the other, so during a migration a green probe is not evidence that both senders are
alive. If both matter to this deployment's health, that is the application's own contributor to add.

**And `@Primary` makes one thing wrong that is otherwise the obvious thing to do: do not label a
subscription by reading the injected `VapidSigner`.** It answers with the primary regardless of
which key the browser being registered was actually handed, so every subscription created against
the other identity is recorded under the wrong one — and because the retirement gate counts the same
labels, those rows are invisible to it right up to the moment the old identity stops signing. The
label comes from `subscription.options.applicationServerKey`, reported by the client and checked
against the keys you serve, and from nothing on the server that says which generation is current.
[`VAPID-KEY-ROTATION.md`](VAPID-KEY-ROTATION.md#the-migration-step-by-step) has the whole of it,
including what the check can and cannot establish.

**Everything except the signer is shared.** The contact address and the endpoint policy belong to
the deployment rather than to an identity, so both senders take the same `EndpointPolicy` bean — the
one [the allowlist properties publish](#the-policy-is-a-bean) — and the same `mailto:` contact. Only
the `VapidSigner` differs between them, which is also why the routing that picks between the two
senders is the application's and not a property.
