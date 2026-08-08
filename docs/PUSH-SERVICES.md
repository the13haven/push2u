# Browser push services

Which endpoints a deployment may POST to is a decision the deployment makes: push2u requires an
`EndpointPolicy` on every `PushSender` and ships no allowlist of its own —
[`README.md` → Endpoint policy (SSRF hardening)](../README.md#endpoint-policy-ssrf-hardening) has
the threat model behind that. This page is where the decision starts: the services the standard
browsers subscribe against, in the two spellings an operator pastes into their own configuration.
Copying them there is the point. In your configuration these names appear in your diff, and a change
to them is a change somebody reviews.

It is a snapshot and not a registry. The authority for every name below is the service operator's
own current documentation, linked beside it — not this page. Two of the four links do not fully
carry that, and *Two of these links are weaker* below says which and why.

## The four services

| Browser family | Push service | Allowlist entry | Kind | Vendor documentation |
|---|---|---|---|---|
| Chrome, and Chromium browsers other than Edge (Opera, Brave, Vivaldi) | Firebase Cloud Messaging | `https://fcm.googleapis.com` | origin | [Web Push Interoperability Wins](https://developer.chrome.com/blog/web-push-interop-wins) — but see *Two of these links are weaker* below |
| Firefox | Mozilla autopush | `https://updates.push.services.mozilla.com` | origin | [autopush](https://mozilla-services.github.io/autopush-rs/) |
| Safari on macOS, iOS and iPadOS | Apple Push Notification service | `push.apple.com` | domain | [Sending web push notifications in web apps and browsers](https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers) |
| Edge | Windows Notification Service (WNS) | `notify.windows.com` | domain | [WNS overview](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/wns-overview) — but see *Two of these links are weaker* below |

Two fixed hosts and two zones, and that split is why an allowlist entry carries its kind. FCM and
Mozilla's autopush issue endpoints on one host each, so an origin entry — matched exactly, scheme
and host and port together — says everything there is to say about them. Apple and Microsoft publish
a zone instead, and both publish it in the same role: as the thing an application server should be
allowed to reach.

Apple, under *Prepare your server to send push notifications*:

> If your network infrastructure limits which URLs your server can access, allow access for
> `https://*.push.apple.com`. Your service should maintain TLS encrypted connections to APNs.

Microsoft, in the WNS overview:

> The subdomain of the channel URI is subject to change and should not be considered when validating
> the channel URI.

Microsoft's subdomains are visibly in use — that page's own example posts to
`cloud.notify.windows.com` and sends it as the `Host:` header, while a
[report of a failing Edge endpoint](https://github.com/MicrosoftEdge/DevTools/issues/262) names
`wns2-ln2p.notify.windows.com`.

`EndpointRule.domain("push.apple.com")` is the right spelling for Apple's instruction but not the
literal one: Apple writes `https://*.push.apple.com`, a wildcard over subdomains, while this
library's domain entry covers the zone apex as well as every subdomain, so it admits one host more
than the wildcard does — `push.apple.com` itself. That host is inside the same Apple zone the
operator has just decided to trust and lets no third party in, but a reader who follows the link
will find a wildcard where this page writes a bare name, so it is said here rather than left to be
noticed. An operator who wants exactly Apple's wording writes the origin
`https://web.push.apple.com`, which is where every Safari web push endpoint observed today sits, and
accepts that it breaks if Apple moves hosts. Enumerating subdomains is not a third option in either
zone: the list is right until the service adds a host, and then those subscriptions are refused one
send at a time, with nothing failing at startup to say so.

A domain entry therefore covers the apex and every subdomain at any depth, matched at a label
boundary — so `notify.windows.com` admits `cloud.notify.windows.com` and refuses
`evilnotify.windows.com` — and only over `https` on the default port.

### Two of these links are weaker

Every row's link is meant to be the thing you check this page against, so the two that cannot quite
carry that are named here rather than left to be discovered.

**Google publishes no egress instruction for the FCM host.** Apple's and Microsoft's sentences above
exist to tell an application server what to allow; Google's documentation has no counterpart, and
`fcm.googleapis.com` appears in it mainly as the host of the FCM server APIs, which is a different
role that happens to share a name. The linked page is a 2016 Chrome for Developers blog post, which
does name the origin a subscription arrives on and makes no promise about the future. Treat the
entry as an observation about the endpoints your own subscriptions carry, and verify it against
those.

**Microsoft's page never mentions Edge or Web Push.** It documents WNS for Windows apps, so a reader
following the link to confirm that Edge's Web Push endpoints are WNS channel URIs will not find that
mapping stated there. The quotation above is Microsoft's instruction about channel URIs; the hop
from "Edge Web Push endpoint" to "WNS channel URI" is observed from Edge subscriptions, not
documented on that page.

## The configuration

In plain Java, one list holding both kinds:

```java
EndpointPolicy pushServices = EndpointPolicies.allowedEndpoints(
    EndpointRule.origin("https://fcm.googleapis.com"),                // Chrome and Chromium
    EndpointRule.origin("https://updates.push.services.mozilla.com"), // Firefox
    EndpointRule.domain("push.apple.com"),                            // Safari, through APNs
    EndpointRule.domain("notify.windows.com"));                       // Edge, through WNS

PushSender sender = PushSender.builder(keys, "mailto:ops@example.com", pushServices).build();
```

Under the Spring Boot starter, the same allowlist across the two properties — they are two halves
of one statement and are unioned, not alternatives
([`SPRING.md` → Endpoint policy](SPRING.md#endpoint-policy)):

```yaml
push2u:
  allowed-origins:
    - "https://fcm.googleapis.com"                 # Chrome and Chromium
    - "https://updates.push.services.mozilla.com"  # Firefox
  allowed-domains:
    - "push.apple.com"                             # Safari, through APNs
    - "notify.windows.com"                         # Edge, through WNS
```

Take out what your users do not arrive on. An entry you do not need is egress you granted for
nothing, and the allowlist is worth exactly what is left out of it.

## Why the library ships none of this

A default allowlist would be push2u asserting, on your deployment's behalf, that a third party's DNS
is trustworthy — and for a zone rather than a host, that assertion covers everything the zone's owner
ever points at it. It would also widen every existing deployment silently on upgrade: a name added
here would reach production through a version bump, which is the one change nobody reads as a change
to their egress rules.

And an allowlist that is mostly right is worse than none, because it hides that the question was
never asked. It goes stale as a service adds a datacentre or moves a host, and when it does it fails
the way described above — quietly, per subscription, for the life of that subscription. Shipped
inside the library, that staleness is ours to notice and yours to suffer. Written into your
configuration, it is in front of you.

## This page goes out of date

These names are what the vendors published when this page was last touched, and nothing in push2u
verifies them. Any of them can change between releases of the library, and the library will not
notice; the vendor documentation in the table above is the authoritative answer for each service —
except in the two rows named above, where the strongest available answer is your own subscriptions
— and it is worth re-reading before a deployment that has to be right. Keeping the names here rather
than in the code is what leaves you, rather than us, in a position to see it happen.

## What a domain entry is worth

A domain entry is worth exactly what the DNS of that zone is worth, and it permits every tenant of
that zone — on a shared hosting zone, that is every customer of the host. push2u makes no
public-suffix judgement and cannot tell a service's own zone from a registry's.

So a domain entry belongs where the service operator *documents* that its hostnames vary within a
zone, which two of the four services above do and two do not. Everything else is an origin entry,
including a self-hosted or intra-organisation push service that happens to answer on one host. A
deployment that needs a non-default port — `https://push.internal.example:8443` — names it exactly
with an origin entry, because a port is a statement about which service on a host is trusted rather
than about which names are.
