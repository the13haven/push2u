# Browser push services

Which endpoints a deployment may POST to is a decision the deployment makes: push2u requires an
`EndpointPolicy` on every `PushSender` and ships no allowlist of its own —
[`README.md` → Endpoint policy (SSRF hardening)](../README.md#endpoint-policy-ssrf-hardening) has
the threat model behind that. This page is where the decision starts: the services the standard
browsers subscribe against, in the two spellings an operator pastes into their own configuration.
Copying them there is the point. In your configuration these names appear in your diff, and a change
to them is a change somebody reviews.

It is a snapshot and not a registry. The authority for every name below is the service operator's
own current documentation, linked beside it — not this page.

## The four services

| Browser family | Push service | Allowlist entry | Kind | Vendor documentation |
|---|---|---|---|---|
| Chrome and Chromium browsers (Opera, Brave, Vivaldi) | Firebase Cloud Messaging | `https://fcm.googleapis.com` | origin | [Firebase Cloud Messaging](https://firebase.google.com/docs/cloud-messaging) |
| Firefox | Mozilla autopush | `https://updates.push.services.mozilla.com` | origin | [autopush](https://mozilla-services.github.io/autopush-rs/) |
| Safari on macOS, iOS and iPadOS | Apple Push Notification service | `https://web.push.apple.com` | origin | [Sending web push notifications in web apps and browsers](https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers) |
| Edge | Windows Notification Service (WNS) | `notify.windows.com` | domain | [WNS overview](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/wns-overview) |

Three fixed hosts and one zone, and that asymmetry is why an allowlist entry carries its kind. The
first three services issue endpoints on one host each, so an origin entry — matched exactly, scheme
and host and port together — says everything there is to say about them. WNS does not: the subdomain
of a channel URI varies by datacentre (`cloud.notify.windows.com` and `wns2-ln2p.notify.windows.com`
are both real), and Microsoft's own documentation instructs the application server to check the
domain and, verbatim, "The subdomain of the channel URI is subject to change and should not be
considered when validating the channel URI". Enumerating the subdomains is not a substitute: the
list is right until WNS adds a datacentre, and then Edge subscriptions on the new one are refused
one send at a time, with nothing failing at startup to say so.

A domain entry therefore covers the apex and every subdomain at any depth, matched at a label
boundary — so `notify.windows.com` admits `cloud.notify.windows.com` and refuses
`evilnotify.windows.com` — and only over `https` on the default port.

## The configuration

In plain Java, one list holding both kinds:

```java
EndpointPolicy pushServices = EndpointPolicies.allowedEndpoints(
    EndpointRule.origin("https://fcm.googleapis.com"),                // Chrome and Chromium
    EndpointRule.origin("https://updates.push.services.mozilla.com"), // Firefox
    EndpointRule.origin("https://web.push.apple.com"),                // Safari
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
    - "https://web.push.apple.com"                 # Safari
  allowed-domains:
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
notice; the vendor documentation in the table above is the authoritative answer for each service, and
it is worth re-reading before a deployment that has to be right. Keeping the names here rather than
in the code is what leaves you, rather than us, in a position to see it happen.

## What a domain entry is worth

A domain entry is worth exactly what the DNS of that zone is worth, and it permits every tenant of
that zone — on a shared hosting zone, that is every customer of the host. push2u makes no
public-suffix judgement and cannot tell a service's own zone from a registry's.

So a domain entry belongs where the service operator *documents* that its hostnames vary within a
zone, which of the four services above is true only for WNS today. Everything else is an origin
entry, including a self-hosted or intra-organisation push service that happens to answer on one
host. A deployment that needs a non-default port — `https://push.internal.example:8443` — names it
exactly with an origin entry, because a port is a statement about which service on a host is trusted
rather than about which names are.
