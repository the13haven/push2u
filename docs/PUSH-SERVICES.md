# Browser push services

Which endpoints a deployment may POST to is a decision the deployment makes: push2u requires an
`EndpointPolicy` on every `PushSender` and ships no allowlist of its own —
[`README.md` → Endpoint policy (SSRF hardening)](../README.md#endpoint-policy-ssrf-hardening) has
the threat model behind that. This page is where the decision starts: the services the standard
browsers subscribe against, in the two spellings an operator pastes into their own configuration.
Copying them there is the point. In your configuration these names appear in your diff, and a change
to them is a change somebody reviews.

It is a snapshot and not a registry. The authority for every name below is the service operator's
own current documentation, linked beside it — not this page. Two of those links stop short of the
whole claim their row makes, and *Where the vendor page stops short* says which and how far.

## The four services

| Browser family | Push service | Allowlist entry | Kind | Vendor documentation |
|---|---|---|---|---|
| Chrome, and Chromium browsers other than Edge (Opera, Brave, Vivaldi, Samsung Internet, Yandex Browser) | Firebase Cloud Messaging | `https://fcm.googleapis.com` | origin | [Configure your Network for FCM](https://firebase.google.com/docs/cloud-messaging/network-configuration) |
| Firefox | Mozilla autopush | `https://updates.push.services.mozilla.com` | origin | [autopush](https://mozilla-services.github.io/autopush-rs/) |
| Safari on macOS, iOS and iPadOS | Apple Push Notification service | `push.apple.com` | domain | [Web Push for Web Apps on iOS and iPadOS](https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/), [Sending web push notifications in web apps and browsers](https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers) |
| Edge | Windows Notification Service (WNS) | `notify.windows.com` | domain | [Firewall allowlist configuration](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/firewall-allowlist-config), [WNS overview](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/wns-overview) |

Two fixed hosts and two zones, and that split is why an allowlist entry carries its kind. FCM and
Mozilla's autopush issue endpoints on one host each, so an origin entry — matched exactly, scheme
and host and port together — says everything there is to say about them. Apple and Microsoft publish
a zone instead, and both publish it in the role this page needs: as what a sending server should be
allowed to reach.

Apple, in WebKit's announcement of Web Push on iOS and iPadOS:

> Just be sure to allow URLs from `*.push.apple.com` if you are in control of your server push
> endpoints.

The same wildcard appears in Apple's APNs documentation, under *Prepare your server to send push
notifications*: "If your network infrastructure limits which URLs your server can access, allow
access for `https://*.push.apple.com`."

Microsoft, on the page about adding WNS traffic to a firewall allowlist, gives the server-to-WNS
direction as an FQDN filter and says why it is the one to use:

> ```xml
> <CloudServiceDNS>
> <DNS FQDN="*.notify.windows.com"/>
> </CloudServiceDNS>
> ```
>
> We strongly suggest that you allow list by FQDN, because these will not change.

The WNS overview says why the entry has to be a zone rather than a host, in the other direction —
validation rather than egress:

> It is important that the cloud service always ensures that the channel URI uses the domain
> "notify.windows.com". The service should never push notifications to a channel on any other
> domain. […] The subdomain of the channel URI is subject to change and should not be considered
> when validating the channel URI.

The subdomains are visibly in use: that page's own example posts to `cloud.notify.windows.com` and
sends it as the `Host:` header, while a
[report of a failing Edge endpoint](https://github.com/MicrosoftEdge/DevTools/issues/262) names
`wns2-ln2p.notify.windows.com`.

### Neither entry is the vendor's wildcard exactly

Both vendors write a wildcard — `*.push.apple.com`, `*.notify.windows.com` — and this library has no
wildcard to write back. `EndpointRule.domain("push.apple.com")` covers the zone apex as well as every
subdomain, so it is one host **wider** than the wildcard: it also admits `push.apple.com` itself,
which is inside the same zone the operator has just decided to trust and lets no third party in. The
alternative, an origin rule naming one host, is much **narrower** than the wildcard: it admits one
name out of a zone the vendor has told you to allow as a whole, and it stops working the day the
service moves hosts — which is the event both wildcards exist to survive. Neither error runs in the
direction of admitting a stranger; they run in opposite directions from what the vendor wrote, and
an operator choosing between them should know which is which.

A domain entry covers the apex and every subdomain at any depth, matched at a label boundary — so
`notify.windows.com` admits `cloud.notify.windows.com` and refuses `evilnotify.windows.com` — and
only over `https` on the default port. A deployment that needs a non-default port,
`https://push.internal.example:8443`, names it exactly with an origin entry, because a port is a
statement about which service on a host is trusted rather than about which names are.

A domain entry is worth exactly what the DNS of that zone is worth, and it permits every tenant of
that zone — on a shared hosting zone, that is every customer of the host. push2u makes no
public-suffix judgement and cannot tell a service's own zone from a registry's. So a domain entry
belongs where the service operator publishes the zone rather than the host: either by documenting
that its hostnames vary within it, as Microsoft does, or by naming the zone as what your server
should be allowed to reach, as Apple does. Anything else is an origin entry, including a self-hosted
or intra-organisation push service that happens to answer on one host.

## Is your browser in this list?

The four rows cover the browsers that implement the Push API, and the reason they do is that most
browsers do not run a push service of their own.

- **Samsung Internet** and **Yandex Browser** deliver through Google's service and are covered by
  the FCM row. Yandex documents this itself — [Yandex Cloud, browser
  notifications](https://github.com/yandex-cloud/docs/blob/master/en/notifications/concepts/browser.md)
  names only FCM and APNs as the delivery servers, and its quickstart's canonical example endpoint
  is `https://fcm.googleapis.com/fcm/send/…`.
- **Opera, Brave and Vivaldi** are Chromium browsers on FCM, as the first row says.
- **Opera Mini, Baidu Browser and the old Android Browser** do not implement the Push API at all, so
  there is nothing for them to allow.
- **Huawei Browser** could not be established either way: Huawei's Push Kit is documented as a
  native-app SDK, and no Web Push host for it appears anywhere. It is left out rather than guessed
  at.

That the list is complete is the harder claim, and it rests on negative evidence worth showing
rather than asserting. Three unrelated production systems ship the same four services and no
vendor-specific host beyond them: [pushpad/known-push-services](https://github.com/pushpad/known-push-services),
a push provider's allowlist built from roughly 200 million observed subscriptions and last updated
2026-06-01, and independently phpBB and Basecamp's Fizzy. That is third-party observation and not
anybody's documentation — it is evidence that nothing else is out there being subscribed to, which
is a different and weaker thing than a vendor telling you so.

### One host you may still hold

`android.googleapis.com` is the pre-VAPID GCM endpoint. Chrome 51 and earlier, Opera for Android and
Samsung Internet issued subscriptions there under `gcm_sender_id`, and it appears in all three
allowlists named above. No current browser issues one — but a stored subscription outlives the
browser version that created it, so a subscription table old enough may still hold endpoints on that
host, and they will be refused with nothing to explain why.

This is a fact about old data rather than about a browser anyone is serving today, which is why it
is not a row and is not in the configuration below. Whether your own table is old enough to need it
is yours to determine; add it only if it is, and not on the strength of this note.

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

## Where the vendor page stops short

Every row's link is meant to be what you check this page against. Two of them carry the host but not
the last step to *Web Push*, and that step is this page's own, so it is named here rather than left
to be discovered.

**Google's page is about sending to FCM, not about Web Push subscriptions.** [Configure your Network
for FCM](https://firebase.google.com/docs/cloud-messaging/network-configuration) is first-party,
current and addressed to the sending server — it names `fcm.googleapis.com` as a host your network
must reach over https, alongside `accounts.google.com` and `iid.googleapis.com` — and it closes with
the same warning this page ends on, in Google's words: "This list is subject to change over time. We
are unable to provide an ip based allowlist for these end points." What it does not say is that
Chrome's **Web Push subscription endpoints** sit on that host. That hop is carried by a Chrome for
Developers post, [Web Push Interoperability
Wins](https://developer.chrome.com/blog/web-push-interop-wins) — "if the origin is
`fcm.googleapis.com`, it's working" — which is dated 2016 and promises nothing about the future.
Your own subscriptions are the current evidence for it.

**Microsoft's pages never mention Edge or Web Push.** Both document WNS for Windows apps, so a reader
following either link to confirm that Edge's Web Push endpoints are WNS channel URIs will not find
that stated. The quotations above are Microsoft's instructions about channel URIs and about
allowlisting the WNS zone; the hop from "Edge Web Push endpoint" to "WNS channel URI" is observed
from Edge subscriptions. Nor does anything here establish that Edge routes through WNS on every
platform — whether Edge on macOS and Android uses WNS or FCM was not determined, and it changes
nothing about the allowlist, since both hosts are in the table either way.

## Why the library ships none of this

A default allowlist would be push2u asserting, on your deployment's behalf, that a third party's DNS
is trustworthy — and for a zone rather than a host, that assertion covers everything the zone's owner
ever points at it. It would also widen every existing deployment silently on upgrade: a name added
here would reach production through a version bump, which is the one change nobody reads as a change
to their egress rules.

And an allowlist that is mostly right is worse than none, because it hides that the question was
never asked. It goes stale as a service adds a datacentre or moves a host, and when it does it fails
quietly — per subscription, for the life of that subscription. Shipped inside the library, that
staleness is ours to notice and yours to suffer. Written into your configuration, it is in front of
you.

## This page goes out of date

These names are what the vendors published when this page was last touched, and nothing in push2u
verifies them. Any of them can change between releases of the library, and the library will not
notice — Google says as much about its own list. Re-read the linked pages before a deployment that
has to be right, and check the two hops named above against your own subscriptions. Keeping the
names here rather than in the code is what leaves you, rather than us, in a position to see it
happen.
