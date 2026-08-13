# ADR-007 — Expired subscription is a result

**Status:** Accepted; one clause superseded by [ADR-021](0021-retry-belongs-to-the-caller.md)

A push service answering `404` or `410` is reporting an ordinary, expected fact: the subscription
is gone and the application should delete it. Callers doing exactly that in a loop over stored
subscriptions would otherwise have to drive their normal path through a `catch` block.

`404` and `410` therefore map to `PushResult.Status.SUBSCRIPTION_EXPIRED`, a value the caller
inspects, not an exception. Exceptions stay for what they are for — a transport failure
(`PushDeliveryException`), a cryptographic failure (`PushCryptoException`), an endpoint the
deployment's policy refuses (`EndpointRejectedException`).

The cost is that a caller who ignores the result silently keeps a dead subscription, which is why
the type makes the state visible (`isSubscriptionExpired()`) rather than hiding it behind a
boolean success flag.
