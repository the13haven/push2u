# ADR-004 — Stateless library

**Status:** Accepted

Subscriptions belong to the application: it decides where they are stored, how they are keyed to
users, and when they are removed. A library that also stored them would have to know about a
datastore, a schema and a transaction boundary — none of which it can choose on the application's
behalf.

The library therefore holds no per-send state. It sends to a `Subscription` the caller supplies
and reports when the push service says that subscription is gone (ADR-007); persisting, deleting
and re-subscribing stay with the application.

`PushSender` holds only final configuration, which is what makes one instance shareable across
every sending thread.
