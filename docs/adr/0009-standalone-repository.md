# ADR-009 — Standalone repository

**Status:** Accepted

A library maintained inside an application's repository acquires that application's build
conventions, its dependency versions and its release cadence — none of which a consumer of the
library should inherit, and all of which are invisible until someone outside tries to use it.

push2u is therefore an independent Gradle multi-project build with its own release cycle, carrying
no application-specific dependency, configuration or assumption. Anything that would only make
sense for one deployment — a datastore, a scheduler, a tenancy model — belongs to the application
(ADR-004).
