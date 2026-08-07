# ADR-008 — Apache License 2.0

**Status:** Accepted

The project is licensed under the Apache License 2.0, for its explicit patent grant: a permissive
licence without one leaves an enterprise consumer's legal review with a question nobody in the
project can answer.

## The notice lives in every source file

`LICENSE` and the POM's `licenses` element already cover the distribution, so a per-file header is
not what makes the licence apply. It is what survives a single file being copied out of the
repository, and what per-file scanners (ScanCode, FOSSA, ORT) read — without it they classify the
file as `unknown licence`, which is friction for exactly the enterprise consumer this library
targets.

The form is the short SPDX identifier rather than the full boilerplate the licence's appendix
suggests: it is machine-readable, and it says the same thing far more briefly than repeating the
appendix in a hundred files.

```java
/*
 * Copyright <year> The 13 Haven
 *
 * SPDX-License-Identifier: Apache-2.0
 */
```

`LICENSE` itself keeps the appendix verbatim, placeholders and all: it is the canonical Apache
text, and the appendix is an instruction for applying the licence rather than a place to assert
ownership. Filling it in was the half-measure this decision replaces — the notice belongs in each
file, which is what the instruction asks for.

Every published jar additionally carries `META-INF/LICENSE`, so an artifact separated from its POM
still states its terms — the terms, not the copyright holder, since the canonical appendix names
nobody and compiled classes carry no comments. A scanner reading the binary jar alone therefore
sees Apache-2.0 without an owner; the owner is in the POM's `developer` entry and its
`organization`, in the source jar and in every source file, which is where it is useful.

## The year is the year of creation

A copyright year is evidence of authorship at a date, not a term that lapses, so a maintained
range would mean re-touching every file each January for no legal effect. The year a file is
created is the year it keeps, and the tree holds a spread of years on purpose.

## No NOTICE file

Apache-2.0 §4(d) obliges every redistributor of a derivative work to reproduce a `NOTICE` if one
exists. That is a real obligation to place on consumers in exchange for attribution the POM, the
source jar and every source file already carry.
