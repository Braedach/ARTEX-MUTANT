# Maintainer guide

This document replaces an earlier upstream-sync and translation-drift runbook that no longer applies:
ARTEX-MUTANT carries no localization, and it is **not** an upstream-tracking fork — see
[README.md's Origin and attribution section](README.md#origin-and-attribution) for why, and for the
full chain of repositories this is built on.

## What this repository is

A security-hardened derivative of [`Braedach/ARTEX`](https://github.com/Braedach/ARTEX), itself a
fork of [`jiwoochris/artex-global`](https://github.com/jiwoochris/artex-global). "Derivative," not
"fork" in the usual sense that implies staying mergeable with upstream: changes here are deliberately
not designed to be pushed back, and upstream changes are not pulled in automatically. Each hardening
fix is reviewed and tested individually against this codebase, informed in places by published
analysis of the same lineage (credited in the PR and commit that introduces it, and in README.md's
attribution section), never merged as foreign code.

## Bringing in a specific upstream or third-party fix

There is no scripted sync process, by design — the whole point of this repository is that nothing
lands without being understood first. To pull in one specific change:

1. Read the real diff in the source repository (`git diff` against the relevant commit, or the
   PR/commit on GitHub) — not just a changelog's description of it. A description can be wrong or
   describe a different codebase than this one; checked twice already this way (see this repo's own
   hardening commits for examples of findings that applied differently here than described
   elsewhere).
2. Confirm the issue actually exists in *this* codebase by reproducing it, not by assuming the
   description transfers across lineages.
3. Implement the fix as a fresh, reviewed patch against this source — with tests that would fail
   without it — rather than copying code. Different fork bases have diverged enough (file layout,
   adjacent features) that a literal patch rarely applies cleanly anyway.
4. Open a PR here, following the pull request template. Credit the source that identified or
   inspired the fix in the PR description.

## Release and build pipeline

Unchanged from `Braedach/ARTEX`'s own model (Design-Reference §24.3 in that homelab's private
infrastructure repository, not duplicated here): built on a dedicated build host from an explicit
tag (never a floating branch), published to `ghcr.io/braedach/artex-mutant`, deployed to a
dev/sandbox host before anything resembling production. A test build's tag contains `-rc` and never
moves `:latest`.

## CI

`.github/workflows/` runs on every push and PR: a Go build, `go vet`, the full test suite (including
`go-db` jobs against a real Postgres instance — some bugs, including one found hardening this very
repository, only surface there), a frontend build, and documentation link checks. All of it must
pass before merging.

## Agent-prompt integrity

The agent's own internal reasoning prompts (`agent/promptcatalog.go`, the DB-seeded `agent_prompts`)
are left exactly as upstream wrote them, in their original language, because the agent's judgment was
benchmarked against that exact text — translating or rewording it risks a silent performance
regression with no compile-time signal. This is the one piece of "foreign-language content" in this
repository that stays, deliberately, and the pull request template has a checklist item for it.
