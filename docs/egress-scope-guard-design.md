# Egress scope guard: design proposal

Status: PROPOSAL (not implemented). Written 2026-11-19 after reviewing the SpiderFoot fork's scope guard
(`scope_policy.py`, built and validated there) and `wufufu770/reArtex`'s `netguard` / `scopepolicy` packages.

## The gap

ARTEX tasks are tied to a company whose scope is a list of rules (domain, IP, CIDR). Nothing enforces that scope
on the network. Scope compliance rests on the agent's own evidence and on its prompt. A prompt-injected or simply
mistaken agent that runs `curl`, `nmap` or `WebFetch` against a host outside the scope is not stopped, and
nothing independent records that it happened. This is the open item in the maintainer's security review
("scope compliance rests on the agent's own evidence, with no independent network capture").

## What the SpiderFoot guard teaches

1. **One policy, defined once, per target type**, read by every layer.
2. **Deny by default for anything that contacts a host**; only passive lookups and vendor APIs are exempt.
3. **Modes `off` / `log` / `enforce`, shipping in `log` first.** Decisions are recorded ("would block") and nothing
   extra is blocked, so intelligence cannot shrink while the policy is being validated against real traffic.
4. **Shared edges are not the target's.** A name that resolves into a CDN range must not authorise contact with the
   other tenants on that address.
5. **Visible:** a per-module / per-reason summary in the task log, with a first example for each reason.
6. **Validate by replay** against recorded real traffic before turning enforcement on.

## Where it fits in ARTEX

The recording proxy (`traffic`, go-mitmproxy) already sees every HTTP(S) request made by WebFetch and by Bash
tools that honour the proxy variables, and its addon interface has a per-request `Request` hook that can answer
instead of forwarding. That is an independent capture point the agent cannot talk its way around, which is
exactly what the review found missing.

Proposed shape:

- A `scopepolicy` package (pure Go, no I/O): `Decide(host) -> {allow, reason}` from a company's rules, with the
  host/URL parsing, IPv4-mapped IPv6 normalisation and registrable-domain comparison the SpiderFoot version uses.
- A proxy addon calling it per request, in `log` mode first: count and record would-block decisions per task, show
  them next to the task's traffic, and add a summary line to the task log.
- `enforce` only after a replay of the recorded traffic from real tasks shows what it would have refused.

## Decisions needed before building (owner)

1. **Attribution.** The proxy is shared, so a request cannot yet be tied to a task or company. Options: per-task
   proxy credentials (`http://task-<id>@proxy`, checked in the addon), or a header the worker adds. Recommendation:
   per-task proxy credentials; the proxy library already has the 407 path.
2. **Bash and non-proxy traffic.** Raw TCP tools (nmap, masscan) and anything ignoring proxy variables bypass the
   proxy. Options: accept it and document it, or add a network-namespace / nftables egress rule on the host.
   Recommendation: ship the proxy layer first, document the gap, treat the nftables layer as a second step.
3. **Chat sessions** have no company. Recommendation: no enforcement, log only.
4. **Internal ranges.** Internal networks are often the legitimate target in this lab; the policy must follow the
   company scope exactly and not add a blanket private-range rule.

## Not proposed

- A hard-coded block of link-local / cloud-metadata addresses (the reArtex `netguard` does this at dial time).
  Useful on a cloud host, little value on this deployment; revisit if it ever runs in a cloud.
- Anything that changes the agent's prompts.
