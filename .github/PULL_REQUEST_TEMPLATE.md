<!--
  This PR template is for ARTEX-MUTANT, a security-hardened derivative of
  Braedach/ARTEX (itself based on jiwoochris/artex-global). Read CONTRIBUTING.md
  first.
-->

## Summary

<!-- One or two sentences: what changed, and why. -->

## Type of change

<!-- Mark whichever applies with an x. -->

- [ ] Bug fix (`fix`)
- [ ] Feature (`feat`)
- [ ] Docs (`docs`)
- [ ] Refactor / cleanup (`refactor` / `chore`)
- [ ] Other:

## Related issue

<!-- e.g. Closes #123 -->

## How this was verified

<!-- Which commands you actually ran, and what they confirmed. Paste output if useful. -->

- [ ] Go changes: `go build ./...` · `go vet ./...` · `go test ./...` pass (including the go-db jobs, against real Postgres)
- [ ] web changes: `npm run check` · `npm run build` pass
- [ ] UI changes: screenshot attached

## Agent-prompt integrity

- [ ] This change does **not** alter the agent's internal reasoning prompts (the behavioural-instruction body, `agent/promptcatalog.go` / `agent_prompts`) without a deliberate, documented reason — they were benchmarked as-is, and an undocumented edit risks a silent performance regression.

## Scope confirmation

- [ ] This change does not encourage use beyond the [authorized-use notice](../README.md#️-read-first--authorized-use-and-legal-notice) or applicable law. Any verification was done only against owned/authorized targets or in a locally isolated environment.
- [ ] No test or scan output is included in the commit.
