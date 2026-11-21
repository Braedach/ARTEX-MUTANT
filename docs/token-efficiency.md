# Token efficiency: analysis and design

Status: implemented (see the changelog). This document records what was measured, why, and what was
changed, so the next person does not have to rediscover it.

## What was wrong

A two-task run on the production stack (3 Nov 2026, `claude-sonnet-5`, 37 model calls in under three
minutes, no findings) used **1,007,257 input tokens**, and **none of them were cached** (cache read and
cache write were 0 on every row of the `llm_usage` ledger):

| Role | Calls | Input tokens | Average per call |
|---|---|---|---|
| worker (ok) | 21 | 643,888 | 30,661 |
| planner | 6 | 242,908 | 40,485 |
| worker (cancelled when the owner paused the task) | 4 | 65,671 | 16,418 |
| goals | 6 | 54,790 | 9,132 |

Almost none of that is the work itself. It is the same fixed prefix sent again on every call: the tool
definitions (about 80% of it: 29 tools for a worker, 42 for the planner) plus the system prompt, then the
conversation so far. The task content is a few hundred tokens.

### Root cause

Anthropic's Messages API caches only what the client marks. The SDK marks the system prompt (a marker on
the system block also covers the tool definitions before it), but only when the request carries a
`DynamicBoundary`. `agent/deferred.go` set that boundary **only when global MCP "deferred tools" existed**:

```go
if block == "" {
    return []string{sysText}, 0   // boundary 0: no cache marker, ever
}
```

A stack with no enabled MCP server (the normal case) therefore never sent a single cache marker. The same
line is in the upstream project (`jiwoochris/artex-global`, checked 21 Nov 2026), and its issue tracker has
no report about it. It costs money only on the Anthropic wire format; OpenAI-style providers cache a stable
prefix automatically, so most of the upstream user base never saw it.

### Two smaller findings

- The 4 "error" calls in the table above were requests in flight when the tasks were paused (the server
  log shows `#1 paused` in the same second). Not a bug.
- The dashboard's default "Old" token view sums per-task activity and under-counted against the ledger
  ("New"): 547.8k against 1,007k for this run. The ledger meters every call, including cancelled and failed
  ones, so it is the authoritative figure.

## What changed

1. **Prompt caching is on by default and covers every provider** (`agent/deferred.go`,
   `agent/promptcache.go`).
   - The whole system prompt is always cacheable, with or without MCP tools.
   - **Anthropic wire format:** a second, moving breakpoint goes on the last block of the conversation, so
     each turn reads the previous turn's prefix from the cache instead of paying for it again. It is added
     in the HTTP transport (the SDK has no hook for it). One-shot calls (one message) are left alone,
     because nothing would ever re-read them; breakpoints never exceed Anthropic's limit of four.
   - **OpenAI Chat Completions, OpenAI Responses and OpenAI-compatible gateways** (DeepSeek, Gemini's
     OpenAI endpoint, vLLM, ...): caching is automatic and keyed on an identical prefix, so the work is to
     keep the prefix byte-stable. `prefix_stability_test.go` pins that: the tool list and the default
     system prompts must be identical from call to call (no clock, no per-call data in them).
   - **A gateway that speaks the Anthropic format but rejects `cache_control`** must not break. If a
     request that carried markers comes back 400/422 and the error mentions `cache_control`, the transport
     retries once without any markers and remembers the host. The cost of being wrong is one extra round
     trip, once per host per process. An unrelated 400 is passed through untouched and never retried.
   - **Switches:** Settings -> Cost controls -> Prompt caching, or `ARTEX_PROMPT_CACHE=off` in the
     environment (the environment wins, so it cannot be re-enabled by accident from the UI). Turning it off
     strips every marker, including the SDK's own.
2. **Per-task token budget** (`server/tokenbudget.go`). A task that has used more than its budget is paused,
   with a line in the server log, and stays paused until the budget is raised and the task resumed. Caching
   makes each turn cheaper but does not limit how many turns an agent loop takes, so this is the backstop.
   The budget counts **cost-weighted** input-token units (`db.WeightedTokens`): uncached input 1, cache
   read 0.1, cache write 1.25, output 5. That way a task that uses caching is not charged as though it did
   not. Default 25,000,000 units per task; 0 means unlimited. Settings -> Cost controls.
3. **The dashboard shows the ledger by default** ("New"), so the number on screen is the number of calls that
   were actually made.

## What did not change, and why

- **Tool sets per agent.** The planner carries 42 tools including file-editing and shell tools although its
  prompt says it only plans. But the planner prompt names `Bash`, `Write`, `WebFetch` and `TodoWrite`, so
  removing them would change behaviour, not just cost. With caching on, the weight of those tools is paid
  once per run instead of once per call. Trimming them is a separate, behaviour-visible change that should
  be made with a test scan in hand.
- **The SDK's own context compaction** (200K window by default) is untouched.

## Expected effect, and how to check it

On the run above, with caching working, the fixed prefix (about 30k tokens per worker call) is read from
the cache after the first call of each run. Anthropic bills cache reads at a tenth of the input rate, so
input spend for runs of this shape should fall by roughly 70-80%. That is an estimate from the pricing
ratios, **not a measurement**: the first real scan after deploying is the measurement. Look at
Dashboard -> LLM token consumption: **Cache hit rate** should be well above zero from the second call of any
run, and `cache_read` in `llm_usage` should dominate `input_tokens`. If it is still 0%:

- the provider or gateway does not support caching (check the server log for `rejected prompt-cache
  markers`), or
- `ARTEX_PROMPT_CACHE=off` is set, or
- the model is below the provider's minimum cacheable prompt (1,024 tokens for most Claude models; the
  smallest ones need 2,048).

Note that `input_tokens` in the ledger still **includes** cached tokens (every provider is normalised to
that convention), so the total does not fall by itself; the cached share is what is cheap. This is why the
budget uses weighted units.

## A caution about custom prompts

A custom agent prompt that uses `{{.Now}}` renders the time to the second into the system prompt, which
changes every call and defeats the cache (and pays the cache-write premium every time). Use a date, not a
timestamp, or put the time in the user message.
