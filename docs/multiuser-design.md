# Multi-user accounts and roles: design

Status: PHASE 1 IMPLEMENTED (accounts, roles, enforcement, UI); phases 2-4 designed only. See "As built" at the end. Written 2026-11-21 after reading `server/auth.go`, `server/session.go` and
SpiderFoot's RBAC module (`spiderfoot/auth/rbac.py`). Decisions confirmed by the owner on 2026-11-21 are marked
**[decided]**.

## Today

- One shared admin password (`settings.auth.password_hash`, bcrypt). No user accounts.
- Login issues a 7-day JWT with no identity or role. `requireAuth` only checks the token is valid, so every
  logged-in person is a full admin.
- That is risky here because the agents have shell and file tools, chat, LLM keys, MCP servers and captured
  traffic. Anyone logged in can, in effect, run commands through the agent.

## Roles **[decided: four roles, cumulative]**

| Role | Adds | Cannot |
|---|---|---|
| `viewer` | Read tasks, findings, reports, dashboard, usage. Raw captured traffic is redacted (it holds live cookies and tokens). | Change anything. |
| `analyst` | Triage findings (status, comments, retest requests), export reports, view raw evidence. | Run or stop tasks, chat with agents. |
| `operator` | Create, start, pause and stop tasks; chat with agents; manage own tasks and their files. | Change settings, secrets, scope policy, or users. Create a task whose targets fall outside the admin allowlist. |
| `admin` | Users, API tokens, LLM profiles and keys, MCP servers, settings, token budget, target allowlist (scope/egress policy), audit log. | Remove or demote the last admin. |

`operator` is the dangerous role: it means running tools. It is bounded by the admin-owned target allowlist
([egress-scope-guard-design.md](egress-scope-guard-design.md)), not by trust in the task text.

**Visibility [decided]:** every user sees every task. Ownership (`created_by`) is recorded from day one so
per-company access can be added later without a data migration.

## Permissions and enforcement

- Permissions are `resource:action` strings (same shape as SpiderFoot): `task:read`, `task:create`,
  `task:run`, `task:delete`, `finding:read`, `finding:triage`, `evidence:read_raw`, `report:export`,
  `chat:use`, `llm:read`, `llm:write`, `mcp:write`, `settings:write`, `scope:write`, `user:manage`,
  `token:manage`, `audit:read`, and so on. Each role is a set; higher roles include the lower ones.
- **One route table**: every `mux.HandleFunc("METHOD /api/...")` is mapped to a required permission. The
  middleware reads `r.Pattern`, looks it up, and **denies by default** when there is no entry.
- **CI guard**: a test walks the registered routes and fails if any lacks an entry, so a new endpoint cannot
  ship unprotected. Streaming endpoints (SSE and any WebSocket) go through the same table.
- The server is the authority. `/api/auth/session` returns the user's role and permission list so the UI can
  hide controls, but hiding is cosmetic.
- Secrets: LLM keys, MCP env, notification credentials and proxy URLs are never returned to anyone once saved,
  not even admins (write-only, show "set"). This pairs with [secrets-at-rest-design.md](secrets-at-rest-design.md).

## Data model (additive migration)

```sql
CREATE TABLE users (
  id              bigserial PRIMARY KEY,
  username        text NOT NULL UNIQUE,         -- case-insensitive via lower() index
  display_name    text NOT NULL DEFAULT '',
  email           text NOT NULL DEFAULT '',
  password_hash   text NOT NULL,                -- bcrypt, same as today
  role            text NOT NULL CHECK (role IN ('viewer','analyst','operator','admin')),
  disabled        boolean NOT NULL DEFAULT false,
  must_change_pw  boolean NOT NULL DEFAULT false,
  token_version   integer NOT NULL DEFAULT 1,   -- bump to invalidate every session of this user
  failed_logins   integer NOT NULL DEFAULT 0,
  locked_until    timestamptz,
  last_login_at   timestamptz,
  totp_secret     bytea,                        -- phase 3, encrypted; NULL = not enrolled
  created_by      bigint REFERENCES users(id),
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_tokens (                       -- phase 2
  id          bigserial PRIMARY KEY,
  user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        text NOT NULL,
  prefix      text NOT NULL,                    -- first 8 chars, for display and lookup
  token_hash  bytea NOT NULL,                   -- sha256 of the token; the token is shown once
  expires_at  timestamptz,
  last_used_at timestamptz,
  revoked_at  timestamptz
);

ALTER TABLE tasks ADD COLUMN created_by bigint REFERENCES users(id);
ALTER TABLE findings ADD COLUMN updated_by bigint REFERENCES users(id);
```

Audit: every state-changing request appends to the existing hash-chained `audit_chain_log` with the user id,
role, route, and target object. Login success, failure, lockout, role change, token create/revoke are logged.

## Sessions

- The JWT carries `sub` (user id), `ver` (token_version) and `iat`. The server loads the user (cached for a
  few seconds) and rejects the token if the user is disabled, locked, or `ver` no longer matches. Disabling a
  user or changing a role therefore takes effect immediately, not after 7 days.
- Lifetime: 12 hours idle, 7 days absolute (down from 7 days flat). Cookie flags unchanged (HttpOnly,
  SameSite, Secure behind HTTPS). The CSRF guard already exempts bearer clients.
- Password change and admin reset bump `token_version`.
- Login limiter: the existing `authLimiter` keyed per username and per IP, with lockout after repeated failures
  and a uniform error so usernames are not enumerable.
- Password policy: minimum 12 characters for new accounts (8 stays valid for the migrated admin until its next
  change), bcrypt 72-byte limit enforced as today.

## Guard rails

- The last enabled admin cannot be deleted, disabled or demoted.
- Nobody can change their own role; an admin cannot demote themselves if they are the last admin.
- Admin password reset sets a temporary password with `must_change_pw`; the user cannot do anything else until
  it is changed.
- Users are disabled, not deleted, by default so audit and `created_by` references stay meaningful.

## Service account for the assistant **[decided]**

A user `claude` with role `operator`, plus an API token (phase 2): hashed at rest, expiry, last-used time,
revocable in one click, **never admin**. It can start, monitor and stop tasks inside the admin allowlist. If it
needs a target added or a setting changed it asks the owner. Tokens go in `Authorization: Bearer`; they are
rejected on the user-management and token-management routes regardless of role.

## Migration

- On first start of the new version, if `auth.password_hash` exists and `users` is empty, create user `admin`
  (role `admin`, that hash) and mark the legacy key consumed. Existing JWTs are invalid: everyone logs in once.
- `ARTEX_ADMIN_PASSWORD` and the `/setup` flow keep working for fresh installs and create the first admin.
- Schema changes are additive, so rolling back to the previous image is safe (it ignores the new tables and
  keeps using the old password row, which we leave in place).

## Phases (separate PRs)

1. **Accounts and enforcement.** `users`, login by username, role and permission table, deny-by-default
   middleware, route-coverage test, user management page, attributed audit, `created_by`, redaction of raw
   evidence for `viewer`.
2. **API tokens** and the `claude` service account.
3. **Designed, ready, not in use [decided]:** TOTP two-factor (RFC 6238, secret encrypted, recovery codes,
   per-user enrolment, admin can require it for roles) and per-company access scoping on top of
   `created_by`. Ship the schema and code paths behind off-by-default settings.
4. **Designed, ready, not in use [decided]:** OIDC single sign-on (authorization-code with PKCE, group or
   claim to role mapping, local login kept as break-glass for admin). Off by default.

## Tests

- Table-driven matrix: for each role and each route, expect allow or 403; the route set comes from the real
  mux so it cannot drift.
- Disabled user, bumped `token_version`, expired token, wrong-role token and last-admin guards.
- Migration: legacy password becomes `admin`; second start is idempotent.
- Viewer never receives raw cookies or `Authorization` values in any response body.
- Bearer tokens refused on `/api/users*` and `/api/tokens*`.
- Frontend: role-based rendering, the user-management page, and the forced password change screen.

## Open points (none blocking phase 1)

- Whether `analyst` may use chat in read-only mode (proposal: no).
- Exact redaction rules for `viewer` on traffic and logs (proposal: header values and bodies replaced, URL and
  status shown).
- Per-user rate limits on chat and task creation (token budget already caps spend per task).

## As built (phase 1) and deviations from the design above

- **Migrated admin keeps the name `ARTEX`**, not `admin`, so the sign-in everyone already uses keeps working.
  New installs created by the setup flow also get `ARTEX` unless a username is supplied.
- **Viewers are denied raw evidence instead of getting redacted copies.** Traffic, intercept history,
  workspace files and chat history need `analyst`. Redaction can come later without changing the roles.
- **Security log is a new table (`security_log`)**, not `audit_chain_log`: that table is the intercept
  approval hash chain and is not a general audit trail.
- **Passwords:** 12 characters minimum for everything set through the multi-user paths (create, reset, change).
  The first-run setup screen and `ARTEX_ADMIN_PASSWORD` keep their existing 8-character minimum.
- **Lockout:** 10 failed sign-ins lock the account for 15 minutes (in addition to the per-IP and per-username
  throttle).
- **Operator scope boundary is not enforced yet.** The design bounds operators by the admin-owned target
  allowlist, but the egress scope guard ([egress-scope-guard-design.md](egress-scope-guard-design.md)) is still
  a design. Until it is built an operator can describe any target in a task. Treat `operator` as trusted to run
  tools; give `analyst` to people who should only review.
- **Not in phase 1:** API tokens and the `claude` service account (phase 2), TOTP and per-company access
  (phase 3), OIDC (phase 4). `tasks.created_by` is recorded now; the UI does not show it yet.
- **Known gap:** `GET /api/llm/profiles` (operator and up) returns each profile's proxy URL, which can carry
  credentials. Admin-only masking is a follow-up.
