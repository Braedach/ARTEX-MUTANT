# Secrets at rest: design proposal

Status: PROPOSAL (not implemented). Written 2026-11-19 after reading how `BaaRai/ARTEX` encrypts credential
columns (`db/secrets.go`) and checking this codebase: nothing here encrypts anything (no `crypto/aes` or AEAD
use outside TLS). A change that rewrites stored credentials needs the owner present, so this is a design, not a patch.

## The gap

These values are plain text in PostgreSQL today:

| Where | What it holds |
|---|---|
| `llm_profiles.api_key`, `llm_profiles.proxy` | LLM provider keys; the proxy URL can carry `user:pass@` |
| `mcp_servers.env` (JSONB) | environment for MCP subprocesses, typically tokens |
| `notification_channels.config` (JSONB) | webhook URLs, Telegram bot tokens, SMTP passwords |
| `tools.exec` (JSONB, user-created rows) | custom-tool headers, proxy, body, command: often API keys |
| `settings` rows `brave_search_api_key`, `tavily_search_api_key`, `web_search_proxy`, `global_proxy` | search keys, proxy credentials |
| `traffic_evidence_snapshots.req_head` / `resp_head` | captured request and response heads: `Cookie` and `Authorization` of the targets |

Who this matters against: a leaked `pg_dump` or backup, a read-only SQL injection, another database user, a
mis-shared volume. It does not help against code execution as the server's own user (that process holds the key);
for that, see the path guard for the key file.

## Proposed design (informed by BaaRai's, implemented fresh)

- **Cipher:** AES-256-GCM, random 12-byte nonce per value, authenticated data `"<table>.<column>"` (`"settings.<key>"`
  for settings), so a ciphertext cannot be moved to another column. TEXT stores `enc:v1:<base64(nonce||ct)>`; JSONB
  stores `{"__artex_enc":"enc:v1:..."}` over the canonical JSON. Empty values stay empty.
- **Key:** `ARTEX_SECRET_KEY` (32 bytes, base64 or hex), else `<keyDir>/secret.key` (0600, generated on first start,
  never auto-generated if encrypted data already exists, so a lost key is not silently replaced).
- **Failure mode:** a value that fails to decrypt is an error, never returned as-is.
- **Migration:** an idempotent startup backfill under the schema advisory lock; each `UPDATE` matches the value it
  read, so a concurrent write is never overwritten; sealed values are skipped. Plaintext rows keep working until
  the backfill runs.
- **Scope of code change:** one `db/secrets.go`, and every read/write of the columns above goes through
  `sealSecret` / `openSecret` (a short, finite list).

## Things that must be decided or done first

1. **Key backup is the whole risk.** Lose the key and every stored credential is gone. The key must be backed up
   somewhere other than the database backup (otherwise the encryption buys nothing), and the restore procedure
   documented. Proposal: key in the homelab credential store, and a restore drill before turning it on.
2. **Rollback.** Take a `pg_dump` immediately before the first backfill, and ship a `--decrypt-all` maintenance
   command so the change can be reversed without the dump.
3. **The key file is a new platform secret.** It must be added to the path guard's protected list (`pathguard`)
   in the same change, or the agent's file tools could read it.
4. **Task archives and exports.** An archive moved to another instance would carry ciphertext that instance cannot
   open. Decide: export decrypted-and-redacted (credentials dropped), or ciphertext plus a documented requirement.
   Proposal: drop credentials from archives, which is safer.
5. **Evidence heads.** Encrypting `req_head`/`resp_head` breaks any SQL that searches them. Check the evidence code
   paths (verbatim-quote checks) before including them; they may need a separate plaintext-safe field.
6. **Where the key lives in the container deployment** (`deploy/stack-podman.yml`, `stack-docker.yml`): an env var
   in the stack is visible to `podman inspect`; a mounted file is better. Proposal: a mounted file, 0600.

## Not proposed

- Encrypting the whole database, or the recorded traffic bodies (different threat, different tooling).
- A key-management service. One local key is proportionate for a single-host deployment.
