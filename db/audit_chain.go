package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"sync"
)

// This file implements the audit hash chain (schema.sql, audit_chain_log).
// ARTEX-MUTANT hardening, informed by reArtex's analysis: every tool-call
// decision that reaches a terminal status (allowed/denied/timeout) is
// recorded as an immutable link, hashed together with the link chained
// immediately before it, so that editing or deleting a link after the fact
// is detectable by VerifyAuditChain. The log is a separate table from
// intercept_pending, not extra columns on it - see schema.sql's own comment
// on audit_chain_log for why chaining over intercept_pending's own rows
// (which are legitimately deleted on task archival) would be wrong.

// chainGenesis is the fixed prev_hash of the first link ever appended.
const chainGenesis = "ARTEX-MUTANT-AUDIT-CHAIN-GENESIS"

// auditChainMu serializes every write that extends the chain: read the
// current tail hash, compute the next link, append it, as one critical
// section. This only protects correctness within ONE process - ARTEX runs
// as a single Go binary with one DB connection pool, so that is the actual
// deployment; if that ever changes (multiple server replicas writing the
// same database), this needs a DB-level serialization point (e.g. an
// advisory lock held for the same span) instead, or concurrent writers
// could read the same stale tail and the chain would fork.
var auditChainMu sync.Mutex

// digestBytes is this package's own input digest for chain links. It only
// needs to be internally consistent (same bytes in -> same digest, every
// time) - there is no requirement that it match the intercept package's own
// digestInput (which canonicalizes JSON before hashing); importing that
// package here would be circular (intercept already imports db).
func digestBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func chainHash(prevHash string, fields ...string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	for _, f := range fields {
		h.Write([]byte{0}) // separator: makes ("a","bc") hash differently from ("ab","c")
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ChainLink is one appended, immutable audit_chain_log row.
type ChainLink struct {
	ID             int64  `json:"id"`
	PendingID      int64  `json:"pending_id,omitempty"`
	TaskID         string `json:"task_id,omitempty"`
	AgentName      string `json:"agent_name"`
	ToolName       string `json:"tool_name"`
	InputDigest    string `json:"input_digest"`
	DecisionSource string `json:"decision_source"`
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	PrevHash       string `json:"prev_hash"`
	Hash           string `json:"hash"`
}

// appendAuditChain appends one link inside tx, so it commits atomically with
// whatever state transition the caller is making terminal. Caller must hold
// auditChainMu. pendingID == 0 is stored as NULL (no owning intercept_pending
// row - the ambient "no rule matched, no judge" default-allow path has one).
func appendAuditChain(tx *sql.Tx, l ChainLink) error {
	var tail sql.NullString
	err := tx.QueryRow(`SELECT hash FROM audit_chain_log ORDER BY id DESC LIMIT 1`).Scan(&tail)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	prev := chainGenesis
	if tail.Valid && tail.String != "" {
		prev = tail.String
	}
	hash := chainHash(prev, l.ToolName, l.Status, l.Reason, l.AgentName, l.TaskID, l.InputDigest, l.DecisionSource)

	var pendingIDPtr *int64
	if l.PendingID != 0 {
		pendingIDPtr = &l.PendingID
	}
	var taskIDPtr *string
	if l.TaskID != "" {
		taskIDPtr = &l.TaskID
	}
	_, err = tx.Exec(`INSERT INTO audit_chain_log
		(pending_id, task_id, agent_name, tool_name, input_digest, decision_source, status, reason, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		pendingIDPtr, taskIDPtr, l.AgentName, l.ToolName, l.InputDigest, l.DecisionSource, l.Status, l.Reason, prev, hash)
	return err
}

// AppendAuditChain appends one link in its own transaction. Use this from a
// call site that isn't already inside a transaction for another reason
// (CreateDecidedIntercept and ResolveIntercept append inline, inside their
// own transaction, instead).
func (d *DB) AppendAuditChain(l ChainLink) error {
	auditChainMu.Lock()
	defer auditChainMu.Unlock()

	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := appendAuditChain(tx, l); err != nil {
		return err
	}
	return tx.Commit()
}

// ChainVerifyResult is the outcome of VerifyAuditChain.
type ChainVerifyResult struct {
	OK       bool  `json:"ok"`
	Checked  int64 `json:"checked"`
	BrokenID int64 `json:"broken_id,omitempty"` // 0 when OK
}

// VerifyAuditChain walks every link in id order and recomputes each one from
// its own persisted columns, reporting the first link (if any) whose stored
// hash no longer matches what its content and position in the chain imply -
// i.e. a link was edited or deleted after being appended (deletion shows up
// as a gap: the next surviving link's prev_hash no longer matches).
func (d *DB) VerifyAuditChain() (ChainVerifyResult, error) {
	rows, err := d.Query(`SELECT id, prev_hash, hash, tool_name, status, reason, agent_name,
		COALESCE(task_id, ''), input_digest, decision_source
		FROM audit_chain_log ORDER BY id`)
	if err != nil {
		return ChainVerifyResult{}, err
	}
	defer rows.Close()

	prev := chainGenesis
	var checked int64
	for rows.Next() {
		var id int64
		var storedPrev, storedHash, toolName, status, reason, agent, task, digest, source string
		if err := rows.Scan(&id, &storedPrev, &storedHash, &toolName, &status, &reason, &agent, &task, &digest, &source); err != nil {
			return ChainVerifyResult{}, err
		}
		if storedPrev != prev {
			return ChainVerifyResult{OK: false, Checked: checked, BrokenID: id}, nil
		}
		want := chainHash(prev, toolName, status, reason, agent, task, digest, source)
		if want != storedHash {
			return ChainVerifyResult{OK: false, Checked: checked, BrokenID: id}, nil
		}
		prev = storedHash
		checked++
	}
	if err := rows.Err(); err != nil {
		return ChainVerifyResult{}, err
	}
	return ChainVerifyResult{OK: true, Checked: checked}, nil
}
