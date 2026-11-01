package db

import "testing"

// chainTail returns VerifyAuditChain's current Checked count and OK state,
// as a baseline to diff against - the chain is shared process/DB-wide and
// never empty after the first test that ever ran against this database, so
// tests assert on deltas rather than absolute state.
func chainTail(t *testing.T, d *DB) ChainVerifyResult {
	t.Helper()
	r, err := d.VerifyAuditChain()
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !r.OK {
		t.Fatalf("chain already broken before this test ran (broken_id=%d) - a previous test corrupted it", r.BrokenID)
	}
	return r
}

// TestAuditChainExtendsOnDecidedIntercept verifies that CreateDecidedIntercept
// (the allow/deny logging path, including the new default-allow entries from
// guard.go) extends the chain by exactly one verifiable link per call, and
// that the chain still verifies afterward.
func TestAuditChainExtendsOnDecidedIntercept(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	before := chainTail(t, d)
	id1, err := d.CreateDecidedIntercept(0, 0, "chain-test-task", "agent-a", "Bash", []byte(`{"command":"ls"}`), "allowed", "no intercept rule matched and no LLM judge verdict was available; allowed by default")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := d.CreateDecidedIntercept(0, 0, "chain-test-task", "agent-a", "Bash", []byte(`{"command":"rm -rf /"}`), "denied", "rule hit")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = id1, id2

	after := chainTail(t, d)
	if after.Checked != before.Checked+2 {
		t.Fatalf("Checked = %d, want %d (+2 links)", after.Checked, before.Checked+2)
	}
}

// TestAuditChainExtendsOnResolveIntercept verifies the HandleAsk/Decide path
// (CreateInterceptPending -> ResolveIntercept) chains exactly once when the
// settle race is won, and not at all for a losing (no-op) resolve attempt.
func TestAuditChainExtendsOnResolveIntercept(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	id, err := d.CreateInterceptPending(0, 0, "chain-test-task", "agent-b", "WebFetch", []byte(`{"url":"http://example.com"}`), "please confirm")
	if err != nil {
		t.Fatal(err)
	}

	before := chainTail(t, d)
	resolved, err := d.ResolveIntercept(id, "allowed", "allow", "manual approval")
	if err != nil {
		t.Fatal(err)
	}
	if !resolved {
		t.Fatal("expected ResolveIntercept to win the settle race")
	}
	afterFirst := chainTail(t, d)
	if afterFirst.Checked != before.Checked+1 {
		t.Fatalf("Checked = %d, want %d (+1 link)", afterFirst.Checked, before.Checked+1)
	}

	// A second resolve of the same already-decided row must be a no-op: no
	// second link for the same decision.
	resolvedAgain, err := d.ResolveIntercept(id, "denied", "deny", "late timeout")
	if err != nil {
		t.Fatal(err)
	}
	if resolvedAgain {
		t.Fatal("expected the second resolve to lose the settle race")
	}
	afterSecond := chainTail(t, d)
	if afterSecond.Checked != afterFirst.Checked {
		t.Fatalf("Checked = %d, want %d (a lost settle race must not chain)", afterSecond.Checked, afterFirst.Checked)
	}
}

// TestAuditChainImmutableAgainstOrdinaryWrites verifies the database-level
// trigger rejects an ordinary UPDATE or DELETE against audit_chain_log
// outright - the first layer of tamper evidence, before VerifyAuditChain
// (the detection layer) ever needs to run.
func TestAuditChainImmutableAgainstOrdinaryWrites(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	if err := d.AppendAuditChain(ChainLink{ToolName: "Bash", Status: "allowed", Reason: "immutability probe"}); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := d.QueryRow(`SELECT id FROM audit_chain_log ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	if _, err := d.Exec(`UPDATE audit_chain_log SET reason='tampered' WHERE id=$1`, id); err == nil {
		t.Fatal("expected UPDATE on audit_chain_log to be rejected")
	}
	if _, err := d.Exec(`DELETE FROM audit_chain_log WHERE id=$1`, id); err == nil {
		t.Fatal("expected DELETE on audit_chain_log to be rejected")
	}
}

// TestVerifyAuditChainDetectsTamperingPastTheTrigger simulates an attacker
// who can also disable the immutability trigger (e.g. a superuser, or a
// migration run with elevated privilege) and shows VerifyAuditChain still
// catches the resulting mismatch - the second, independent layer of tamper
// evidence that doesn't rely on the trigger holding.
func TestVerifyAuditChainDetectsTamperingPastTheTrigger(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	if err := d.AppendAuditChain(ChainLink{ToolName: "Bash", Status: "allowed", Reason: "tamper-detection probe"}); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := d.QueryRow(`SELECT id FROM audit_chain_log ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	if _, err := d.Exec(`ALTER TABLE audit_chain_log DISABLE TRIGGER trg_audit_chain_log_immutable`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`ALTER TABLE audit_chain_log ENABLE TRIGGER trg_audit_chain_log_immutable`)
	})

	before := chainTail(t, d)
	if before.BrokenID != 0 {
		t.Fatalf("chain already broken before this test's own tamper (broken_id=%d)", before.BrokenID)
	}

	if _, err := d.Exec(`UPDATE audit_chain_log SET reason='tampered after the fact' WHERE id=$1`, id); err != nil {
		t.Fatalf("direct update (trigger disabled) failed: %v", err)
	}

	after, err := d.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if after.OK {
		t.Fatal("expected VerifyAuditChain to detect the tampered row")
	}
	if after.BrokenID != id {
		t.Fatalf("BrokenID = %d, want %d", after.BrokenID, id)
	}

	// Restore the row's true content (recomputing would require knowing the
	// prior prev_hash context, which this test already has from before()'s
	// perspective being OK) so later tests in this process don't inherit a
	// permanently broken chain from this one.
	if _, err := d.Exec(`UPDATE audit_chain_log SET reason='tamper-detection probe' WHERE id=$1`, id); err != nil {
		t.Fatalf("restoring tampered row failed: %v", err)
	}
	restored, err := d.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if !restored.OK {
		t.Fatalf("expected chain to verify again after restoring the row, broken_id=%d", restored.BrokenID)
	}
}
