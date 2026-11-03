package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
)

// containsCJK reports whether s contains any CJK Han ideograph or Hangul
// syllable - either would mean a translation reverted or a new string was
// added without translating it.
func containsCJK(s string) (rune, bool) {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) || (r >= 0xAC00 && r <= 0xD7A3) {
			return r, true
		}
	}
	return 0, false
}

func sampleFindingNode(t *testing.T) *db.Node {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"vulnclass": "SQL Injection",
		"name":      "SQL injection in the login form",
		"severity":  "high",
		"summary":   "Error-based SQL injection was confirmed in the login parameter.",
		"evidence":  map[string]string{"poc": "' OR '1'='1"},
	})
	if err != nil {
		t.Fatalf("payload marshal failed: %v", err)
	}
	return &db.Node{ID: 1, Kind: "finding", Payload: payload}
}

func sampleDBFinding() *db.DBFinding {
	return &db.DBFinding{
		ID:              123,
		VulnClass:       "SQL Injection",
		Name:            "SQL injection in the login form",
		Severity:        "high",
		Summary:         "Error-based SQL injection was confirmed in the login parameter.",
		Evidence:        "' OR '1'='1",
		Status:          "confirmed",
		Report:          "Detailed analysis body.",
		CreatedAt:       time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC),
		EvidenceVersion: 2,
		TaskDescription: "Demo target penetration test",
		TrafficBindings: []db.FindingTrafficBinding{
			{
				ID:   9,
				Role: "request",
				Note: "Where the injection payload was sent",
				Snapshot: db.TrafficEvidenceSnapshot{
					Method: "POST",
					URL:    "https://sandbox.local/login",
					Status: 200,
				},
			},
		},
	}
}

// TestReportMarkdownLocalized verifies the exploration-graph report
// (report.Markdown) skeleton is in English, with no leftover CJK text.
func TestReportMarkdownLocalized(t *testing.T) {
	out := Markdown(Input{
		Title:       "Demo task",
		Goal:        "Full sandbox sweep",
		GeneratedAt: time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC),
		AssetCounts: map[string]int{"host": 2, "url": 5},
		Findings:    []*db.Node{sampleFindingNode(t)},
	})
	if r, ok := containsCJK(out); ok {
		t.Fatalf("report skeleton still has CJK character %q:\n%s", string(r), out)
	}
	for _, want := range []string{
		"# Penetration Test Report: Demo task",
		"- **Task goal**: Full sandbox sweep",
		"- **Generated at**:",
		"## Summary",
		"- Confirmed vulnerabilities: **1**",
		"## Findings",
		"**PoC / Evidence:**",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report skeleton is missing %q", want)
		}
	}
}

// TestReportMarkdownEmptyLocalized verifies the no-findings placeholder text is in English.
func TestReportMarkdownEmptyLocalized(t *testing.T) {
	out := Markdown(Input{Title: "Empty task", GeneratedAt: time.Now()})
	if r, ok := containsCJK(out); ok {
		t.Fatalf("empty report still has CJK character %q:\n%s", string(r), out)
	}
	if !strings.Contains(out, "_No vulnerabilities were confirmed this time._") {
		t.Errorf("empty-report placeholder text is not English:\n%s", out)
	}
}

// TestFindingsMarkdownLocalized verifies the findings summary/detail
// Markdown export skeleton and severity labels are in English, with no
// leftover CJK text.
func TestFindingsMarkdownLocalized(t *testing.T) {
	f := sampleDBFinding()
	out := FindingsMarkdown([]*db.DBFinding{f}, time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC))
	if r, ok := containsCJK(out); ok {
		t.Fatalf("findings summary report still has CJK character %q:\n%s", string(r), out)
	}
	for _, want := range []string{
		"# Vulnerability Summary Report",
		"- **Generated at**:",
		"- **Total vulnerabilities**: 1",
		"## Summary",
		"| Severity | Count |",
		"| Critical |", "| High |", "| Medium |", "| Low |", // severity labels (same as the UI's status.severity)
		"## Vulnerability Details",
		"- **Class**: SQL Injection",
		"- **Status**: confirmed",
		"- **Task**: Demo target penetration test",
		"- **Found at**:",
		"**Evidence:**",
		"**Detailed report:**",
		"## Related Traffic Evidence",
		"Evidence version: 2, binding count: 1.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary report is missing %q", want)
		}
	}

	single := SingleFindingMarkdown(f, time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC))
	if r, ok := containsCJK(single); ok {
		t.Fatalf("single-finding report still has CJK character %q:\n%s", string(r), single)
	}
	for _, want := range []string{
		"- **Severity**: high",
		"## Overview",
		"## Evidence",
		"## Detailed Report",
		"[Request](evidence/123/9/request.http)",
		"[Response](evidence/123/9/response.http)",
	} {
		if !strings.Contains(single, want) {
			t.Errorf("single-finding report is missing %q", want)
		}
	}
}

// TestFindingsCSVLocalized verifies the CSV export header is in English,
// with no leftover CJK text. (Only the header row after the BOM needs to be
// English - data values are left as-is.)
func TestFindingsCSVLocalized(t *testing.T) {
	raw := FindingsCSV([]*db.DBFinding{sampleDBFinding()})
	out := strings.TrimPrefix(string(raw), "\xEF\xBB\xBF")
	header := strings.SplitN(out, "\n", 2)[0]
	if r, ok := containsCJK(header); ok {
		t.Fatalf("CSV header still has CJK character %q: %s", string(r), header)
	}
	for _, col := range []string{"ID", "Name", "Class", "Severity", "Status", "Task", "Found At", "Summary", "Traffic Evidence Count", "Traffic Evidence IDs"} {
		if !strings.Contains(header, col) {
			t.Errorf("CSV header is missing column %q: %s", col, header)
		}
	}
}
