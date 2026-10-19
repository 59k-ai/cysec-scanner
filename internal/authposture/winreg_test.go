// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// errWinregTestBaseline is the baseline openWinregSession error set by TestMain.
var errWinregTestBaseline = errors.New("winreg disabled in test baseline")

// TestMain installs a HERMETIC network baseline for the WHOLE authposture test
// binary. The un-editable full-Run tests (authposture_test.go) invoke the real
// readWinreg directly — it is NOT a top-level overridable seam like readWMI — so
// without this baseline the package would make real winreg dials to the fake test
// IPs (10.0.0.x, 10.1.0.x) and block on connection timeouts. The baseline makes
// openWinregSession fail immediately so the real readWinreg adds NO registry rows
// (configuration_checks stays []), keeping those tests both correct and fast.
// Per-test winreg tests below override this seam and defer a restore to baseline.
// (Task 2 extends this baseline with the probeSMB2 seam.)
func TestMain(m *testing.M) {
	openWinregSession = func(context.Context, string) (winregSession, error) {
		return nil, errWinregTestBaseline
	}
	os.Exit(m.Run())
}

// fakeWinregSession is an in-memory winregSession for Linux CI: it returns canned
// tri-state results keyed by the exact value name, defaulting any unspecified
// value to regAbsent. It never touches a real host.
type fakeWinregSession struct {
	results map[string]regResult
}

func (f *fakeWinregSession) queryDword(_ context.Context, _, value string) regResult {
	if r, ok := f.results[value]; ok {
		return r
	}
	return regResult{outcome: regAbsent}
}

func (f *fakeWinregSession) close() {}

// fakeWinregOpener returns an openWinregSession seam yielding the given canned
// results.
func fakeWinregOpener(results map[string]regResult) func(context.Context, string) (winregSession, error) {
	return func(context.Context, string) (winregSession, error) {
		return &fakeWinregSession{results: results}, nil
	}
}

// observedByCheckCode indexes a host's configuration_checks ObservedValue by
// check code for concise assertions.
func observedByCheckCode(hf hostFacts) map[string]string {
	out := make(map[string]string, len(hf.configChecks))
	for _, c := range hf.configChecks {
		out[c.CheckCode] = c.ObservedValue
	}
	return out
}

// winregAsset builds a minimal gated-Windows AssetItem carrying a dialable IP.
func winregAsset(externalID, ip string) payload.AssetItem {
	addr := ip
	return payload.AssetItem{ExternalID: externalID, IPAddress: &addr}
}

// TestReadWinregTriState proves the hard spike-settled tri-state contract: a
// present DWORD 1, a present DWORD 0, and an ABSENT value (ERROR_FILE_NOT_FOUND,
// 0x2) map to THREE DISTINCT ConfigurationCheckItem ObservedValues — a present 0
// ("0") is never conflated with an absent value ("absent"). An absent value is
// NEVER coerced to 0.
func TestReadWinregTriState(t *testing.T) {
	origOpen := openWinregSession
	defer func() { openWinregSession = origOpen }()

	openWinregSession = fakeWinregOpener(map[string]regResult{
		// server-signing REQUIRED present as DWORD 1
		"requiresecuritysignature": {outcome: regPresent, value: 1},
		// server-signing ENABLED present as DWORD 0 (present 0, NOT absent)
		"enablesecuritysignature": {outcome: regPresent, value: 0},
		// client-signing value ABSENT (0x2 / ERROR_FILE_NOT_FOUND)
		"RequireSecuritySignature": {outcome: regAbsent},
	})

	hf := readWinreg(context.Background(), winregAsset("ip:dc01", "10.9.9.9"),
		scanCredential{domainUser: "LAB\\scan", password: "pw"})

	obs := observedByCheckCode(hf)
	if got := obs["smb_signing:server_required"]; got != "1" {
		t.Errorf("present DWORD 1 observed %q, want \"1\"", got)
	}
	if got := obs["smb_signing:server_enabled"]; got != "0" {
		t.Errorf("present DWORD 0 observed %q, want \"0\" (present 0, not absent)", got)
	}
	if got := obs["smb_signing:client_required"]; got != observedAbsent {
		t.Errorf("absent value observed %q, want %q (0x2 is absent, never 0)", got, observedAbsent)
	}
	// The three outcomes must be mutually distinct.
	if obs["smb_signing:server_enabled"] == obs["smb_signing:client_required"] {
		t.Fatal("present 0 and absent collapsed to the same ObservedValue (tri-state violated)")
	}
}

// TestReadWinregReadsAllSixValues proves the full SMB-signing / Lsa value set is
// read and mapped (parity-locked, WINAD-05): one configuration_checks row per
// value, each carrying the allowed Status/Severity enum spellings.
func TestReadWinregReadsAllSixValues(t *testing.T) {
	origOpen := openWinregSession
	defer func() { openWinregSession = origOpen }()

	openWinregSession = fakeWinregOpener(map[string]regResult{
		"requiresecuritysignature": {outcome: regPresent, value: 1},
		"enablesecuritysignature":  {outcome: regPresent, value: 1},
		"RequireSecuritySignature": {outcome: regPresent, value: 1},
		"LmCompatibilityLevel":     {outcome: regPresent, value: 5},
		"RunAsPPL":                 {outcome: regPresent, value: 1},
		"RestrictAnonymous":        {outcome: regPresent, value: 1},
	})

	hf := readWinreg(context.Background(), winregAsset("ip:dc01", "10.9.9.9"),
		scanCredential{domainUser: "LAB\\scan", password: "pw"})

	obs := observedByCheckCode(hf)
	for _, code := range []string{
		"smb_signing:server_required", "smb_signing:server_enabled", "smb_signing:client_required",
		"lsa:lm_compatibility_level", "lsa:run_as_ppl", "lsa:restrict_anonymous",
	} {
		if _, ok := obs[code]; !ok {
			t.Errorf("missing configuration_checks row for %q", code)
		}
	}
	for _, c := range hf.configChecks {
		if !allowedCheckStatus[c.Status] {
			t.Errorf("row %q status %q not an allowed enum member", c.CheckCode, c.Status)
		}
		if !allowedSeverity[c.Severity] {
			t.Errorf("row %q severity %q not an allowed enum member", c.CheckCode, c.Severity)
		}
		if c.AssetExternalID != "ip:dc01" {
			t.Errorf("row %q asset id %q, want ip:dc01", c.CheckCode, c.AssetExternalID)
		}
	}
}

// TestReadWinregPerValueErrorNeverRaises proves never-raises at value granularity:
// one value's open/query error lands a per-check error note and observes "error",
// while every OTHER value still maps to its row.
func TestReadWinregPerValueErrorNeverRaises(t *testing.T) {
	origOpen := openWinregSession
	defer func() { openWinregSession = origOpen }()

	openWinregSession = fakeWinregOpener(map[string]regResult{
		"requiresecuritysignature": {outcome: regPresent, value: 1},
		"RunAsPPL":                 {outcome: regError, err: errors.New("open_key: AccessDenied")},
	})

	hf := readWinreg(context.Background(), winregAsset("ip:dc01", "10.9.9.9"),
		scanCredential{domainUser: "LAB\\scan", password: "pw"})

	obs := observedByCheckCode(hf)
	if got := obs["smb_signing:server_required"]; got != "1" {
		t.Errorf("sibling value did not map despite another value's error: observed %q", got)
	}
	if got := obs["lsa:run_as_ppl"]; got != observedError {
		t.Errorf("errored value observed %q, want %q", got, observedError)
	}
	if note := hf.notes[winregValueNoteKey("RunAsPPL")]; !strings.Contains(note, "AccessDenied") {
		t.Errorf("per-value error note missing/unexpected: %q", note)
	}
	// Every other value absent-defaults, so all six rows are present (never-raises).
	if len(hf.configChecks) < 6 {
		t.Errorf("configuration_checks rows = %d, want >= 6 (all values mapped)", len(hf.configChecks))
	}
}

// TestReadWinregSessionFailureNoteNoRows proves a whole-session dial failure is a
// per-check note and adds NO configuration_checks rows (the never-raises baseline
// the un-editable full-Run tests rely on).
func TestReadWinregSessionFailureNoteNoRows(t *testing.T) {
	origOpen := openWinregSession
	defer func() { openWinregSession = origOpen }()

	openWinregSession = func(context.Context, string) (winregSession, error) {
		return nil, errors.New("dial: i/o timeout")
	}

	hf := readWinreg(context.Background(), winregAsset("ip:dc01", "10.9.9.9"),
		scanCredential{domainUser: "LAB\\scan", password: "pw"})

	if len(hf.configChecks) != 0 {
		t.Errorf("configuration_checks rows = %d, want 0 on session failure", len(hf.configChecks))
	}
	if note := hf.notes[noteKeyWinreg]; !strings.Contains(note, "session") {
		t.Errorf("session-failure note missing/unexpected: %q", note)
	}
}
