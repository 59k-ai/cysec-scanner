// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
)

// errWinregTestBaseline is the baseline openWinregSession error set by TestMain.
var errWinregTestBaseline = errors.New("winreg disabled in test baseline")

// TestMain installs a HERMETIC network baseline for the WHOLE authposture test
// binary. The un-editable full-Run tests (authposture_test.go) invoke the real
// readWinreg directly — it is NOT a top-level overridable seam like readWMI — so
// without this baseline the package would make real winreg dials to the fake test
// IPs (10.0.0.x, 10.1.0.x) and block on connection timeouts. The baseline makes
// openWinregSession fail immediately (and probeSMB2 return an empty not-ok result)
// so the real readWinreg adds NO registry rows and NO effective-signing row
// (configuration_checks stays []), keeping those tests both correct and fast.
// Per-test winreg tests below override these seams and defer a restore to baseline.
func TestMain(m *testing.M) {
	openWinregSession = func(context.Context, string) (winregSession, error) {
		return nil, errWinregTestBaseline
	}
	probeSMB2 = func(context.Context, string) smb2SigningProbe { return smb2SigningProbe{} }
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

// --- Task 2: live SMB2 negotiate probe + registry/probe combiner ---

// fakeNegotiateResponse builds a well-formed SMB2 NEGOTIATE response message
// (header + body, transport stripped) advertising the given server SecurityMode,
// for the bounded-parser test.
func fakeNegotiateResponse(secMode uint16) []byte {
	msg := make([]byte, smb2HeaderLen+8)
	msg[0], msg[1], msg[2], msg[3] = 0xFE, 'S', 'M', 'B'
	// Command at header offset 12 is NEGOTIATE (0) — already zero.
	binary.LittleEndian.PutUint16(msg[smb2HeaderLen:], 65)        // body StructureSize
	binary.LittleEndian.PutUint16(msg[smb2HeaderLen+2:], secMode) // body SecurityMode
	return msg
}

// probeConst returns a probeSMB2 seam yielding a fixed result.
func probeConst(p smb2SigningProbe) smb2ProbeFunc {
	return func(context.Context, string) smb2SigningProbe { return p }
}

// TestSMB2NegotiateParseBounded proves the strictly bounded negotiate parser:
// a well-formed response yields the advertised signing flags, and any
// malformed / truncated / non-negotiate input collapses to an empty (ok=false)
// result with no over-read or panic.
func TestSMB2NegotiateParseBounded(t *testing.T) {
	t.Parallel()

	if got := parseNegotiateResponse(fakeNegotiateResponse(smb2SigningEnabled | smb2SigningRequired)); !got.ok || !got.signingRequired || !got.signingEnabled {
		t.Errorf("signing-required response parsed as %+v, want ok+enabled+required", got)
	}
	if got := parseNegotiateResponse(fakeNegotiateResponse(smb2SigningEnabled)); !got.ok || got.signingRequired || !got.signingEnabled {
		t.Errorf("signing-enabled-only response parsed as %+v, want ok+enabled, not required", got)
	}
	// Truncated response (shorter than header + SecurityMode offset) -> empty.
	if got := parseNegotiateResponse([]byte{0xFE, 'S', 'M', 'B', 0x00, 0x00}); got.ok {
		t.Errorf("truncated response parsed ok=%v, want collapsed to empty", got.ok)
	}
	// Wrong protocol magic -> empty.
	bad := fakeNegotiateResponse(smb2SigningRequired)
	bad[0] = 0x00
	if got := parseNegotiateResponse(bad); got.ok {
		t.Errorf("bad-magic response parsed ok=%v, want collapsed to empty", got.ok)
	}
	// Empty / nil input -> empty, no panic.
	if got := parseNegotiateResponse(nil); got.ok {
		t.Errorf("nil input parsed ok=%v, want empty", got.ok)
	}
}

// TestEffectiveSigningNoFalseNegative is the core WINAD-02 guarantee: a registry
// server-signing value that is ABSENT (Win11 24H2+ default) combined with a live
// SMB2 negotiate probe reporting signing-required resolves the effective verdict
// to "required" — the registry-only false-negative is avoided.
func TestEffectiveSigningNoFalseNegative(t *testing.T) {
	origOpen := openWinregSession
	origProbe := probeSMB2
	defer func() { openWinregSession = origOpen; probeSMB2 = origProbe }()

	openWinregSession = fakeWinregOpener(map[string]regResult{
		"requiresecuritysignature": {outcome: regAbsent}, // absent-by-default modern client
	})
	probeSMB2 = probeConst(smb2SigningProbe{ok: true, signingEnabled: true, signingRequired: true})

	hf := readWinreg(context.Background(), winregAsset("ip:dc01", "10.9.9.9"),
		scanCredential{domainUser: "LAB\\scan", password: "pw"})

	obs := observedByCheckCode(hf)
	eff, ok := obs[checkCodeEffectiveSigning]
	if !ok {
		t.Fatalf("no effective-signing row; rows=%+v", obs)
	}
	if !strings.HasPrefix(eff, effectiveRequired) {
		t.Errorf("effective signing = %q, want prefix %q (registry absent + probe required must be required)", eff, effectiveRequired)
	}
}

// TestEffectiveSigningRegistryZeroProbeNotRequired proves the agreeing case:
// registry server-signing present-0 + probe signing-not-required resolves to
// "not_required".
func TestEffectiveSigningRegistryZeroProbeNotRequired(t *testing.T) {
	origOpen := openWinregSession
	origProbe := probeSMB2
	defer func() { openWinregSession = origOpen; probeSMB2 = origProbe }()

	openWinregSession = fakeWinregOpener(map[string]regResult{
		"requiresecuritysignature": {outcome: regPresent, value: 0},
	})
	probeSMB2 = probeConst(smb2SigningProbe{ok: true, signingEnabled: true, signingRequired: false})

	hf := readWinreg(context.Background(), winregAsset("ip:dc01", "10.9.9.9"),
		scanCredential{domainUser: "LAB\\scan", password: "pw"})

	eff := observedByCheckCode(hf)[checkCodeEffectiveSigning]
	if !strings.HasPrefix(eff, effectiveNotRequired) {
		t.Errorf("effective signing = %q, want prefix %q", eff, effectiveNotRequired)
	}
}

// TestEffectiveSigningProbeRequiredOverridesRegistryZero proves a probe reporting
// signing-required wins over a registry present-0 (the server enforces signing
// even though the server-signing value reads 0).
func TestEffectiveSigningProbeRequiredOverridesRegistryZero(t *testing.T) {
	origOpen := openWinregSession
	origProbe := probeSMB2
	defer func() { openWinregSession = origOpen; probeSMB2 = origProbe }()

	openWinregSession = fakeWinregOpener(map[string]regResult{
		"requiresecuritysignature": {outcome: regPresent, value: 0},
	})
	probeSMB2 = probeConst(smb2SigningProbe{ok: true, signingEnabled: true, signingRequired: true})

	hf := readWinreg(context.Background(), winregAsset("ip:dc01", "10.9.9.9"),
		scanCredential{domainUser: "LAB\\scan", password: "pw"})

	eff := observedByCheckCode(hf)[checkCodeEffectiveSigning]
	if !strings.HasPrefix(eff, effectiveRequired) {
		t.Errorf("effective signing = %q, want prefix %q (probe-required overrides registry 0)", eff, effectiveRequired)
	}
}

// TestRunWinregProbeFailureNeverRaises proves a probe failure degrades gracefully
// to the registry-only rows: Run returns nil, the six registry rows survive on
// the payload, and the probe failure is a per-check note (never a stage error).
func TestRunWinregProbeFailureNeverRaises(t *testing.T) {
	origWMI := readWMI
	origOpen := openWinregSession
	origProbe := probeSMB2
	defer func() { readWMI = origWMI; openWinregSession = origOpen; probeSMB2 = origProbe }()

	// Keep WMI out of the picture (no real :135 dial for this winreg-focused test).
	readWMI = func(context.Context, payload.AssetItem, scanCredential) hostFacts { return newHostFacts() }
	openWinregSession = fakeWinregOpener(map[string]regResult{
		"requiresecuritysignature": {outcome: regPresent, value: 1},
	})
	probeSMB2 = probeConst(smb2SigningProbe{}) // ok=false: probe failed

	st := scanstate.New("full", "engine/test")
	seedGatedWindows(st, "ip:10.0.0.10", "10.0.0.10")

	if err := Run(context.Background(), st, capabilities.Capabilities{},
		Options{DomainUser: "LAB\\scan", Password: "pw", Workers: DefaultWorkers}); err != nil {
		t.Fatalf("Run returned an error on a probe failure (never-raises violated): %v", err)
	}

	pl := st.Payload()
	pl.Normalize()
	// The six registry rows must survive even though the probe failed.
	var regRows int
	for _, c := range pl.ConfigurationChecks {
		if strings.HasPrefix(c.CheckCode, "smb_signing:") || strings.HasPrefix(c.CheckCode, "lsa:") {
			regRows++
		}
	}
	if regRows < 6 {
		t.Errorf("registry-derived configuration_checks = %d, want >= 6 after probe failure", regRows)
	}
	note := pl.Assets[0].Classification.Evidence[noteKeySMB2]
	if note == "" {
		t.Errorf("probe-failure per-check note missing from evidence: %+v", pl.Assets[0].Classification.Evidence)
	}
}
