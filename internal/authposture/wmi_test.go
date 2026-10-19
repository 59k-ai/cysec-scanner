// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/payload"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
)

// fakeWMISession is an in-memory wmiSession for Linux CI: it returns canned rows
// keyed by the exact WQL (so each cimv2 class gets its own rows) and can simulate
// a per-namespace failure (e.g. a missing Defender/BitLocker namespace ->
// StatusInvalidNamespace) via errByNamespace. It never touches a real host.
type fakeWMISession struct {
	rowsByWQL      map[string][]wmio.Values
	errByNamespace map[string]error
}

func (f *fakeWMISession) query(_ context.Context, namespace, wql string) ([]wmio.Values, error) {
	if f.errByNamespace != nil {
		if err := f.errByNamespace[namespace]; err != nil {
			return nil, err
		}
	}
	return f.rowsByWQL[wql], nil
}

func (f *fakeWMISession) close() {}

// allClassRows returns one representative row per D-04 class, keyed by the exact
// WQL constant the class table uses (the fake session is WQL-addressed).
func allClassRows() map[string][]wmio.Values {
	return map[string][]wmio.Values{
		osWQL:                {{"Caption": "Microsoft Windows Server 2025 Standard", "Version": "10.0.26100", "BuildNumber": "26100", "OSArchitecture": "64-bit", "CSName": "DC01"}},
		quickFixWQL:          {{"HotFixID": "KB5034123", "Description": "Security Update"}},
		serviceWQL:           {{"Name": "LanmanServer", "State": "Running", "StartMode": "Auto", "StartName": "LocalSystem"}},
		installedProgramsWQL: {{"Name": "7-Zip", "Version": "23.01", "Vendor": "Igor Pavlov"}},
		eventlogWQL:          {{"LogfileName": "Security", "MaxFileSize": uint32(20971520), "OverWritePolicy": "OverwriteAsNeeded"}},
		encryptableVolumeWQL: {{"DriveLetter": "C:", "ProtectionStatus": uint32(1)}},
		defenderWQL:          {{"AntivirusEnabled": true, "RealTimeProtectionEnabled": true, "AntivirusSignatureAge": uint32(0)}},
	}
}

// allowedCheckStatus / allowedSeverity are the exact enum members the strict v6
// reference schema declares (payload-and-packaging.md). The mapping tests assert
// every emitted configuration_checks row uses ONLY these spellings.
var allowedCheckStatus = map[string]bool{"pass": true, "warn": true, "fail": true}
var allowedSeverity = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// TestWMIMapsAllSevenClasses drives the class table over a fake session returning
// rows for all seven D-04 classes and asserts each lands on its v6 target:
// Win32_OperatingSystem -> asset OS fields; Win32_QuickFixEngineering ->
// missing_kbs; Win32_InstalledWin32Program -> software_inventory; the four
// remaining classes -> configuration_checks. It also asserts the configuration
// Status/Severity use only the allowed enum members.
func TestWMIMapsAllSevenClasses(t *testing.T) {
	t.Parallel()

	sess := &fakeWMISession{rowsByWQL: allClassRows()}
	hf := newHostFacts()
	collectWMIClasses(context.Background(), sess, "ip:10.0.0.10", &hf)

	if hf.operatingSystem != "Microsoft Windows Server 2025 Standard" {
		t.Errorf("operatingSystem = %q, want the OS caption", hf.operatingSystem)
	}
	if hf.osVersion != "10.0.26100" {
		t.Errorf("osVersion = %q, want 10.0.26100", hf.osVersion)
	}

	if len(hf.missingKbs) != 1 {
		t.Fatalf("missingKbs = %d, want 1", len(hf.missingKbs))
	}
	if kb := hf.missingKbs[0]; kb.KBID != "KB5034123" || kb.AssetExternalID != "ip:10.0.0.10" || kb.Title != "Security Update" {
		t.Errorf("missingKb row unexpected: %+v", kb)
	}

	if len(hf.software) != 1 {
		t.Fatalf("software = %d, want 1", len(hf.software))
	}
	if sw := hf.software[0]; sw.DisplayName != "7-Zip" || sw.InstallSource != "wmi" || sw.AssetExternalID != "ip:10.0.0.10" {
		t.Errorf("software row unexpected: %+v", sw)
	}

	// Four config-check-bearing classes: service, event log, BitLocker, Defender.
	if len(hf.configChecks) != 4 {
		t.Fatalf("configChecks = %d, want 4 (service+eventlog+bitlocker+defender)", len(hf.configChecks))
	}
	wantCodes := map[string]bool{
		"win_service:LanmanServer": false,
		"win_eventlog:Security":    false,
		"bitlocker:C:":             false,
		"defender:status":          false,
	}
	for _, c := range hf.configChecks {
		if _, known := wantCodes[c.CheckCode]; known {
			wantCodes[c.CheckCode] = true
		}
		if c.AssetExternalID != "ip:10.0.0.10" {
			t.Errorf("config check %q has wrong asset id %q", c.CheckCode, c.AssetExternalID)
		}
		if !allowedCheckStatus[c.Status] {
			t.Errorf("config check %q status %q not an allowed {pass,warn,fail} member", c.CheckCode, c.Status)
		}
		if !allowedSeverity[c.Severity] {
			t.Errorf("config check %q severity %q not an allowed member", c.CheckCode, c.Severity)
		}
		if c.ObservedValue == "" {
			t.Errorf("config check %q has empty observed value (evidence missing)", c.CheckCode)
		}
	}
	for code, seen := range wantCodes {
		if !seen {
			t.Errorf("expected a configuration_check with code %q, none emitted", code)
		}
	}

	// missing_kbs severity must also be an allowed member.
	if !allowedSeverity[hf.missingKbs[0].Severity] {
		t.Errorf("missing_kb severity %q not an allowed member", hf.missingKbs[0].Severity)
	}
}

// TestWMINamespaceErrorNeverRaises proves the never-raises contract: when the
// Defender AND BitLocker namespaces fail (a StatusInvalidNamespace-shaped error),
// the mapping records a per-class evidence note for each and leaves every other
// class intact (OS fields, missing_kbs, software, and the cimv2 config checks all
// still present). No panic, no aborted loop.
func TestWMINamespaceErrorNeverRaises(t *testing.T) {
	t.Parallel()

	sess := &fakeWMISession{
		rowsByWQL: allClassRows(),
		errByNamespace: map[string]error{
			wmiNamespaceDefender:  wmiErr("StatusInvalidNamespace"),
			wmiNamespaceBitLocker: wmiErr("StatusInvalidNamespace"),
		},
	}
	hf := newHostFacts()
	collectWMIClasses(context.Background(), sess, "ip:10.0.0.10", &hf)

	// The other classes are intact.
	if hf.operatingSystem == "" || hf.osVersion == "" {
		t.Errorf("OS fields dropped when Defender/BitLocker failed: %q / %q", hf.operatingSystem, hf.osVersion)
	}
	if len(hf.missingKbs) != 1 {
		t.Errorf("missingKbs = %d, want 1 (QFE must survive a Defender/BitLocker failure)", len(hf.missingKbs))
	}
	if len(hf.software) != 1 {
		t.Errorf("software = %d, want 1 (installed-programs must survive)", len(hf.software))
	}
	// cimv2 config checks (service + event log) survive; the two failed namespaces
	// contribute nothing.
	if len(hf.configChecks) != 2 {
		t.Errorf("configChecks = %d, want 2 (service+eventlog only; bitlocker+defender failed)", len(hf.configChecks))
	}

	// A per-class evidence note was recorded for each failed namespace.
	for _, class := range []string{"MSFT_MpComputerStatus", "Win32_EncryptableVolume"} {
		if note := hf.notes[wmiClassNoteKey(class)]; note == "" {
			t.Errorf("no per-class evidence note recorded for failed class %q", class)
		}
	}
}

// wmiErr is a tiny error value for the namespace-failure fake.
type wmiErrString string

func (e wmiErrString) Error() string { return string(e) }
func wmiErr(s string) error          { return wmiErrString(s) }

// TestWMIClassParity is the operational WINAD-05 regression for the WMI reads: it
// asserts the package's class/namespace table EQUALS the spike's authoritative
// seven-class set across the three namespaces, with the banned MSI-reconfiguring
// product class deliberately absent. If a class is added, dropped, or renamed —
// or the banned class creeps in — parity fails, flagging a cutover drift from the
// Python agent. The expected set is encoded in-test (the spike source lives
// outside this module and is not read at runtime).
func TestWMIClassParity(t *testing.T) {
	t.Parallel()

	type nc struct{ ns, class string }
	want := map[nc]bool{
		{"//./root/cimv2", "Win32_OperatingSystem"}:                                      false,
		{"//./root/cimv2", "Win32_QuickFixEngineering"}:                                  false,
		{"//./root/cimv2", "Win32_Service"}:                                              false,
		{"//./root/cimv2", "Win32_InstalledWin32Program"}:                                false,
		{"//./root/cimv2", "Win32_NTEventlogFile"}:                                       false,
		{"//./root/cimv2/Security/MicrosoftVolumeEncryption", "Win32_EncryptableVolume"}: false,
		{"//./root/Microsoft/Windows/Defender", "MSFT_MpComputerStatus"}:                 false,
	}

	if len(wmiQueries) != len(want) {
		t.Fatalf("wmiQueries has %d entries, want %d (class set drifted from the spike)", len(wmiQueries), len(want))
	}

	namespaces := map[string]bool{}
	for _, q := range wmiQueries {
		namespaces[q.namespace] = true
		key := nc{q.namespace, q.class}
		seen, expected := want[key]
		if !expected {
			t.Errorf("unexpected WMI class/namespace in table: %s @ %s", q.class, q.namespace)
			continue
		}
		if seen {
			t.Errorf("duplicate WMI class/namespace in table: %s @ %s", q.class, q.namespace)
		}
		want[key] = true

		// Each query's WQL must actually SELECT FROM its declared class, and the
		// banned MSI-reconfiguring product class must never be the FROM target.
		if !strings.Contains(q.wql, "FROM "+q.class) {
			t.Errorf("query for %s does not SELECT FROM %s: %q", q.class, q.class, q.wql)
		}
		if strings.Contains(q.wql, "FROM Win32_Product") {
			t.Errorf("banned MSI-reconfiguring product class present in query: %q", q.wql)
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("expected WMI class/namespace missing from table: %s @ %s", key.class, key.ns)
		}
	}

	if len(namespaces) != 3 {
		t.Errorf("WMI table spans %d namespaces, want 3", len(namespaces))
	}
}

// TestWMIStrictValidV6EndToEnd drives the injectable reader with rows for all
// seven classes through the REAL stage (readWMI = liveWMIRead over a fake
// session), snapshots the payload, Normalizes it, and asserts software_inventory,
// missing_kbs, and configuration_checks are all populated and the whole payload
// marshals strict-valid at schema_version 6 (required slices as [] not null,
// pointer optionals null when unset). It also asserts the scan credential never
// appears in the marshalled payload (T-6-01).
func TestWMIStrictValidV6EndToEnd(t *testing.T) {
	origRead := readWMI
	origOpen := openWMISession
	defer func() { readWMI = origRead; openWMISession = origOpen }()

	readWMI = liveWMIRead // exercise the real class table + row mapping
	openWMISession = func(_ context.Context, _ string) (wmiSession, error) {
		return &fakeWMISession{rowsByWQL: allClassRows()}, nil
	}

	st := scanstate.New("full", "engine/test")
	seedGatedWindows(st, "ip:10.0.0.10", "10.0.0.10")

	const pw = "S3cr3t-PW-do-not-leak"
	if err := Run(context.Background(), st, capabilities.Capabilities{},
		Options{DomainUser: "LAB\\scan", Password: pw, Workers: DefaultWorkers}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	pl := st.Payload()
	pl.Normalize()

	if len(pl.SoftwareInventory) != 1 {
		t.Errorf("software_inventory = %d, want 1", len(pl.SoftwareInventory))
	}
	if len(pl.MissingKbs) != 1 {
		t.Errorf("missing_kbs = %d, want 1", len(pl.MissingKbs))
	}
	if len(pl.ConfigurationChecks) != 4 {
		t.Errorf("configuration_checks = %d, want 4", len(pl.ConfigurationChecks))
	}
	// The OS fields landed on the gated asset.
	if pl.Assets[0].OperatingSystem == "" {
		t.Errorf("asset operating_system not populated from Win32_OperatingSystem")
	}

	// Every configuration_checks row uses only the allowed enum spellings.
	for _, c := range pl.ConfigurationChecks {
		if !allowedCheckStatus[c.Status] {
			t.Errorf("config check %q status %q not an allowed member", c.CheckCode, c.Status)
		}
		if !allowedSeverity[c.Severity] {
			t.Errorf("config check %q severity %q not an allowed member", c.CheckCode, c.Severity)
		}
	}

	raw, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	for _, want := range []string{
		`"schema_version":6`,
		`"software_inventory":[`,
		`"missing_kbs":[`,
		`"configuration_checks":[`,
		`"assets":[`,
		`"identities":[]`,
		`"password_policies":[]`,
		`"tls_probes":[]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in strict-valid payload; json=%s", want, s)
		}
	}

	var back payload.Payload
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if back.SchemaVersion != 6 {
		t.Errorf("round-trip schema_version = %d, want 6", back.SchemaVersion)
	}

	// T-6-01: the scan credential never reaches the wire payload.
	if strings.Contains(s, pw) {
		t.Fatal("scan password leaked into the marshalled payload")
	}
}
