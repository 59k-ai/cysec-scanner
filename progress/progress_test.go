// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package progress

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLegacyEventBytesUnchanged pins the legacy 8-key wire shape byte-for-byte:
// the detailed sub-objects are omitempty pointers, so a legacy event never
// grows a key (D-05).
func TestLegacyEventBytesUnchanged(t *testing.T) {
	got, err := json.Marshal(Event{Kind: PhaseStart, Seq: 0, TS: 0, Phase: "collect"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"phase_start","seq":0,"ts":0,"phase":"collect","agent":null,"errors":0,"warnings":0,"assets":0}`
	if string(got) != want {
		t.Fatalf("legacy bytes changed:\n got %s\nwant %s", got, want)
	}

	agent := "port"
	got, err = json.Marshal(Event{Kind: AgentStart, Seq: 1, TS: 0, Phase: "collect", Agent: &agent})
	if err != nil {
		t.Fatal(err)
	}
	want = `{"kind":"agent_start","seq":1,"ts":0,"phase":"collect","agent":"port","errors":0,"warnings":0,"assets":0}`
	if string(got) != want {
		t.Fatalf("legacy agent bytes changed:\n got %s\nwant %s", got, want)
	}
}

// TestDetailedSubObjectsOmittedWhenNil proves no detailed key leaks onto an
// event whose sub-object pointers are nil.
func TestDetailedSubObjectsOmittedWhenNil(t *testing.T) {
	b, err := json.Marshal(Event{Kind: AgentDone, Phase: "collect"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"scan", "progress", "host", "log", "scan_end"} {
		if _, ok := m[k]; ok {
			t.Errorf("key %q present on a nil sub-object: %s", k, b)
		}
	}
	if len(m) != 8 {
		t.Errorf("got %d keys, want 8: %s", len(m), b)
	}
}

// TestHostSummaryNullsAndEmptyServices proves nullable host fields marshal as
// JSON null and an empty services slice marshals as [].
func TestHostSummaryNullsAndEmptyServices(t *testing.T) {
	b, err := json.Marshal(HostSummary{IP: "192.0.2.1", Services: []ServiceSummary{}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"mac":null`, `"mac_vendor":null`, `"os_guess":null`, `"os_guess_confidence":null`, `"services":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
}

// TestDetailedEventCarriesSubObject proves a populated sub-object travels under
// its documented key.
func TestDetailedEventCarriesSubObject(t *testing.T) {
	b, err := json.Marshal(Event{Kind: ScanEnd, ScanEnd: &ScanEndInfo{Status: "completed", Assets: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"scan_end":{"status":"completed","error":null,"assets":2}`) {
		t.Fatalf("scan_end sub-object wrong: %s", b)
	}
}
