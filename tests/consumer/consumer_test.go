// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package consumer_test is an OUT-OF-MODULE proof (LIB-02): a separate Go module
// imports ONLY the public scanner/payload/progress packages and drives
// scanner.Run in-process with no proprietary knowledge and no credentials. It is
// the contract the whole v1.3 milestone sits on.
package consumer_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/progress"
	"github.com/59k-ai/cysec-scanner/scanner"
)

// consumerScope is a non-routable TEST-NET-1 (RFC 5737) single-host scope: the
// pipeline runs end-to-end but finds no live host, keeping the proof fast and
// deterministic and touching no real network host.
var consumerScope = []string{"192.0.2.1/32"}

// assertStrictValidV6 is the consumer-side copy of the objective's four-point
// strict-valid v6 check: (1) schema_version == 6; (2) payload_type in the enum;
// (3) after Normalize every required top-level slice marshals as a JSON array
// (never null) and nested required containers are non-nil; (4) additive scalar
// pointer fields are present.
func assertStrictValidV6(t *testing.T, pl payload.Payload) {
	t.Helper()

	if pl.SchemaVersion != 6 {
		t.Fatalf("schema_version = %d, want 6", pl.SchemaVersion)
	}
	switch pl.PayloadType {
	case "discovery", "identity", "vulnerability", "configuration", "full":
	default:
		t.Fatalf("payload_type = %q, not a valid v6 enum member", pl.PayloadType)
	}

	pl.Normalize()
	raw, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal top-level: %v", err)
	}
	for _, key := range []string{
		"assets", "identities", "service_exposures", "vulnerabilities",
		"configuration_checks", "password_policies", "software_inventory",
		"missing_kbs", "tls_probes",
	} {
		v, ok := top[key]
		if !ok {
			t.Errorf("required top-level key %q missing", key)
			continue
		}
		s := strings.TrimSpace(string(v))
		if s == "null" {
			t.Errorf("required slice %q marshaled to null, want array", key)
		}
		if len(s) == 0 || s[0] != '[' {
			t.Errorf("required slice %q is not a JSON array: %s", key, s)
		}
	}

	var reparsed payload.Payload
	if err := json.Unmarshal(raw, &reparsed); err != nil {
		t.Fatalf("reparse payload: %v", err)
	}
	for i := range reparsed.Assets {
		a := reparsed.Assets[i]
		if a.Services == nil {
			t.Errorf("asset[%d].services is nil after Normalize", i)
		}
		if a.NetworkAliases == nil {
			t.Errorf("asset[%d].network_aliases is nil after Normalize", i)
		}
		if a.Classification != nil {
			if a.Classification.Evidence == nil {
				t.Errorf("asset[%d] classification evidence is nil", i)
			}
			if a.Classification.SecurityFlags == nil {
				t.Errorf("asset[%d] classification security_flags is nil", i)
			}
		}
	}

	for _, key := range []string{"payload_id_hash", "scan_metadata"} {
		if _, ok := top[key]; !ok {
			t.Errorf("additive pointer key %q missing from JSON", key)
		}
	}
}

// TestConsumerDrivesRun proves a separate module can import the public packages
// and drive scanner.Run with a ProgressSink, receiving a strict-valid v6 payload
// and a contiguous Seq from 0 — with no proprietary knowledge and no credentials.
func TestConsumerDrivesRun(t *testing.T) {
	var events []progress.Event
	sink := func(ev progress.Event) { events = append(events, ev) }

	cfg := scanner.Config{CIDRs: consumerScope}
	pl, err := scanner.Run(context.Background(), cfg, sink)
	if err != nil {
		t.Fatalf("scanner.Run: %v", err)
	}

	assertStrictValidV6(t, pl)

	if len(events) == 0 {
		t.Fatal("expected progress events, got none")
	}
	for i, ev := range events {
		if ev.Seq != i {
			t.Errorf("event %d seq = %d, want %d (contiguous from 0, LIB-02)", i, ev.Seq, i)
		}
	}
	// First event is the phase_start of the collect phase (Run owns sequencing).
	if events[0].Kind != progress.PhaseStart || events[0].Seq != 0 {
		t.Errorf("first event = {kind:%q seq:%d}, want {phase_start 0}", events[0].Kind, events[0].Seq)
	}
}

// TestConsumerDefaultStages proves the public default order visible to a separate
// module is exactly the three non-proprietary stages (authposture absent, LIB-03).
func TestConsumerDefaultStages(t *testing.T) {
	if got := len(scanner.DefaultStages()); got != 3 {
		t.Fatalf("scanner.DefaultStages() = %d, want exactly 3", got)
	}
}
