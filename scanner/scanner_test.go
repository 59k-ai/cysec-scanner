// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/progress"
)

// testScope is a non-routable TEST-NET-1 (RFC 5737) single-host scope: the
// pipeline runs end-to-end but finds no live host, so the tests stay fast and
// deterministic and touch no real network host while still exercising every
// default stage and the full payload-assembly path.
var testScope = []string{"192.0.2.1/32"}

// assertStrictValidV6 implements the four-point "strict-valid v6 payload" check
// (plan objective): (1) schema_version == 6; (2) payload_type in the exact enum
// set; (3) after Normalize every required top-level slice marshals as a JSON
// array (never null) and every nested required container is non-nil; (4) the
// additive scalar pointer fields are present (serialize null-or-value).
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

	// Nested required containers must be non-nil after Normalize.
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

	// Additive scalar pointer fields are present (null-or-value).
	for _, key := range []string{"payload_id_hash", "scan_metadata"} {
		if _, ok := top[key]; !ok {
			t.Errorf("additive pointer key %q missing from JSON", key)
		}
	}
}

// TestRunDefaultPayloadStrictValid proves Run with nil ExtraStages returns a
// strict-valid v6 payload end-to-end.
func TestRunDefaultPayloadStrictValid(t *testing.T) {
	pl, err := Run(context.Background(), Config{CIDRs: testScope}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertStrictValidV6(t, pl)
}

// TestRunCanceledContextRunsZeroStageBodies proves a ctx canceled before Run
// returns a context error and runs zero stage bodies: the cancellation check
// precedes each stage, so no agent_start event is ever emitted.
func TestRunCanceledContextRunsZeroStageBodies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var events []progress.Event
	sink := func(ev progress.Event) { events = append(events, ev) }

	_, err := Run(ctx, Config{CIDRs: testScope}, sink)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
	for _, ev := range events {
		if ev.Kind == progress.AgentStart {
			t.Errorf("a stage began despite a pre-canceled ctx: %+v", ev)
		}
	}
}

// TestRunExtraStageSeesScanContext proves an ExtraStage receives a usable
// ScanContext facade: it can read Assets(), call UpdateAsset(), and read the
// immutable Capabilities.
func TestRunExtraStageSeesScanContext(t *testing.T) {
	var sawCtx, sawFacade bool
	extra := func(ctx context.Context, sc *ScanContext) error {
		sawCtx = ctx != nil
		_ = sc.Assets()
		sc.UpdateAsset("no-such-asset", func(a *payload.AssetItem) {})
		_ = sc.Capabilities.SystemPing
		sawFacade = true
		return nil
	}

	pl, err := Run(context.Background(), Config{CIDRs: testScope, ExtraStages: []Stage{extra}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !sawCtx || !sawFacade {
		t.Fatalf("extra stage did not receive a usable ScanContext (ctx=%v facade=%v)", sawCtx, sawFacade)
	}
	assertStrictValidV6(t, pl)
}

// TestRunExtraStageWidenedFacadeEmits proves the five slice-writer methods on
// the ScanContext facade reach the payload Run returns: an ExtraStage appends
// one row to each top-level slice and every row survives Run -> facade ->
// accumulator -> returned payload, which stays strict-valid v6.
func TestRunExtraStageWidenedFacadeEmits(t *testing.T) {
	minLen := 12
	extra := func(ctx context.Context, sc *ScanContext) error {
		sc.AddSoftwareInventory(payload.SoftwareInventoryItem{
			AssetExternalID: "host-1",
			DisplayName:     "Example App",
			InstallSource:   "test",
		})
		sc.AddMissingKb(payload.MissingKbItem{
			AssetExternalID: "host-1",
			KBID:            "KB0000001",
			Title:           "Example update",
			Severity:        "high",
		})
		sc.AddConfigurationCheck(payload.ConfigurationCheckItem{
			AssetExternalID: "host-1",
			CheckCode:       "EXAMPLE-001",
			Title:           "Example check",
			Status:          "fail",
			Severity:        "medium",
		})
		sc.AddPasswordPolicy(payload.PasswordPolicyItem{
			PolicyName: "Default",
			Scope:      "domain",
			MinLength:  &minLen,
		})
		sc.AddIdentity(payload.IdentityItem{
			ExternalID: "user-1",
			Username:   "alice",
			Source:     "directory",
			IsActive:   true,
		})
		return nil
	}

	pl, err := Run(context.Background(), Config{CIDRs: testScope, ExtraStages: []Stage{extra}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pl.SoftwareInventory) != 1 || len(pl.MissingKbs) != 1 ||
		len(pl.ConfigurationChecks) != 1 || len(pl.PasswordPolicies) != 1 ||
		len(pl.Identities) != 1 {
		t.Fatalf("slice lengths software=%d missing_kbs=%d config_checks=%d password_policies=%d identities=%d, want 1 each",
			len(pl.SoftwareInventory), len(pl.MissingKbs), len(pl.ConfigurationChecks),
			len(pl.PasswordPolicies), len(pl.Identities))
	}
	// Name-matched delegation: each row landed in its own slice, not a sibling.
	if pl.PasswordPolicies[0].PolicyName != "Default" {
		t.Errorf("password_policies[0].policy_name = %q, want %q", pl.PasswordPolicies[0].PolicyName, "Default")
	}
	if pl.Identities[0].Username != "alice" {
		t.Errorf("identities[0].username = %q, want %q", pl.Identities[0].Username, "alice")
	}
	assertStrictValidV6(t, pl)
}

// TestRunSinkSequence pins the progress event sequence Run owns (D-08): with nil
// ExtraStages the sink sees phase_start + one agent_start per default stage +
// phase_done, with a contiguous monotonic Seq from 0, the expected kind/phase/
// agent order, Agent nil on phase_* events, and a positive float TS (value not
// pinned).
func TestRunSinkSequence(t *testing.T) {
	var events []progress.Event
	sink := func(ev progress.Event) { events = append(events, ev) }

	if _, err := Run(context.Background(), Config{CIDRs: testScope}, sink); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(events) != 5 {
		t.Fatalf("got %d events, want 5 (phase_start + 3 agent_start + phase_done): %+v", len(events), events)
	}
	for i, ev := range events {
		if ev.Seq != i {
			t.Errorf("event %d seq = %d, want %d (contiguous from 0)", i, ev.Seq, i)
		}
		if ev.Phase != "collect" {
			t.Errorf("event %d phase = %q, want %q", i, ev.Phase, "collect")
		}
		if ev.TS <= 0 {
			t.Errorf("event %d ts = %v, want positive wall-clock", i, ev.TS)
		}
	}
	wantKinds := []progress.Kind{
		progress.PhaseStart, progress.AgentStart, progress.AgentStart,
		progress.AgentStart, progress.PhaseDone,
	}
	for i, want := range wantKinds {
		if events[i].Kind != want {
			t.Errorf("event %d kind = %q, want %q", i, events[i].Kind, want)
		}
	}
	if events[0].Agent != nil || events[4].Agent != nil {
		t.Error("phase_* events must carry a nil agent")
	}
	for i, want := range []string{"discovery", "port", "fingerprint"} {
		ev := events[i+1]
		if ev.Agent == nil || *ev.Agent != want {
			t.Errorf("agent_start event %d agent = %v, want %q", i, ev.Agent, want)
		}
	}
}

// TestDefaultStagesThreeNoAuthposture proves the public default order is exactly
// the three non-proprietary stages (LIB-03); authposture absence is enforced
// structurally (no fourth stage) and by the NO_AUTHPOSTURE_DEP build gate.
func TestDefaultStagesThreeNoAuthposture(t *testing.T) {
	if got := len(DefaultStages()); got != 3 {
		t.Fatalf("DefaultStages() returned %d stages, want exactly 3 (discovery, port, fingerprint)", got)
	}
}

// TestStandaloneSmoke is the zero-proprietary-code end-to-end proof (LIB-03): it
// drives the library against an auto-detect-shaped scope with no ExtraStages and
// no proprietary knowledge, asserts the produced payload is strict-valid v6, and
// asserts the public default order is exactly three stages with authposture
// absent. (A non-routable TEST-NET scope keeps the run fast and deterministic;
// the full auto-detect path is exercised by the CLI NDJSON smoke in verify.)
func TestStandaloneSmoke(t *testing.T) {
	if got := len(DefaultStages()); got != 3 {
		t.Fatalf("DefaultStages() = %d stages, want exactly 3 (authposture must be absent, LIB-03)", got)
	}
	pl, err := Run(context.Background(), Config{CIDRs: testScope}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertStrictValidV6(t, pl)
}
