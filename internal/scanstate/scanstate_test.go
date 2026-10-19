// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package scanstate

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/59k-ai/cysec-scanner/internal/payload"
)

// TestSnapshotIsolation proves Payload() returns a snapshot whose asset slice
// does not alias internal state: mutating the snapshot leaves the accumulator
// unchanged.
func TestSnapshotIsolation(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	ip := "10.0.0.1"
	st.AddAsset(payload.AssetItem{ExternalID: "ip:10.0.0.1", IPAddress: &ip})

	snap := st.Payload()
	if len(snap.Assets) != 1 {
		t.Fatalf("snapshot assets = %d, want 1", len(snap.Assets))
	}
	snap.Assets = append(snap.Assets, payload.AssetItem{ExternalID: "ip:10.0.0.2"})

	if again := st.Payload(); len(again.Assets) != 1 {
		t.Fatalf("mutating the snapshot leaked into the accumulator: assets = %d, want 1", len(again.Assets))
	}
}

// TestConcurrentAddAsset proves the accumulator is safe under concurrent writers
// (run with -race; mirrors the concurrent sweep, Pitfall 4).
func TestConcurrentAddAsset(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", i)
			st.AddAsset(payload.AssetItem{ExternalID: "ip:" + ip, IPAddress: &ip})
		}(i)
	}
	wg.Wait()
	if got := len(st.Payload().Assets); got != n {
		t.Fatalf("concurrent AddAsset produced %d assets, want %d", got, n)
	}
}

// TestServiceBannersSideChannelIsolated proves the off-wire banner side-channel
// round-trips per asset and returns a copy: mutating the returned map does not
// change the stored state, and the banners never leak into the serialized
// payload.
func TestServiceBannersSideChannelIsolated(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	st.SetServiceBanners("ip:10.0.0.1", map[int]string{22: "SSH-2.0-OpenSSH_9.6p1"})

	got := st.ServiceBanners("ip:10.0.0.1")
	if got[22] != "SSH-2.0-OpenSSH_9.6p1" {
		t.Fatalf("banner not stored: %v", got)
	}
	// Mutating the returned copy must not affect stored state.
	got[22] = "tampered"
	got[80] = "injected"
	if again := st.ServiceBanners("ip:10.0.0.1"); again[22] != "SSH-2.0-OpenSSH_9.6p1" || len(again) != 1 {
		t.Fatalf("returned map aliased internal state: %v", again)
	}
	// An unknown asset yields an empty (non-nil) map.
	if m := st.ServiceBanners("ip:none"); m == nil || len(m) != 0 {
		t.Fatalf("unknown asset should yield empty map, got %v", m)
	}
	// Banners never reach the serialized payload.
	if b, _ := json.Marshal(st.Payload()); strings.Contains(string(b), "OpenSSH_9.6p1") {
		t.Fatalf("raw banner leaked into the payload: %s", b)
	}
}

// TestAddTopLevelSliceAccessors proves each new top-level-slice accessor appends
// one row to its matching payload slice (the authposture seam). One append per
// accessor, mirroring the AddAsset contract.
func TestAddTopLevelSliceAccessors(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")

	st.AddSoftwareInventory(payload.SoftwareInventoryItem{AssetExternalID: "ip:a", DisplayName: "7-Zip"})
	st.AddMissingKb(payload.MissingKbItem{AssetExternalID: "ip:a", KBID: "KB5001"})
	st.AddConfigurationCheck(payload.ConfigurationCheckItem{AssetExternalID: "ip:a", CheckCode: "SMB-SIGN"})
	st.AddIdentity(payload.IdentityItem{ExternalID: "u:svc", Username: "svc", Source: "active_directory"})
	st.AddPasswordPolicy(payload.PasswordPolicyItem{PolicyName: "Default Domain Policy"})

	pl := st.Payload()
	if len(pl.SoftwareInventory) != 1 || pl.SoftwareInventory[0].DisplayName != "7-Zip" {
		t.Errorf("AddSoftwareInventory: %+v", pl.SoftwareInventory)
	}
	if len(pl.MissingKbs) != 1 || pl.MissingKbs[0].KBID != "KB5001" {
		t.Errorf("AddMissingKb: %+v", pl.MissingKbs)
	}
	if len(pl.ConfigurationChecks) != 1 || pl.ConfigurationChecks[0].CheckCode != "SMB-SIGN" {
		t.Errorf("AddConfigurationCheck: %+v", pl.ConfigurationChecks)
	}
	if len(pl.Identities) != 1 || pl.Identities[0].Username != "svc" {
		t.Errorf("AddIdentity: %+v", pl.Identities)
	}
	if len(pl.PasswordPolicies) != 1 || pl.PasswordPolicies[0].PolicyName != "Default Domain Policy" {
		t.Errorf("AddPasswordPolicy: %+v", pl.PasswordPolicies)
	}
}

// TestSetRecogDBVersion proves the scan-metadata setter populates the v6 block
// and surfaces the value on the snapshot.
func TestSetRecogDBVersion(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	if sm := st.Payload().ScanMetadata; sm != nil {
		t.Fatalf("scan_metadata should start nil, got %+v", sm)
	}
	st.SetRecogDBVersion("abc123")
	sm := st.Payload().ScanMetadata
	if sm == nil || sm.RecogDBVersion == nil || *sm.RecogDBVersion != "abc123" {
		t.Fatalf("recog_db_version not recorded: %+v", sm)
	}
}

// TestSetOSSignatureDBVersion proves the OS-signature scan-metadata setter
// mirrors SetRecogDBVersion: it allocates the v6 block on first write and
// surfaces the value on the snapshot, independent of the recog version.
func TestSetOSSignatureDBVersion(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	if sm := st.Payload().ScanMetadata; sm != nil {
		t.Fatalf("scan_metadata should start nil, got %+v", sm)
	}
	st.SetOSSignatureDBVersion("osfp-v1-2026-10-19")
	sm := st.Payload().ScanMetadata
	if sm == nil || sm.OSSignatureDBVersion == nil || *sm.OSSignatureDBVersion != "osfp-v1-2026-10-19" {
		t.Fatalf("os_signature_db_version not recorded: %+v", sm)
	}
}
