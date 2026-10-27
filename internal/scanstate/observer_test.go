// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package scanstate

import (
	"testing"

	"github.com/59k-ai/cysec-scanner/payload"
)

// TestObserverNilSafe proves every observer-touching method is a no-op without
// an observer (and with an observer whose funcs are nil).
func TestObserverNilSafe(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	st.AddAsset(payload.AssetItem{ExternalID: "a"})
	st.UpdateAsset("a", func(a *payload.AssetItem) { a.Hostname = "h" })
	st.ReportProgress("port", 1, 2)
	st.ReportHostSeen("192.0.2.1")
	st.ReportLog("info", "x")

	st.SetObserver(&Observer{})
	st.AddAsset(payload.AssetItem{ExternalID: "b"})
	st.UpdateAsset("b", func(a *payload.AssetItem) { a.Hostname = "h" })
	st.ReportProgress("port", 1, 2)
	st.ReportHostSeen("192.0.2.1")
	st.ReportLog("info", "x")

	st.SetObserver(nil)
	st.AddAsset(payload.AssetItem{ExternalID: "c"})
}

// TestObserverOnAssetCopyAfterUnlock proves OnAsset receives an isolated copy
// after AddAsset and UpdateAsset, and runs after the lock is released (calling
// back into ScanState does not deadlock).
func TestObserverOnAssetCopyAfterUnlock(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	var got []payload.AssetItem
	st.SetObserver(&Observer{OnAsset: func(a payload.AssetItem) {
		_ = st.Assets() // would deadlock if called under s.mu
		a.Hostname = "mutated"
		if len(a.Services) > 0 {
			a.Services[0].Port = 9999
		}
		got = append(got, a)
	}})

	st.AddAsset(payload.AssetItem{ExternalID: "a", Services: []payload.ServiceItem{{Port: 22}}})
	st.UpdateAsset("a", func(a *payload.AssetItem) {
		a.Services = append(a.Services, payload.ServiceItem{Port: 80})
	})
	st.UpdateAsset("missing", func(a *payload.AssetItem) {})

	if len(got) != 2 {
		t.Fatalf("OnAsset calls = %d, want 2", len(got))
	}
	if len(got[1].Services) != 2 {
		t.Fatalf("UpdateAsset copy services = %d, want 2", len(got[1].Services))
	}
	as := st.Assets()
	if as[0].Hostname != "" {
		t.Errorf("observer mutation leaked into accumulator hostname: %q", as[0].Hostname)
	}
	if as[0].Services[0].Port != 22 {
		t.Errorf("observer mutation leaked into accumulator services: %d", as[0].Services[0].Port)
	}
}

// TestObserverReportForwarding proves the Report* methods forward verbatim.
func TestObserverReportForwarding(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	var stage, ip, level, msg string
	var done, total int
	st.SetObserver(&Observer{
		OnProgress: func(s string, d, tt int) { stage, done, total = s, d, tt },
		OnHostSeen: func(i string) { ip = i },
		OnLog:      func(l, m string) { level, msg = l, m },
	})
	st.ReportProgress("port", 3, 7)
	st.ReportHostSeen("192.0.2.9")
	st.ReportLog("warn", "hello")
	if stage != "port" || done != 3 || total != 7 {
		t.Errorf("progress = %q %d/%d", stage, done, total)
	}
	if ip != "192.0.2.9" {
		t.Errorf("host seen = %q", ip)
	}
	if level != "warn" || msg != "hello" {
		t.Errorf("log = %q %q", level, msg)
	}
}
