// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/payload"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// seedGatedWindows adds one gated Windows host (confident os_guess) with a
// realistic server classification already set by the upstream stages.
func seedGatedWindows(st *scanstate.ScanState, externalID, ip string) {
	addr := ip
	st.AddAsset(payload.AssetItem{
		ExternalID:     externalID,
		IPAddress:      &addr,
		OSGuess:        ptr("Windows"),
		Classification: &payload.ClassificationEvidence{AssetType: "server", Evidence: map[string]string{}},
	})
}

// fakeSoftwareReader returns a reader seam that lands one installed-software row
// stamped with the host's external id (mirrors the real reader's output shape).
func fakeSoftwareReader(row payload.SoftwareInventoryItem) wmiReaderFunc {
	return func(_ context.Context, ai payload.AssetItem, _ scanCredential) hostFacts {
		hf := newHostFacts()
		r := row
		r.AssetExternalID = ai.ExternalID
		hf.software = append(hf.software, r)
		hf.note(noteKeyWMISoftware, "fake read")
		return hf
	}
}

// recordingReader records every external id it was called with.
type recordingReader struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingReader) read(_ context.Context, ai payload.AssetItem, _ scanCredential) hostFacts {
	r.mu.Lock()
	r.calls = append(r.calls, ai.ExternalID)
	r.mu.Unlock()
	return newHostFacts()
}

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written, so the T-6-01 "password absent from logs" assertion has something to
// inspect.
func captureStderr(fn func()) string {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

// TestRunLandsSoftwareStrictValidV6 is the tracer end-to-end: a gated Windows
// host plus a fake WMI reader lands one software_inventory entry and the whole
// payload re-serialises strict-valid v6. It also proves the scan password is
// absent from the marshalled payload and from captured stderr (T-6-01).
func TestRunLandsSoftwareStrictValidV6(t *testing.T) {
	orig := readWMI
	defer func() { readWMI = orig }()
	readWMI = fakeSoftwareReader(payload.SoftwareInventoryItem{
		DisplayName:    "7-Zip",
		DisplayVersion: ptr("23.01"),
		Publisher:      ptr("Igor Pavlov"),
		InstallSource:  "wmi",
	})

	st := scanstate.New("full", "engine/test")
	seedGatedWindows(st, "ip:10.0.0.10", "10.0.0.10")
	// A non-gated host (nil guess, only ssh open) must never reach a reader.
	st.AddAsset(payload.AssetItem{ExternalID: "ip:10.0.0.99", Services: svcPorts(22)})

	const pw = "S3cr3t-PW-do-not-leak"
	captured := captureStderr(func() {
		if err := Run(context.Background(), st, capabilities.Capabilities{},
			Options{DomainUser: "LAB\\scan", Password: pw, Workers: DefaultWorkers}); err != nil {
			t.Fatalf("Run: %v", err)
		}
	})

	pl := st.Payload()
	pl.Normalize()

	if len(pl.SoftwareInventory) != 1 {
		t.Fatalf("software_inventory = %d, want 1", len(pl.SoftwareInventory))
	}
	if got := pl.SoftwareInventory[0]; got.AssetExternalID != "ip:10.0.0.10" || got.DisplayName != "7-Zip" {
		t.Fatalf("unexpected software row: %+v", got)
	}

	raw, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	for _, want := range []string{
		`"schema_version":6`,
		`"software_inventory":[`,
		`"assets":[`,
		`"identities":[]`,
		`"missing_kbs":[]`,
		`"password_policies":[]`,
		`"configuration_checks":[]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in payload; json=%s", want, s)
		}
	}

	var back payload.Payload
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if back.SchemaVersion != 6 {
		t.Errorf("round-trip schema_version = %d, want 6", back.SchemaVersion)
	}

	// T-6-01: the scan password never reaches the wire payload nor the logs.
	if strings.Contains(s, pw) {
		t.Fatal("scan password leaked into the marshalled payload")
	}
	if strings.Contains(captured, pw) {
		t.Fatalf("scan password leaked into stderr: %q", captured)
	}
}

// TestRunNoCredentialSkips proves D-06: with no credential the reader is never
// called, software_inventory stays empty, the gated host carries the
// no-credential evidence note, and the payload is still strict-valid v6.
func TestRunNoCredentialSkips(t *testing.T) {
	orig := readWMI
	defer func() { readWMI = orig }()
	called := false
	readWMI = func(_ context.Context, _ payload.AssetItem, _ scanCredential) hostFacts {
		called = true
		return newHostFacts()
	}

	st := scanstate.New("full", "engine/test")
	seedGatedWindows(st, "ip:10.0.0.10", "10.0.0.10")

	if err := Run(context.Background(), st, capabilities.Capabilities{}, Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if called {
		t.Fatal("reader invoked despite no credential (D-06 self-skip violated)")
	}

	pl := st.Payload()
	pl.Normalize()
	if len(pl.SoftwareInventory) != 0 {
		t.Fatalf("software_inventory = %d, want 0 on skip", len(pl.SoftwareInventory))
	}
	if note := pl.Assets[0].Classification.Evidence[evidenceKeyNoCredential]; note != noteNoCredential {
		t.Fatalf("no-credential evidence note = %q, want %q", note, noteNoCredential)
	}
	raw, _ := json.Marshal(pl)
	s := string(raw)
	if !strings.Contains(s, `"schema_version":6`) || !strings.Contains(s, `"software_inventory":[]`) {
		t.Fatalf("skip path not strict-valid v6: %s", s)
	}
}

// TestRunNonGatedHostNeverRead proves the gate (D-03): a confident non-Windows
// host with 445 open and a nil-guess host with no Windows port are never passed
// to any reader; only the gated host is.
func TestRunNonGatedHostNeverRead(t *testing.T) {
	orig := readWMI
	defer func() { readWMI = orig }()
	rec := &recordingReader{}
	readWMI = rec.read

	st := scanstate.New("full", "engine/test")
	seedGatedWindows(st, "ip:10.0.0.10", "10.0.0.10")
	linux := "10.0.0.50"
	st.AddAsset(payload.AssetItem{ExternalID: "ip:10.0.0.50", IPAddress: &linux, OSGuess: ptr("Linux"), Services: svcPorts(445)})
	st.AddAsset(payload.AssetItem{ExternalID: "ip:10.0.0.99", Services: svcPorts(22)})

	if err := Run(context.Background(), st, capabilities.Capabilities{},
		Options{DomainUser: "LAB\\scan", Password: "pw", Workers: 6}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != "ip:10.0.0.10" {
		t.Fatalf("reader called for non-gated hosts: %v (want only [ip:10.0.0.10])", rec.calls)
	}
}

// TestRunReaderErrorNeverRaises proves ENG-06/D-06: a reader that reports a
// degraded read (an error note) does not fail the stage; Run returns nil, the
// payload is still strict-valid, and the error note is recorded as evidence.
func TestRunReaderErrorNeverRaises(t *testing.T) {
	orig := readWMI
	defer func() { readWMI = orig }()
	readWMI = func(_ context.Context, _ payload.AssetItem, _ scanCredential) hostFacts {
		hf := newHostFacts()
		hf.note(noteKeyWMI, "AccessDenied")
		return hf
	}

	st := scanstate.New("full", "engine/test")
	seedGatedWindows(st, "ip:10.0.0.10", "10.0.0.10")

	if err := Run(context.Background(), st, capabilities.Capabilities{},
		Options{DomainUser: "LAB\\scan", Password: "pw", Workers: 6}); err != nil {
		t.Fatalf("Run returned an error on a degraded read (never-raises violated): %v", err)
	}
	pl := st.Payload()
	pl.Normalize()
	raw, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"schema_version":6`) {
		t.Fatal("degraded path not strict-valid v6")
	}
	if got := pl.Assets[0].Classification.Evidence[noteKeyWMI]; got != "AccessDenied" {
		t.Fatalf("error note not recorded as evidence: %+v", pl.Assets[0].Classification.Evidence)
	}
}

// TestRunWorkerPoolBound proves WINAD-04 holds DURING Run (not only inside
// clampWorkers): a blocking fake reader records the peak concurrent reader
// invocations, which must never exceed the clamped worker cap.
func TestRunWorkerPoolBound(t *testing.T) {
	orig := readWMI
	defer func() { readWMI = orig }()
	var inFlight, peak int32
	readWMI = func(_ context.Context, _ payload.AssetItem, _ scanCredential) hostFacts {
		cur := atomic.AddInt32(&inFlight, 1)
		defer atomic.AddInt32(&inFlight, -1)
		for {
			p := atomic.LoadInt32(&peak)
			if cur <= p || atomic.CompareAndSwapInt32(&peak, p, cur) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		return newHostFacts()
	}

	st := scanstate.New("full", "engine/test")
	for i := 0; i < 40; i++ {
		seedGatedWindows(st, fmt.Sprintf("ip:10.1.0.%d", i), fmt.Sprintf("10.1.0.%d", i))
	}
	const requested = 5
	capWorkers := clampWorkers(requested)
	if err := Run(context.Background(), st, capabilities.Capabilities{},
		Options{DomainUser: "LAB\\scan", Password: "pw", Workers: requested}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := atomic.LoadInt32(&peak); got > int32(capWorkers) {
		t.Fatalf("peak concurrent reads = %d, want <= %d (worker cap regressed during Run)", got, capWorkers)
	}
	if atomic.LoadInt32(&peak) == 0 {
		t.Fatal("no reads ran — the test did not exercise the pool")
	}
}
