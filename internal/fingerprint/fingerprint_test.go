// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/fingerprint/recog"
	"github.com/cysec-watch/cysec-scanner/internal/payload"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// fakeIdentity builds a synthetic match result so the precedence gate can be
// exercised at and below the confidence cut without depending on a database
// fingerprint that happens to carry a particular confidence.
func fakeIdentity(product, version string, conf float64) recog.Identity {
	return recog.Identity{Product: product, ServiceVersion: version, Confidence: conf}
}

// seedAsset builds a ScanState with one asset carrying one SSH service on port 22
// and stashes the given banner on the off-wire side-channel, exactly as the port
// stage would.
func seedAsset(t *testing.T, banner string, svc payload.ServiceItem) *scanstate.ScanState {
	t.Helper()
	st := scanstate.New("full", "engine/test")
	ip := "10.0.0.10"
	st.AddAsset(payload.AssetItem{
		ExternalID: "ip:10.0.0.10",
		IPAddress:  &ip,
		Services:   []payload.ServiceItem{svc},
	})
	st.SetServiceBanners("ip:10.0.0.10", map[int]string{svc.Port: banner})
	return st
}

func runStage(t *testing.T, st *scanstate.ScanState) payload.Payload {
	t.Helper()
	if err := Run(context.Background(), st, capabilities.Capabilities{}, Options{}); err != nil {
		t.Fatalf("fingerprint.Run returned error: %v", err)
	}
	pl := st.Payload()
	pl.Normalize()
	return pl
}

// TestEndToEndRecogMatch is the tracer proof: a discovered host whose captured
// SSH banner matches the vendored database emits the database-derived product /
// version / cpe on its service item with source "recog-v1" and a numeric
// confidence, and the snapshot payload is strict-valid at version 6.
func TestEndToEndRecogMatch(t *testing.T) {
	t.Parallel()

	st := seedAsset(t, "SSH-2.0-OpenSSH_5.9p1", payload.ServiceItem{
		Port:        22,
		Protocol:    "tcp",
		ServiceName: "ssh",
	})
	pl := runStage(t, st)

	if len(pl.Assets) != 1 || len(pl.Assets[0].Services) != 1 {
		t.Fatalf("unexpected shape: %+v", pl.Assets)
	}
	svc := pl.Assets[0].Services[0]
	if got := deref(svc.Product); got != "OpenSSH" {
		t.Errorf("product = %q, want OpenSSH", got)
	}
	if got := deref(svc.ServiceVersion); got != "5.9p1" {
		t.Errorf("service_version = %q, want 5.9p1", got)
	}
	if got := deref(svc.CPE); got != "cpe:/a:openbsd:openssh:5.9p1" {
		t.Errorf("cpe = %q, want cpe:/a:openbsd:openssh:5.9p1", got)
	}
	if got := deref(svc.ServiceIdentitySource); got != sourceRecogV1 {
		t.Errorf("service_identity_source = %q, want %q", got, sourceRecogV1)
	}
	if svc.ServiceIdentityConfidence == nil || *svc.ServiceIdentityConfidence < confidenceCut {
		t.Errorf("service_identity_confidence = %v, want >= %v", svc.ServiceIdentityConfidence, confidenceCut)
	}

	// Snapshot is strict-valid at version 6 (required slices [], version 6).
	assertStrictValidV6(t, pl)
}

// TestDBVersionRecorded proves scan_metadata.recog_db_version is set from the
// pinned governed manifest entry and is identical across repeated identical runs
// (FPRINT-04 determinism).
func TestDBVersionRecorded(t *testing.T) {
	t.Parallel()

	run := func() string {
		st := seedAsset(t, "SSH-2.0-OpenSSH_5.9p1", payload.ServiceItem{Port: 22, Protocol: "tcp", ServiceName: "ssh"})
		pl := runStage(t, st)
		if pl.ScanMetadata == nil {
			t.Fatalf("scan_metadata not set")
		}
		return deref(pl.ScanMetadata.RecogDBVersion)
	}

	want := recogDBVersion()
	if want == "" {
		t.Fatal("recogDBVersion() empty — manifest entry missing")
	}
	first := run()
	second := run()
	if first != want {
		t.Errorf("recog_db_version = %q, want manifest snapshot %q", first, want)
	}
	if first != second {
		t.Errorf("recog_db_version not deterministic across runs: %q vs %q", first, second)
	}
}

// TestPrecedenceMissKeepsPhase4Value proves a non-SSH banner (a miss) leaves the
// existing port-stage product and its source label untouched (D-11 — no clobber).
func TestPrecedenceMissKeepsPhase4Value(t *testing.T) {
	t.Parallel()

	phase4Source := "port-banner-v1"
	phase4Conf := 0.3
	st := seedAsset(t, "220 some-ftp-server ready", payload.ServiceItem{
		Port:                      21,
		Protocol:                  "tcp",
		ServiceName:               "ftp",
		Product:                   strptr("LightParseFTP"),
		ServiceVersion:            strptr("1.0"),
		ServiceIdentitySource:     &phase4Source,
		ServiceIdentityConfidence: &phase4Conf,
	})
	pl := runStage(t, st)
	svc := pl.Assets[0].Services[0]
	if deref(svc.Product) != "LightParseFTP" || deref(svc.ServiceVersion) != "1.0" {
		t.Errorf("miss clobbered the existing value: %+v", svc)
	}
	if deref(svc.ServiceIdentitySource) != phase4Source {
		t.Errorf("miss re-labeled the source: %q", deref(svc.ServiceIdentitySource))
	}
	assertStrictValidV6(t, pl)
}

// TestPrecedenceAtCutIsInclusive proves the 0.5 confidence cut is inclusive: a
// synthetic match at exactly the cut is promoted; one just below is not.
func TestPrecedenceAtCutIsInclusive(t *testing.T) {
	t.Parallel()

	phase4Source := "port-banner-v1"
	base := func() *payload.ServiceItem {
		return &payload.ServiceItem{
			Port:                  22,
			Product:               strptr("Phase4SSH"),
			ServiceVersion:        strptr("0.1"),
			ServiceIdentitySource: &phase4Source,
		}
	}

	atCut := base()
	if !applyServiceIdentity(atCut, fakeIdentity("OpenSSH", "9.0", confidenceCut), confidenceCut) {
		t.Fatal("match at the cut was not promoted; cut must be inclusive")
	}
	if deref(atCut.Product) != "OpenSSH" || deref(atCut.ServiceIdentitySource) != sourceRecogV1 {
		t.Errorf("at-cut match not promoted/re-labeled: %+v", atCut)
	}

	belowCut := base()
	if applyServiceIdentity(belowCut, fakeIdentity("OpenSSH", "9.0", confidenceCut-0.01), confidenceCut) {
		t.Fatal("below-cut match was promoted; should be suppressed")
	}
	if deref(belowCut.Product) != "Phase4SSH" || deref(belowCut.ServiceIdentitySource) != phase4Source {
		t.Errorf("below-cut match clobbered the Phase-4 value: %+v", belowCut)
	}
}

// TestNeverRaises proves hostile/degenerate banners yield no enrichment, no
// panic and a strict-valid payload (D-14). It also proves a matched value is
// control-char stripped and length-capped.
func TestNeverRaises(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"dark":      "",
		"binary":    "\x00\x01\x02\xff\xfe",
		"truncated": "SSH-2.0-Open",
		"oversized": "SSH-2.0-OpenSSH_" + strings.Repeat("A", 100000),
		"hostile":   "SSH-2.0-OpenSSH_5.9p1\x1b[31mmalicious\x00",
	}
	for name, banner := range cases {
		banner := banner
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := seedAsset(t, banner, payload.ServiceItem{Port: 22, Protocol: "tcp", ServiceName: "ssh"})
			pl := runStage(t, st)
			svc := pl.Assets[0].Services[0]
			// Any promoted value must be sanitized + capped (no control chars,
			// bounded length).
			if svc.Product != nil {
				if strings.ContainsAny(*svc.Product, "\x00\x1b") {
					t.Errorf("product carries control chars: %q", *svc.Product)
				}
			}
			if svc.ServiceVersion != nil && len(*svc.ServiceVersion) > maxParamBytesForTest {
				t.Errorf("service_version not length-capped: %d bytes", len(*svc.ServiceVersion))
			}
			assertStrictValidV6(t, pl)
		})
	}
}

// --- helpers ---

// maxParamBytesForTest mirrors the matcher's length cap for the never-raises
// assertion (a generous upper bound; the matcher caps well below this).
const maxParamBytesForTest = 1024

func assertStrictValidV6(t *testing.T, pl payload.Payload) {
	t.Helper()
	b, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"schema_version":6`) {
		t.Errorf("payload not at version 6; json=%s", s)
	}
	for _, tag := range []string{"assets", "service_exposures", "identities"} {
		if strings.Contains(s, `"`+tag+`":null`) {
			t.Errorf("required slice %q serialized null; json=%s", tag, s)
		}
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func strptr(s string) *string { return &s }
