// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	scannerdata "github.com/59k-ai/cysec-scanner"
	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/fingerprint/osfp"
	"github.com/59k-ai/cysec-scanner/internal/fingerprint/recog"
	"github.com/59k-ai/cysec-scanner/internal/payload"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
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

// TestBackfillPhase4Provenance proves the backfill stamps a retained light-parse
// value with its paired provenance, leaves a promoted value untouched, and never
// invents provenance for a value-less service.
func TestBackfillPhase4Provenance(t *testing.T) {
	t.Parallel()

	t.Run("retained value stamped", func(t *testing.T) {
		t.Parallel()
		s := &payload.ServiceItem{Port: 80, Product: strptr("Zarniwoop-HTTPd/0.0")}
		backfillPhase4Provenance(s)
		if deref(s.ServiceIdentitySource) != sourcePortBannerV1 {
			t.Errorf("source = %q, want %q", deref(s.ServiceIdentitySource), sourcePortBannerV1)
		}
		if s.ServiceIdentityConfidence == nil || *s.ServiceIdentityConfidence != confidencePortBannerV1 {
			t.Errorf("confidence = %v, want %v", s.ServiceIdentityConfidence, confidencePortBannerV1)
		}
		if deref(s.Product) != "Zarniwoop-HTTPd/0.0" {
			t.Errorf("backfill mutated the product: %q", deref(s.Product))
		}
	})

	t.Run("promoted value untouched", func(t *testing.T) {
		t.Parallel()
		// Reach the already-promoted state through the real promotion path rather
		// than seeding a wire source by hand.
		s := &payload.ServiceItem{Port: 22, Product: strptr("Phase4SSH")}
		if !applyServiceIdentity(s, fakeIdentity("OpenSSH", "9.6", 0.9), confidenceCut) {
			t.Fatal("precondition: match was not promoted")
		}
		backfillPhase4Provenance(s)
		if deref(s.ServiceIdentitySource) != sourceRecogV1 || *s.ServiceIdentityConfidence != 0.9 {
			t.Errorf("backfill overwrote a promoted value: %+v", s)
		}
	})

	t.Run("no value untouched", func(t *testing.T) {
		t.Parallel()
		s := &payload.ServiceItem{Port: 23}
		backfillPhase4Provenance(s)
		if s.ServiceIdentitySource != nil || s.ServiceIdentityConfidence != nil {
			t.Errorf("backfill invented provenance for a value-less service: %+v", s)
		}
	})
}

// TestRetainedPhase4ValueCarriesProvenance proves a retained light-parse value
// (the database did not promote) keeps its value AND gains its paired provenance
// on the wire: a full HTTP response block whose Server value the http database
// does NOT match leaves the port-stage Product untouched (D-11 — a miss never
// nulls a good value) but stamps source=port-banner-v1 + confidence=0.3, so the
// wire never carries a product without its paired source + confidence (FPRINT-03).
func TestRetainedPhase4ValueCarriesProvenance(t *testing.T) {
	t.Parallel()

	// A full response block whose Server value matches no http fingerprint.
	const block = "HTTP/1.0 200 OK\r\nServer: Zarniwoop-HTTPd/0.0-nomatch\r\nContent-Type: text/html\r\n\r\n"

	// Confirm the Recog miss directly against the real corpus so the test exercises
	// the miss branch reaching the backfill, not a silent match.
	corpus, err := recog.LoadCorpus(scannerdata.DataFS, recogDir)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if _, matched := matchService(corpus, 80, block); matched {
		t.Fatalf("precondition: the Server value was expected to miss the http database")
	}

	// The port stage sets Product to the RAW Server-header value and records no
	// wire-level source (its provenance rides the classification evidence map).
	st := seedAsset(t, block, payload.ServiceItem{
		Port:        80,
		Protocol:    "tcp",
		ServiceName: "http",
		Product:     strptr("Zarniwoop-HTTPd/0.0-nomatch"),
	})
	pl := runStage(t, st)
	svc := pl.Assets[0].Services[0]
	if deref(svc.Product) != "Zarniwoop-HTTPd/0.0-nomatch" {
		t.Errorf("miss clobbered the retained value: %q", deref(svc.Product))
	}
	if got := deref(svc.ServiceIdentitySource); got != "port-banner-v1" {
		t.Errorf("service_identity_source = %q, want port-banner-v1", got)
	}
	if svc.ServiceIdentityConfidence == nil || *svc.ServiceIdentityConfidence != 0.3 {
		t.Errorf("service_identity_confidence = %v, want 0.3", svc.ServiceIdentityConfidence)
	}
	assertStrictValidV6(t, pl)
}

// TestPrecedenceOverwritesPhase4 proves an above-cut database match OVERWRITES a
// pre-existing lower-fidelity (port-stage) value and re-labels the source
// (D-11), end-to-end through the stage against the real database.
func TestPrecedenceOverwritesPhase4(t *testing.T) {
	t.Parallel()

	st := seedAsset(t, "SSH-2.0-OpenSSH_5.9p1", payload.ServiceItem{
		Port:           22,
		Protocol:       "tcp",
		ServiceName:    "ssh",
		Product:        strptr("GenericSSH"),
		ServiceVersion: strptr("0.0"),
	})
	pl := runStage(t, st)
	svc := pl.Assets[0].Services[0]
	if deref(svc.Product) != "OpenSSH" || deref(svc.ServiceVersion) != "5.9p1" {
		t.Errorf("above-cut match did not overwrite the Phase-4 value: %+v", svc)
	}
	if deref(svc.ServiceIdentitySource) != sourceRecogV1 {
		t.Errorf("source not re-labeled to %q: %q", sourceRecogV1, deref(svc.ServiceIdentitySource))
	}
	assertStrictValidV6(t, pl)
}

// TestPrecedenceAtCutIsInclusive proves the 0.5 confidence cut is inclusive: a
// synthetic match at exactly the cut is promoted; one just below is not.
func TestPrecedenceAtCutIsInclusive(t *testing.T) {
	t.Parallel()

	base := func() *payload.ServiceItem {
		return &payload.ServiceItem{
			Port:           22,
			Product:        strptr("Phase4SSH"),
			ServiceVersion: strptr("0.1"),
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
	if deref(belowCut.Product) != "Phase4SSH" || belowCut.ServiceIdentitySource != nil {
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

// seedAssetWithEvidence builds a ScanState with one asset carrying the given
// service, classification evidence, and (optionally) a captured banner on the
// off-wire side-channel — the shape the OS engine reads.
func seedAssetWithEvidence(t *testing.T, evidence map[string]string, svc payload.ServiceItem, banner string) *scanstate.ScanState {
	t.Helper()
	st := scanstate.New("full", "engine/test")
	ip := "10.0.0.20"
	st.AddAsset(payload.AssetItem{
		ExternalID: "ip:10.0.0.20",
		IPAddress:  &ip,
		Services:   []payload.ServiceItem{svc},
		Classification: &payload.ClassificationEvidence{
			AssetType:     "unknown",
			Evidence:      evidence,
			SecurityFlags: []string{},
		},
	})
	if banner != "" {
		st.SetServiceBanners("ip:10.0.0.20", map[int]string{svc.Port: banner})
	}
	return st
}

// TestHTTPRealPortStageResolvesV6 proves the multi-protocol routing closes
// FPRINT-01 end-to-end against the SHAPE the port stage actually captures: a FULL
// HTTP response block (status line + header lines), not a pre-stripped Server
// value. The fingerprint stage must extract the Server-header value before
// matching the http database, resolving into the v6 service-identity fields with
// source recog-v1 — a non-SSH protocol flowing all the way to the wire.
func TestHTTPRealPortStageResolvesV6(t *testing.T) {
	t.Parallel()

	// The port stage stashes the full response block (sanitizeBanner keeps CR/LF),
	// and its light parse sets Product to the RAW Server-header value.
	st := seedAsset(t, "HTTP/1.0 200 OK\r\nServer: nginx/1.4.6\r\nContent-Type: text/html\r\n\r\n", payload.ServiceItem{
		Port:        80,
		Protocol:    "tcp",
		ServiceName: "http",
		Product:     strptr("nginx/1.4.6"),
	})
	pl := runStage(t, st)
	svc := pl.Assets[0].Services[0]
	if got := deref(svc.Product); got != "nginx" {
		t.Errorf("product = %q, want nginx", got)
	}
	if got := deref(svc.ServiceVersion); got != "1.4.6" {
		t.Errorf("service_version = %q, want 1.4.6", got)
	}
	if got := deref(svc.CPE); got != "cpe:/a:f5:nginx:1.4.6" {
		t.Errorf("cpe = %q, want cpe:/a:f5:nginx:1.4.6", got)
	}
	if got := deref(svc.ServiceIdentitySource); got != sourceRecogV1 {
		t.Errorf("service_identity_source = %q, want %q", got, sourceRecogV1)
	}
	if svc.CPE == nil {
		t.Errorf("cpe nil; want non-nil")
	}
	assertStrictValidV6(t, pl)
}

// TestBelowCutServiceMatchNoOSGuess proves a below-cut service match cannot leak
// its OS family past the prefer-unknown cut. A real `220 ` SMTP greeting matches
// the smtp database (preference 0.20 < cut) and that fingerprint carries an
// os.family of Windows; with a corroborating windows reply-TTL family on the
// asset, an UNGATED banner cue would amplify past the cut into an os_guess. The
// cut-gate on bannerOSCue collection keeps the below-cut family out of the OS
// engine, so the os_guess trio stays null together.
func TestBelowCutServiceMatchNoOSGuess(t *testing.T) {
	t.Parallel()

	const smtpGreeting = "220 ArGoSoft Mail Server, Version 1.4 (1.4.0.7)"

	// Confirm the preconditions with a direct probe on the real corpus: the greeting
	// matches, carries an OS family, and is BELOW the confidence cut.
	corpus, err := recog.LoadCorpus(scannerdata.DataFS, recogDir)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	id, matched := matchService(corpus, 25, smtpGreeting)
	if !matched {
		t.Fatalf("precondition: smtp greeting did not match the corpus")
	}
	if id.OSFamily == "" {
		t.Fatalf("precondition: matched smtp fingerprint carries no OS family")
	}
	if id.Confidence >= confidenceCut {
		t.Fatalf("precondition: smtp match confidence %v not below cut %v", id.Confidence, confidenceCut)
	}

	st := seedAssetWithEvidence(t,
		map[string]string{"os_ttl_family": "windows"},
		payload.ServiceItem{Port: 25, Protocol: "tcp", ServiceName: "smtp"},
		smtpGreeting,
	)
	pl := runStage(t, st)
	a := pl.Assets[0]
	if a.OSGuess != nil || a.OSGuessSource != nil || a.OSGuessConfidence != nil {
		t.Errorf("below-cut OS family leaked into os_guess: guess=%v source=%v conf=%v",
			a.OSGuess, a.OSGuessSource, a.OSGuessConfidence)
	}
	assertStrictValidV6(t, pl)
}

// TestOSGuessFromTTLAndBanner proves the OS engine emits a guess into the v6
// os_guess trio when an unprivileged TTL family and a banner OS cue corroborate.
// The banner OS cue flows from the Recog match (a Microsoft FTP banner carries an
// os.family of Windows), and the discovery reply-TTL family is windows.
func TestOSGuessFromTTLAndBanner(t *testing.T) {
	t.Parallel()

	st := seedAssetWithEvidence(t,
		map[string]string{"os_ttl_family": "windows"},
		payload.ServiceItem{Port: 21, Protocol: "tcp", ServiceName: "ftp"},
		"220 foo.bar Microsoft FTP Service (Version 3.0).",
	)
	pl := runStage(t, st)
	a := pl.Assets[0]
	if got := deref(a.OSGuess); got != "Windows" {
		t.Errorf("os_guess = %q, want Windows", got)
	}
	if got := deref(a.OSGuessSource); got != "osfp-banner-v1" {
		t.Errorf("os_guess_source = %q, want osfp-banner-v1", got)
	}
	if a.OSGuessConfidence == nil || *a.OSGuessConfidence < 0.5 {
		t.Errorf("os_guess_confidence = %v, want >= 0.5", a.OSGuessConfidence)
	}
	// The FTP service identity is also promoted (IIS) — routing works for non-SSH.
	if got := deref(a.Services[0].Product); got != "IIS" {
		t.Errorf("ftp product = %q, want IIS", got)
	}
	assertStrictValidV6(t, pl)
}

// TestOSGuessTTLAloneIsUnknown proves a coarse TTL-only signal (no banner cue)
// scores below the cut, so os_guess, os_guess_source and os_guess_confidence stay
// null together — "unknown" is preferred over a spoofable TTL guess.
func TestOSGuessTTLAloneIsUnknown(t *testing.T) {
	t.Parallel()

	st := seedAssetWithEvidence(t,
		map[string]string{"os_ttl_family": "linux"},
		payload.ServiceItem{Port: 22, Protocol: "tcp", ServiceName: "ssh"},
		"", // no banner
	)
	pl := runStage(t, st)
	a := pl.Assets[0]
	if a.OSGuess != nil || a.OSGuessSource != nil || a.OSGuessConfidence != nil {
		t.Errorf("TTL-alone must leave os_guess trio null: guess=%v source=%v conf=%v",
			a.OSGuess, a.OSGuessSource, a.OSGuessConfidence)
	}
	assertStrictValidV6(t, pl)
}

// TestOSGuessNoSignalAllNull proves a host with no TTL family and no banner cue
// yields no OS guess at all — every OS provenance field null together.
func TestOSGuessNoSignalAllNull(t *testing.T) {
	t.Parallel()

	st := seedAssetWithEvidence(t,
		map[string]string{},
		payload.ServiceItem{Port: 22, Protocol: "tcp", ServiceName: "ssh"},
		"",
	)
	pl := runStage(t, st)
	a := pl.Assets[0]
	if a.OSGuess != nil || a.OSGuessSource != nil || a.OSGuessConfidence != nil {
		t.Errorf("no-signal host must have null os_guess trio: %+v", a)
	}
	assertStrictValidV6(t, pl)
}

// TestOSDBVersionRecorded proves scan_metadata.os_signature_db_version is set on
// every run from the self-authored package constant (FPRINT-04).
func TestOSDBVersionRecorded(t *testing.T) {
	t.Parallel()

	st := seedAsset(t, "SSH-2.0-OpenSSH_5.9p1", payload.ServiceItem{Port: 22, Protocol: "tcp", ServiceName: "ssh"})
	pl := runStage(t, st)
	if pl.ScanMetadata == nil {
		t.Fatal("scan_metadata not set")
	}
	if got := deref(pl.ScanMetadata.OSSignatureDBVersion); got != osfp.OSSignatureDBVersion {
		t.Errorf("os_signature_db_version = %q, want %q", got, osfp.OSSignatureDBVersion)
	}
}

// Corpus-grounded leadered greetings: each is a golden <example> from its
// protocol's vendored database with the real status leader the port stage
// captures prepended (FTP/SMTP "220 ", POP3 "+OK ", IMAP "* OK ") — never a
// pre-stripped payload.
const (
	ftpLeaderedGreeting  = "220 foo.bar Microsoft FTP Service (Version 3.0)."
	smtpLeaderedGreeting = "220 ArGoSoft Mail Server, Version 1.4 (1.4.0.7)"
	pop3LeaderedGreeting = "+OK Lotus Notes POP3 server version Release 8.5.1FP5 ready on foo/US."
	imapLeaderedGreeting = "* OK Microsoft Exchange 2000 IMAP4rev1 server version 6.0.6249.0 (foo.bar) ready."
)

// TestMatchServiceNormalizesLeaderedBanners proves matchService strips each
// protocol's real greeting leader before the match: a full leadered greeting (the
// shape the port stage emits) matches its database. ftp/smtp exercise the numeric
// status-leader strip; pop3/imap exercise the token/untagged-response strip.
func TestMatchServiceNormalizesLeaderedBanners(t *testing.T) {
	t.Parallel()

	corpus, err := recog.LoadCorpus(scannerdata.DataFS, recogDir)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	cases := []struct {
		name     string
		port     int
		greeting string
	}{
		{"ftp", 21, ftpLeaderedGreeting},
		{"smtp", 25, smtpLeaderedGreeting},
		{"pop3", 110, pop3LeaderedGreeting},
		{"imap", 143, imapLeaderedGreeting},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, matched := matchService(corpus, tc.port, tc.greeting); !matched {
				t.Errorf("%s: leadered greeting %q did not match after normalisation", tc.name, tc.greeting)
			}
		})
	}
}

// TestFTPGreetingResolvesToV6 proves a real FTP greeting (with its 220 leader)
// resolves end-to-end to recog-v1 with a product and cpe (ftp database preference
// 0.90 >= cut). FTP resolves via the numeric-leader strip added for the tracer.
func TestFTPGreetingResolvesToV6(t *testing.T) {
	t.Parallel()
	assertGreetingResolvesV6(t, 21, "ftp", ftpLeaderedGreeting)
}

// TestPOP3GreetingResolvesToV6 proves a real POP3 greeting (with its +OK leader)
// resolves end-to-end to recog-v1 with a product and cpe (pop3 database 0.90).
func TestPOP3GreetingResolvesToV6(t *testing.T) {
	t.Parallel()
	assertGreetingResolvesV6(t, 110, "pop3", pop3LeaderedGreeting)
}

// TestIMAPGreetingResolvesToV6 proves a real IMAP greeting (with its untagged
// "* OK" leader) resolves end-to-end to recog-v1 with a product and cpe (imap
// database 0.90).
func TestIMAPGreetingResolvesToV6(t *testing.T) {
	t.Parallel()
	assertGreetingResolvesV6(t, 143, "imap", imapLeaderedGreeting)
}

// TestSMTPBelowCutRetained proves a real SMTP greeting matches after the leader
// strip but is NOT promoted to recog-v1 (smtp database preference 0.20 < cut).
func TestSMTPBelowCutRetained(t *testing.T) {
	t.Parallel()

	st := seedAsset(t, smtpLeaderedGreeting, payload.ServiceItem{
		Port:        25,
		Protocol:    "tcp",
		ServiceName: "smtp",
	})
	pl := runStage(t, st)
	svc := pl.Assets[0].Services[0]
	if deref(svc.ServiceIdentitySource) == sourceRecogV1 {
		t.Errorf("below-cut smtp match was promoted to %q; preference 0.20 < cut", sourceRecogV1)
	}
	assertStrictValidV6(t, pl)
}

// assertGreetingResolvesV6 drives a leadered greeting through fingerprint.Run on
// the given port and asserts it promotes to recog-v1 with a non-nil product and
// cpe, on a strict-valid v6 payload.
func assertGreetingResolvesV6(t *testing.T, port int, serviceName, greeting string) {
	t.Helper()
	st := seedAsset(t, greeting, payload.ServiceItem{
		Port:        port,
		Protocol:    "tcp",
		ServiceName: serviceName,
	})
	pl := runStage(t, st)
	svc := pl.Assets[0].Services[0]
	if got := deref(svc.ServiceIdentitySource); got != sourceRecogV1 {
		t.Errorf("service_identity_source = %q, want %q", got, sourceRecogV1)
	}
	if svc.Product == nil {
		t.Errorf("product nil; want non-nil")
	}
	if svc.CPE == nil {
		t.Errorf("cpe nil; want non-nil")
	}
	assertStrictValidV6(t, pl)
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
