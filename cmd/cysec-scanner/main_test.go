// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/59k-ai/cysec-scanner/payload"
)

// legacyKeys is the locked key set of every legacy NDJSON line (the Python
// engine driver's contract).
var legacyKeys = []string{"agent", "assets", "errors", "kind", "phase", "seq", "ts", "warnings"}

// emptyStdin is a stdin that is already at EOF, like "</dev/null".
func emptyStdin() io.Reader { return strings.NewReader("") }

func ndjsonLines(t *testing.T, out []byte) []map[string]json.RawMessage {
	t.Helper()
	var lines []map[string]json.RawMessage
	for _, raw := range bytes.Split(bytes.TrimRight(out, "\n"), []byte("\n")) {
		if len(raw) == 0 {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("stdout line is not JSON: %q: %v", raw, err)
		}
		lines = append(lines, m)
	}
	return lines
}

func kindOf(t *testing.T, line map[string]json.RawMessage) string {
	t.Helper()
	var k string
	if err := json.Unmarshal(line["kind"], &k); err != nil {
		t.Fatalf("kind: %v", err)
	}
	return k
}

func scanEndStatus(t *testing.T, line map[string]json.RawMessage) string {
	t.Helper()
	var se struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(line["scan_end"], &se); err != nil {
		t.Fatalf("scan_end: %v", err)
	}
	return se.Status
}

// readStrictPayload decodes the payload file rejecting unknown fields, so it is
// a strict-valid v7 document in the Go model's shape.
func readStrictPayload(t *testing.T, path string) (payload.Payload, map[string]json.RawMessage) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var pl payload.Payload
	if err := dec.Decode(&pl); err != nil {
		t.Fatalf("strict decode payload: %v", err)
	}
	if pl.SchemaVersion != payload.SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", pl.SchemaVersion, payload.SchemaVersion)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return pl, top
}

// TestLegacyStdoutUnchanged proves the default stdout is the legacy 5-event
// stream with exactly the 8 legacy keys per line.
func TestLegacyStdoutUnchanged(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--payload-out", out, "--cidr", "192.0.2.1/32"}, emptyStdin(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	lines := ndjsonLines(t, stdout.Bytes())
	if len(lines) != 5 {
		t.Fatalf("got %d stdout lines, want 5:\n%s", len(lines), stdout.String())
	}
	for i, l := range lines {
		keys := make([]string, 0, len(l))
		for k := range l {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if !reflect.DeepEqual(keys, legacyKeys) {
			t.Fatalf("line %d keys = %v, want %v", i, keys, legacyKeys)
		}
	}
}

// TestDetailedEvents proves --events=detailed frames the stream with scan_start
// and scan_end(completed), and the payload is v7 with scan_status null.
func TestDetailedEvents(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--payload-out", out, "--cidr", "192.0.2.1/32", "--events=detailed"}, emptyStdin(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	lines := ndjsonLines(t, stdout.Bytes())
	if len(lines) < 2 {
		t.Fatalf("too few lines: %s", stdout.String())
	}
	if k := kindOf(t, lines[0]); k != "scan_start" {
		t.Fatalf("first kind = %q, want scan_start", k)
	}
	last := lines[len(lines)-1]
	if k := kindOf(t, last); k != "scan_end" {
		t.Fatalf("last kind = %q, want scan_end", k)
	}
	if s := scanEndStatus(t, last); s != "completed" {
		t.Fatalf("scan_end status = %q, want completed", s)
	}
	pl, top := readStrictPayload(t, out)
	if pl.ScanStatus != nil || string(top["scan_status"]) != "null" {
		t.Fatalf("scan_status = %s, want null", top["scan_status"])
	}
}

// TestBadEventsFlagExit2 proves an unknown --events value is a usage error and
// no payload is written.
func TestBadEventsFlagExit2(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--payload-out", out, "--events=verbose"}, emptyStdin(), &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("payload file exists after usage error (err=%v)", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout not empty: %q", stdout.String())
	}
}

// TestCancelOnStdinEOFWritesPartialPayload proves stdin EOF cancels with the
// flag set: exit 130, a strict-valid partial payload marked cancelled, and a
// scan_end(cancelled) last line. TEST-NET-1 scope: no LAN probes leave the host.
func TestCancelOnStdinEOFWritesPartialPayload(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.json")
	pr, pw := io.Pipe()
	_ = pw.Close()
	var stdout, stderr bytes.Buffer
	code := run([]string{"--payload-out", out, "--cancel-on-stdin-eof", "--events=detailed", "--cidr", "192.0.2.0/24"}, pr, &stdout, &stderr)
	if code != 130 {
		t.Fatalf("exit = %d, want 130; stderr=%s", code, stderr.String())
	}
	pl, _ := readStrictPayload(t, out)
	if pl.ScanStatus == nil || *pl.ScanStatus != payload.ScanStatusCancelled {
		t.Fatalf("scan_status = %v, want cancelled", pl.ScanStatus)
	}
	lines := ndjsonLines(t, stdout.Bytes())
	if len(lines) == 0 {
		t.Fatal("no stdout lines")
	}
	last := lines[len(lines)-1]
	if k := kindOf(t, last); k != "scan_end" {
		t.Fatalf("last kind = %q, want scan_end", k)
	}
	if s := scanEndStatus(t, last); s != "cancelled" {
		t.Fatalf("scan_end status = %q, want cancelled", s)
	}
}

// TestStdinEOFIgnoredWithoutFlag proves a closed stdin does not cancel a scan
// unless --cancel-on-stdin-eof is set (T-13-51).
func TestStdinEOFIgnoredWithoutFlag(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.json")
	pr, pw := io.Pipe()
	_ = pw.Close()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--payload-out", out, "--cidr", "192.0.2.1/32"}, pr, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr.String())
	}
	pl, _ := readStrictPayload(t, out)
	if pl.ScanStatus != nil {
		t.Fatalf("scan_status = %v, want nil", *pl.ScanStatus)
	}
}

// TestDescribe proves --describe prints exactly one JSON document with the
// locked keys and exits 0 without --payload-out.
func TestDescribe(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--describe"}, emptyStdin(), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var doc map[string]json.RawMessage
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode describe: %v", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("more than one JSON document on stdout (err=%v)", err)
	}
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"capabilities", "default_ports", "engine_version", "event_modes", "networks", "timing_tiers"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	var full struct {
		EngineVersion string          `json:"engine_version"`
		Capabilities  map[string]bool `json:"capabilities"`
		Networks      []struct {
			Interface *string `json:"interface"`
			CIDR      string  `json:"cidr"`
		} `json:"networks"`
		DefaultPorts []int    `json:"default_ports"`
		TimingTiers  []string `json:"timing_tiers"`
		EventModes   []string `json:"event_modes"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &full); err != nil {
		t.Fatalf("decode typed: %v", err)
	}
	if full.EngineVersion == "" {
		t.Fatal("empty engine_version")
	}
	capKeys := make([]string, 0, len(full.Capabilities))
	for k := range full.Capabilities {
		capKeys = append(capKeys, k)
	}
	sort.Strings(capKeys)
	if !reflect.DeepEqual(capKeys, []string{"arp_cache", "system_ping", "unprivileged_icmp"}) {
		t.Fatalf("capability keys = %v", capKeys)
	}
	if string(doc["networks"]) == "null" {
		t.Fatal("networks is null, want an array")
	}
	for _, n := range full.Networks {
		if n.Interface == nil || n.CIDR == "" {
			t.Fatalf("network entry missing interface/cidr: %+v", n)
		}
	}
	if len(full.DefaultPorts) != 37 || full.DefaultPorts[0] != 21 {
		t.Fatalf("default_ports len=%d first=%v", len(full.DefaultPorts), full.DefaultPorts)
	}
	if !reflect.DeepEqual(full.TimingTiers, []string{"polite"}) {
		t.Fatalf("timing_tiers = %v", full.TimingTiers)
	}
	if !reflect.DeepEqual(full.EventModes, []string{"legacy", "detailed"}) {
		t.Fatalf("event_modes = %v", full.EventModes)
	}
}

// TestVersion proves --version prints one non-empty line and honours the
// ldflags-stamped package var.
func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, emptyStdin(), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	s := stdout.String()
	if strings.Count(s, "\n") != 1 || strings.TrimSpace(s) == "" {
		t.Fatalf("version output = %q, want one non-empty line", s)
	}

	orig := version
	version = "v9.9.9"
	defer func() { version = orig }()
	stdout.Reset()
	if code := run([]string{"--version"}, emptyStdin(), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if got := stdout.String(); got != "v9.9.9\n" {
		t.Fatalf("version = %q, want v9.9.9", got)
	}
}
