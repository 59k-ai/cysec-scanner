// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package runstate

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"

	"github.com/59k-ai/cysec-scanner/progress"
)

func strp(s string) *string { return &s }

func scanStartEv(seq int, stages ...string) progress.Event {
	return progress.Event{
		Kind:  progress.ScanStart,
		Seq:   seq,
		Phase: "scan",
		Scan:  &progress.ScanInfo{Scope: []string{"10.0.0.0/24"}, Stages: stages},
	}
}

func stageEv(seq int, stage string, done, total int) progress.Event {
	return progress.Event{
		Kind:     progress.StageProgress,
		Seq:      seq,
		Phase:    "scan",
		Agent:    strp(stage),
		Progress: &progress.StageCounts{Done: done, Total: total},
	}
}

func hostEv(seq int, ip, hostname string) progress.Event {
	return progress.Event{
		Kind:  progress.Host,
		Seq:   seq,
		Phase: "scan",
		Agent: strp("discovery"),
		Host: &progress.HostSummary{
			IP:         ip,
			ExternalID: "ip:" + ip,
			Hostname:   hostname,
			Services:   []progress.ServiceSummary{},
		},
	}
}

func logEv(seq int, level, msg string) progress.Event {
	return progress.Event{
		Kind:  progress.Log,
		Seq:   seq,
		Phase: "scan",
		Log:   &progress.LogLine{Level: level, Message: msg},
	}
}

func TestReduceStages(t *testing.T) {
	rs := newRunState(0)
	if rs.LastSeq() != -1 {
		t.Fatalf("LastSeq before any event = %d, want -1", rs.LastSeq())
	}
	rs.Apply(scanStartEv(0, "discovery", "port", "fingerprint"))
	rs.Apply(stageEv(1, "port", 120, 256))
	rs.Apply(stageEv(2, "port", 200, 256))

	rep := rs.Replay()
	if len(rep) != 2 {
		t.Fatalf("Replay len = %d, want 2: %+v", len(rep), rep)
	}
	if rep[0].Kind != progress.ScanStart || rep[0].Seq != 0 || rep[0].Scan == nil {
		t.Fatalf("Replay[0] = %+v, want scan_start seq 0", rep[0])
	}
	if got := rep[0].Scan.Stages; len(got) != 3 || got[1] != "port" {
		t.Fatalf("scan_start stages = %v", got)
	}
	sp := rep[1]
	if sp.Kind != progress.StageProgress || sp.Agent == nil || *sp.Agent != "port" ||
		sp.Progress == nil || sp.Progress.Done != 200 || sp.Progress.Total != 256 || sp.Seq != 2 {
		t.Fatalf("Replay[1] = %+v, want stage_progress port 200/256 seq 2", sp)
	}
	name, done, total := rs.CurrentStage()
	if name != "port" || done != 200 || total != 256 {
		t.Fatalf("CurrentStage = (%q, %d, %d), want (port, 200, 256)", name, done, total)
	}
	if rs.LastSeq() != 2 {
		t.Fatalf("LastSeq = %d, want 2", rs.LastSeq())
	}
}

func TestReduceStagesReplayInStageOrder(t *testing.T) {
	rs := newRunState(0)
	rs.Apply(scanStartEv(0, "discovery", "port", "fingerprint"))
	rs.Apply(stageEv(1, "fingerprint", 1, 3))
	rs.Apply(stageEv(2, "discovery", 5, 5))
	rs.Apply(stageEv(3, "extra", 1, 1))
	rep := rs.Replay()
	var order []string
	for _, ev := range rep[1:] {
		order = append(order, *ev.Agent)
	}
	want := []string{"discovery", "fingerprint", "extra"}
	if len(order) != len(want) {
		t.Fatalf("stage order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("stage order = %v, want %v", order, want)
		}
	}
}

func TestReduceHostsUpsert(t *testing.T) {
	rs := newRunState(0)
	rs.Apply(hostEv(0, "10.0.0.2", "old"))
	rs.Apply(hostEv(1, "10.0.0.1", "a"))
	rs.Apply(hostEv(2, "10.0.0.2", "new"))

	hosts, truncated := rs.Hosts()
	if truncated {
		t.Fatal("truncated = true, want false")
	}
	if len(hosts) != 2 || hosts[0].IP != "10.0.0.1" || hosts[1].IP != "10.0.0.2" {
		t.Fatalf("Hosts = %+v, want [10.0.0.1, 10.0.0.2]", hosts)
	}
	if hosts[1].Hostname != "new" {
		t.Fatalf("10.0.0.2 hostname = %q, want new", hosts[1].Hostname)
	}
	rep := rs.Replay()
	if len(rep) != 2 {
		t.Fatalf("Replay len = %d, want 2", len(rep))
	}
	if rep[0].Host.IP != "10.0.0.1" || rep[0].Seq != 1 {
		t.Fatalf("Replay[0] = %+v", rep[0])
	}
	if rep[1].Host.IP != "10.0.0.2" || rep[1].Seq != 2 || rep[1].Host.Hostname != "new" {
		t.Fatalf("Replay[1] = %+v", rep[1])
	}
	if _, _, h := rs.Counts(); h != 2 {
		t.Fatalf("Counts hosts = %d, want 2", h)
	}
}

func TestReduceHostsNumericOrder(t *testing.T) {
	rs := newRunState(0)
	rs.Apply(hostEv(0, "10.0.0.10", ""))
	rs.Apply(hostEv(1, "10.0.0.9", ""))
	hosts, _ := rs.Hosts()
	if hosts[0].IP != "10.0.0.9" || hosts[1].IP != "10.0.0.10" {
		t.Fatalf("Hosts order = %s, %s; want numeric order", hosts[0].IP, hosts[1].IP)
	}
}

func TestReduceCounts(t *testing.T) {
	rs := newRunState(0)
	rs.Apply(logEv(0, "warn", "w"))
	rs.Apply(logEv(1, "error", "e"))
	rs.Apply(logEv(2, "info", "i"))
	errs, warns, _ := rs.Counts()
	if errs != 1 || warns != 1 {
		t.Fatalf("after logs Counts = (%d, %d), want (1, 1)", errs, warns)
	}
	rs.Apply(progress.Event{Kind: progress.AgentDone, Seq: 3, Phase: "scan", Agent: strp("port"), Errors: 2, Warnings: 1})
	errs, warns, _ = rs.Counts()
	if errs != 2 || warns != 1 {
		t.Fatalf("after agent_done Counts = (%d, %d), want (2, 1)", errs, warns)
	}
	// A later log line still counts on top of the running total.
	rs.Apply(logEv(4, "warn", "w2"))
	if _, warns, _ = rs.Counts(); warns != 2 {
		t.Fatalf("after second warn warnings = %d, want 2", warns)
	}
}

func TestReduceHostCap(t *testing.T) {
	rs := newRunState(3)
	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		rs.Apply(hostEv(i, ip, ""))
	}
	hosts, truncated := rs.Hosts()
	if len(hosts) != 3 || !truncated {
		t.Fatalf("Hosts len = %d truncated = %v, want 3 true", len(hosts), truncated)
	}
	rs.Apply(hostEv(5, "10.0.0.2", "updated"))
	hosts, _ = rs.Hosts()
	if hosts[1].IP != "10.0.0.2" || hosts[1].Hostname != "updated" {
		t.Fatalf("update to kept host not applied: %+v", hosts[1])
	}
	if _, _, h := rs.Counts(); h != 5 {
		t.Fatalf("Counts hosts = %d, want 5 (dropped hosts are still counted)", h)
	}
	// A repeat of a dropped host is not counted twice.
	rs.Apply(hostEv(6, "10.0.0.5", ""))
	if _, _, h := rs.Counts(); h != 5 {
		t.Fatalf("Counts hosts after repeat = %d, want 5", h)
	}
	if got := len(rs.Replay()); got != 3 {
		t.Fatalf("Replay len = %d, want 3", got)
	}
}

func TestReduceFixture(t *testing.T) {
	f, err := os.Open("../../gui/tests/fixtures/ndjson-detailed.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs := newRunState(0)
	sc := bufio.NewScanner(f)
	var last progress.Event
	for sc.Scan() {
		var ev progress.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("fixture line: %v", err)
		}
		rs.Apply(ev)
		last = ev
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if rs.LastSeq() != last.Seq {
		t.Fatalf("LastSeq = %d, want %d", rs.LastSeq(), last.Seq)
	}
	end := rs.End()
	if end == nil || last.ScanEnd == nil || end.Status != last.ScanEnd.Status {
		t.Fatalf("End = %+v, want status %+v", end, last.ScanEnd)
	}
	hosts, _ := rs.Hosts()
	if len(hosts) != 3 {
		t.Fatalf("fixture hosts = %d, want 3", len(hosts))
	}
	// Every replayed event must survive a JSON round trip unchanged in shape.
	for _, ev := range rs.Replay() {
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		var back progress.Event
		if err := json.Unmarshal(b, &back); err != nil || back.Kind != ev.Kind || back.Seq != ev.Seq {
			t.Fatalf("round trip %s: %v", b, err)
		}
	}
}
