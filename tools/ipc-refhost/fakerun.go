// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/59k-ai/cysec-scanner/ipc"
	"github.com/59k-ai/cysec-scanner/ipc/runstate"
	"github.com/59k-ai/cysec-scanner/progress"
)

// startParams is the run.start params object this host accepts. Unknown
// fields are refused so a client typo fails loudly.
type startParams struct {
	CIDRs        []string `json:"cidrs"`
	Ports        *string  `json:"ports"`
	ProbeFragile *bool    `json:"probe_fragile"`
}

func invalidParams(msg string) error {
	return &ipc.Error{Code: ipc.CodeInvalidParams, Message: msg}
}

func parseStartParams(raw json.RawMessage) (startParams, error) {
	var p startParams
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return p, nil
	}
	if raw[0] != '{' {
		return p, invalidParams("params must be an object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, invalidParams("invalid params")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return p, invalidParams("invalid params")
	}
	for _, c := range p.CIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			return p, invalidParams("invalid cidr")
		}
	}
	return p, nil
}

// fakeRun is a RunController that plays a fixed script of progress events
// into the hub instead of scanning anything. Each run renumbers the events
// from seq 0 and stamps them with the current time; the outcome is taken from
// the script's scan_end status (completed, cancelled or failed).
type fakeRun struct {
	hub    *runstate.Hub
	script []progress.Event
	step   time.Duration
	now    func() time.Time

	mu     sync.Mutex
	runID  string
	cancel chan struct{}
	wg     sync.WaitGroup
}

func newFakeRun(hub *runstate.Hub, script []progress.Event, step time.Duration) *fakeRun {
	return &fakeRun{hub: hub, script: script, step: step, now: time.Now}
}

// Start implements ipc.RunController.
func (f *fakeRun) Start(_ context.Context, raw json.RawMessage, _ ipc.Peer) (string, error) {
	p, err := parseStartParams(raw)
	if err != nil {
		return "", err
	}
	return f.begin("manual", p.CIDRs)
}

func (f *fakeRun) begin(trigger string, scope []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runID != "" {
		return "", ipc.ErrRunInProgress{RunID: f.runID}
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	f.runID = "run-" + hex.EncodeToString(b[:])
	f.cancel = make(chan struct{})
	f.hub.Begin(runstate.RunInfo{RunID: f.runID, Trigger: trigger, StartedAt: f.now()})
	f.wg.Add(1)
	go f.play(f.cancel, scope)
	return f.runID, nil
}

// Cancel implements ipc.RunController.
func (f *fakeRun) Cancel(_ context.Context, runID string, _ ipc.Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.runID == "":
		return ipc.ErrNotRunning
	case runID != f.runID:
		return ipc.ErrRunMismatch
	}
	select {
	case <-f.cancel:
	default:
		close(f.cancel)
		f.hub.SetState("stopping")
	}
	return nil
}

// Status implements ipc.RunController; the host fills state and run from the
// hub, and this host has no schedule.
func (f *fakeRun) Status() ipc.RunStatus { return ipc.RunStatus{} }

// stop cancels an active run and waits for it to end.
func (f *fakeRun) stop() {
	f.mu.Lock()
	if f.runID != "" {
		select {
		case <-f.cancel:
		default:
			close(f.cancel)
		}
	}
	f.mu.Unlock()
	f.wg.Wait()
}

func (f *fakeRun) play(cancel <-chan struct{}, scope []string) {
	defer f.wg.Done()
	seq, assets := 0, 0
	emit := func(ev progress.Event) {
		ev.Seq = seq
		ev.TS = float64(f.now().UnixNano()) / 1e9
		seq++
		assets = ev.Assets
		f.hub.Publish(ev)
	}

	outcome, closed := "", false
	timer := time.NewTimer(f.step)
	defer timer.Stop()
script:
	for i, ev := range f.script {
		if i > 0 {
			timer.Reset(f.step)
			select {
			case <-cancel:
				outcome = "cancelled"
				break script
			case <-timer.C:
			}
		}
		if ev.Kind == progress.ScanStart && ev.Scan != nil && len(scope) > 0 {
			s := *ev.Scan
			s.Scope = append([]string(nil), scope...)
			ev.Scan = &s
		}
		emit(ev)
		if ev.Kind == progress.ScanEnd {
			closed = true
			outcome = "completed"
			if ev.ScanEnd != nil && (ev.ScanEnd.Status == "cancelled" || ev.ScanEnd.Status == "failed") {
				outcome = ev.ScanEnd.Status
			}
			break script
		}
	}
	if !closed {
		// A cancelled run, or a script without scan_end: close the run the way
		// an engine would, so every run ends with exactly one scan_end.
		if outcome == "" {
			outcome = "completed"
		}
		emit(progress.Event{Kind: progress.ScanEnd, Phase: "scan", Assets: assets,
			ScanEnd: &progress.ScanEndInfo{Status: outcome, Assets: assets}})
	}

	f.mu.Lock()
	f.runID = ""
	f.mu.Unlock()
	f.hub.End(outcome)
}

// loadScript reads an NDJSON file of progress events.
func loadScript(path string) ([]progress.Event, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []progress.Event
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev progress.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("script line %d: %w", n, err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("script is empty")
	}
	return out, nil
}

// defaultScript is a short run covering every detailed event kind.
func defaultScript() []progress.Event {
	stage := func(s string) *string { return &s }
	ev := func(kind progress.Kind, agent *string, assets int) progress.Event {
		return progress.Event{Kind: kind, Phase: "scan", Agent: agent, Assets: assets}
	}
	host := func(ip string, assets int, services ...progress.ServiceSummary) progress.Event {
		e := ev(progress.Host, stage("discovery"), assets)
		if services == nil {
			services = []progress.ServiceSummary{}
		}
		e.Host = &progress.HostSummary{IP: ip, ExternalID: "ip:" + ip, Services: services}
		return e
	}
	counts := func(name string, done, total, assets int) progress.Event {
		e := ev(progress.StageProgress, stage(name), assets)
		e.Progress = &progress.StageCounts{Done: done, Total: total}
		return e
	}
	start := ev(progress.ScanStart, nil, 0)
	start.Scan = &progress.ScanInfo{
		Scope:        []string{"192.0.2.0/29"},
		Stages:       []string{"discovery", "port"},
		Capabilities: progress.CapabilityInfo{SystemPing: true},
	}
	warn := ev(progress.Log, stage("port"), 3)
	warn.Warnings = 1
	warn.Log = &progress.LogLine{Level: "warn", Message: "host 192.0.2.5 did not answer the port probe"}
	ssh := progress.ServiceSummary{Port: 22, Protocol: "tcp", ServiceName: "ssh"}
	end := ev(progress.ScanEnd, nil, 3)
	end.Warnings = 1
	end.ScanEnd = &progress.ScanEndInfo{Status: "completed", Assets: 3}
	return []progress.Event{
		start,
		ev(progress.PhaseStart, nil, 0),
		ev(progress.AgentStart, stage("discovery"), 0),
		counts("discovery", 0, 8, 0),
		host("192.0.2.1", 1),
		counts("discovery", 3, 8, 1),
		host("192.0.2.3", 2),
		counts("discovery", 6, 8, 2),
		host("192.0.2.5", 3),
		counts("discovery", 8, 8, 3),
		ev(progress.AgentDone, stage("discovery"), 3),
		ev(progress.AgentStart, stage("port"), 3),
		counts("port", 0, 3, 3),
		host("192.0.2.1", 3, ssh),
		counts("port", 2, 3, 3),
		warn,
		counts("port", 3, 3, 3),
		ev(progress.AgentDone, stage("port"), 3),
		ev(progress.PhaseDone, nil, 3),
		end,
	}
}
