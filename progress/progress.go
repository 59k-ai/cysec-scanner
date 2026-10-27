// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package progress carries the NDJSON ProgressEvent shape, mirroring the
// authoritative wire model's ProgressEvent contract.
//
// Event is the public, single source of truth for the per-line NDJSON wire
// shape: one complete JSON object is written per line and NOTHING else is
// written to that stream — no banners, no log lines, no payload. The engine
// wires a sink to os.Stdout; all logging goes to os.Stderr via slog. The
// Emitter writes one whole object per Encode under a mutex, so concurrent
// writes can never interleave into a torn line (ENG-02).
//
// ProgressSink is the public progress callback type (D-07): scanner.Run invokes
// it synchronously as each stage begins, with a fully-populated Event. A nil
// sink means no progress is emitted. Run owns Seq/TS assignment (D-08) — the
// Write path and a ProgressSink are pure serializers and assign neither.
//
// Detailed kinds (scan_start, stage_progress, host, log, scan_end) and the
// agent_done lifecycle event are opt-in (D-05): they are only emitted when the
// scanner runs with Config.DetailedEvents. They carry their payload in pointer
// sub-objects tagged omitempty, so a legacy event marshals with exactly the
// eight legacy keys and a legacy consumer sees a byte-identical stream.
package progress

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Kind is the coarse progress taxonomy; its value is the JSON wire string. The
// values mirror the authoritative ProgressEvent kind vocabulary (phase_start/
// phase_done/agent_start/agent_done).
type Kind string

const (
	PhaseStart Kind = "phase_start"
	PhaseDone  Kind = "phase_done"
	AgentStart Kind = "agent_start"
	AgentDone  Kind = "agent_done"

	// Detailed kinds (opt-in, D-05). These extend the reference schema's kind
	// vocabulary and are never emitted in legacy mode.
	ScanStart     Kind = "scan_start"
	StageProgress Kind = "stage_progress"
	Host          Kind = "host"
	Log           Kind = "log"
	ScanEnd       Kind = "scan_end"
)

// Event is the on-the-wire ProgressEvent shape; keys mirror the authoritative
// wire model's ProgressEvent contract exactly. Agent is a pointer so it marshals
// to JSON null on phase_* events (the reference contract carries no agent on
// those). The field set and JSON tags are a public contract (D-08): Seq is a
// contiguous monotonic counter from 0 within a run and TS is a wall-clock
// UnixNano()/1e9 timestamp, both assigned by scanner.Run.
type Event struct {
	Kind     Kind    `json:"kind"`
	Seq      int     `json:"seq"`
	TS       float64 `json:"ts"`
	Phase    string  `json:"phase"`
	Agent    *string `json:"agent"`
	Errors   int     `json:"errors"`
	Warnings int     `json:"warnings"`
	Assets   int     `json:"assets"`

	// Detailed sub-objects (opt-in, D-05). Each is a pointer tagged omitempty so
	// it is absent from the wire unless set; at most one is set per event.
	Scan     *ScanInfo    `json:"scan,omitempty"`
	Progress *StageCounts `json:"progress,omitempty"`
	Host     *HostSummary `json:"host,omitempty"`
	Log      *LogLine     `json:"log,omitempty"`
	ScanEnd  *ScanEndInfo `json:"scan_end,omitempty"`
}

// ScanInfo rides on scan_start: the scope as given, the stage names in run
// order, and the runtime capabilities detected for this run.
type ScanInfo struct {
	Scope        []string       `json:"scope"`
	Stages       []string       `json:"stages"`
	Capabilities CapabilityInfo `json:"capabilities"`
}

// CapabilityInfo is the wire model of the engine's detected runtime
// capabilities.
type CapabilityInfo struct {
	UnprivilegedICMP bool `json:"unprivileged_icmp"`
	SystemPing       bool `json:"system_ping"`
	ARPCache         bool `json:"arp_cache"`
}

// StageCounts rides on stage_progress; the stage name travels in Event.Agent.
type StageCounts struct {
	Done  int `json:"done"`
	Total int `json:"total"`
}

// HostSummary rides on host: a compact per-host view for live display. Nullable
// fields marshal as JSON null; Services is always a JSON array.
type HostSummary struct {
	IP                string           `json:"ip"`
	ExternalID        string           `json:"external_id"`
	Hostname          string           `json:"hostname"`
	MAC               *string          `json:"mac"`
	MACVendor         *string          `json:"mac_vendor"`
	OSGuess           *string          `json:"os_guess"`
	OSGuessConfidence *float64         `json:"os_guess_confidence"`
	Services          []ServiceSummary `json:"services"`
}

// ServiceSummary is one open service on a HostSummary.
type ServiceSummary struct {
	Port           int     `json:"port"`
	Protocol       string  `json:"protocol"`
	ServiceName    string  `json:"service_name"`
	Product        *string `json:"product"`
	ServiceVersion *string `json:"service_version"`
}

// LogLine rides on log. Level is "info", "warn" or "error"; Message is
// sanitised by the engine (control runes stripped, length capped) before emit.
type LogLine struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// ScanEndInfo rides on scan_end. Status is "completed", "cancelled" or
// "failed"; Error is set only for "failed".
type ScanEndInfo struct {
	Status string  `json:"status"`
	Error  *string `json:"error"`
	Assets int     `json:"assets"`
}

// ProgressSink is the public progress callback (D-07). It is synchronous:
// scanner.Run calls it as each stage begins, passing a fully-populated Event. A
// nil sink emits nothing. A GUI that wants async delivery wraps it with its own
// channel.
type ProgressSink func(Event)

// Emitter serializes Events to a single stream as NDJSON, one JSON object per
// line, atomically relative to other writes on the same Emitter. Its Write path
// owns the atomic line discipline only; the caller (scanner.Run) owns Seq/TS
// (D-08). The legacy Emit/Phase/Agent helpers below still self-assign a monotonic
// seq + wall-clock ts for callers that want the Emitter to own sequencing.
type Emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
	seq int
	now func() time.Time
}

// NewEmitter returns an Emitter writing to w (the CLI passes os.Stdout).
func NewEmitter(w io.Writer) *Emitter {
	return &Emitter{enc: json.NewEncoder(w), now: time.Now}
}

// Write serializes one already-populated Event as a single NDJSON line. Seq and
// TS are taken from ev verbatim (the caller owns sequencing, D-08); the Emitter
// only guarantees the write is atomic relative to other Write calls, so
// concurrent sinks never produce a torn line. This is the sequencing-free path a
// ProgressSink uses.
func (e *Emitter) Write(ev Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enc.Encode(ev)
}

// Emit writes one ProgressEvent as a single NDJSON line, self-assigning a
// monotonic seq (from 0) and a wall-clock ts. The write is atomic relative to
// other Emit/Write calls on this Emitter. Prefer Write + caller-owned
// sequencing (D-08); Emit remains for callers that want the Emitter to own seq.
func (e *Emitter) Emit(kind Kind, phase string, agent *string, errs, warnings, assets int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	ev := Event{
		Kind:     kind,
		Seq:      e.seq,
		TS:       float64(e.now().UnixNano()) / 1e9,
		Phase:    phase,
		Agent:    agent,
		Errors:   errs,
		Warnings: warnings,
		Assets:   assets,
	}
	e.seq++
	return e.enc.Encode(ev)
}

// Phase emits a phase lifecycle event (agent is null).
func (e *Emitter) Phase(kind Kind, phase string) error {
	return e.Emit(kind, phase, nil, 0, 0, 0)
}

// Agent emits an agent lifecycle event tagged with the agent/stage name.
func (e *Emitter) Agent(kind Kind, phase, agent string) error {
	return e.Emit(kind, phase, &agent, 0, 0, 0)
}
