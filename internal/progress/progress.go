// Package progress emits NDJSON ProgressEvent objects on an output stream,
// mirroring the cysec.watch Collector-side ProgressEvent wire contract.
//
// One complete JSON object is written per line and NOTHING else is written to
// that stream — no banners, no log lines, no payload. The engine wires this to
// os.Stdout; all logging goes to os.Stderr via slog. Every Emit is guarded by a
// mutex and uses json.Encoder.Encode, which writes one whole object followed by
// a newline, so concurrent emits can never interleave into a torn line
// (ENG-02).
package progress

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Kind is the coarse progress taxonomy; its value is the JSON wire string. The
// values mirror EventKind in progress.py (phase_start/phase_done/agent_start/
// agent_done).
type Kind string

const (
	PhaseStart Kind = "phase_start"
	PhaseDone  Kind = "phase_done"
	AgentStart Kind = "agent_start"
	AgentDone  Kind = "agent_done"
)

// event is the on-the-wire shape; keys mirror progress.py to_dict exactly. Agent
// is a pointer so it marshals to JSON null on phase_* events (agent is None in
// the Python model on those).
type event struct {
	Kind     Kind    `json:"kind"`
	Seq      int     `json:"seq"`
	TS       float64 `json:"ts"`
	Phase    string  `json:"phase"`
	Agent    *string `json:"agent"`
	Errors   int     `json:"errors"`
	Warnings int     `json:"warnings"`
	Assets   int     `json:"assets"`
}

// Emitter writes NDJSON ProgressEvents to a single stream with a monotonic,
// contiguous seq starting at 0 within its lifetime.
type Emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
	seq int
	now func() time.Time
}

// NewEmitter returns an Emitter writing to w (the engine passes os.Stdout).
func NewEmitter(w io.Writer) *Emitter {
	return &Emitter{enc: json.NewEncoder(w), now: time.Now}
}

// Emit writes one ProgressEvent as a single NDJSON line. The write is atomic
// relative to other Emit calls on this Emitter.
func (e *Emitter) Emit(kind Kind, phase string, agent *string, errors, warnings, assets int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	ev := event{
		Kind:     kind,
		Seq:      e.seq,
		TS:       float64(e.now().UnixNano()) / 1e9,
		Phase:    phase,
		Agent:    agent,
		Errors:   errors,
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
