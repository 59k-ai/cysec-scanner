// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package runstate

import (
	"net/netip"
	"sort"

	"github.com/59k-ai/cysec-scanner/progress"
)

// DefaultMaxHosts bounds the hosts a RunState keeps. It matches the line cap
// of the GUI host list, so a large scope cannot grow a snapshot past what an
// observer would display anyway.
const DefaultMaxHosts = 10000

// maxOverflowTracked bounds the set used to count distinct hosts beyond the
// cap. Past it, further unseen hosts are still counted, but repeats of them
// may be counted more than once. That keeps memory bounded on a huge scope.
const maxOverflowTracked = 1 << 20

// RunState is the reduced view of one run. The zero value is not usable; a Hub
// creates one per run, and Hub.State returns an independent copy.
//
// Counting rules: every log line at level "warn" or "error" adds one to the
// warning or error count. An agent_done event carries the engine's totals so
// far; the count becomes the larger of the running count and that total, so
// the two sources never add up twice and neither can lower the count.
//
// Hosts are keyed by IP and replaced on every host event for that IP. Once
// maxHosts distinct hosts are stored, new IPs are counted but not stored and
// the truncated flag is set; updates to stored hosts still apply.
type RunState struct {
	maxHosts int

	lastSeq   int
	scanStart *progress.Event

	stageOrder []string
	stages     map[string]progress.Event

	current string

	hosts     map[string]progress.Event
	overflow  map[string]struct{}
	extra     int
	truncated bool

	errors   int
	warnings int

	end *progress.ScanEndInfo
}

func newRunState(maxHosts int) *RunState {
	if maxHosts <= 0 {
		maxHosts = DefaultMaxHosts
	}
	return &RunState{
		maxHosts: maxHosts,
		lastSeq:  -1,
		stages:   make(map[string]progress.Event),
		hosts:    make(map[string]progress.Event),
	}
}

// Apply folds one event into the state.
func (r *RunState) Apply(ev progress.Event) {
	if ev.Seq > r.lastSeq {
		r.lastSeq = ev.Seq
	}
	switch ev.Kind {
	case progress.ScanStart:
		if ev.Scan == nil {
			return
		}
		e := ev
		r.scanStart = &e
		r.stageOrder = r.stageOrder[:0]
		seen := make(map[string]bool, len(ev.Scan.Stages))
		for _, s := range ev.Scan.Stages {
			if !seen[s] {
				seen[s] = true
				r.stageOrder = append(r.stageOrder, s)
			}
		}
		// Stages already reported before this scan_start keep their slot.
		for name := range r.stages {
			if !seen[name] {
				r.stageOrder = append(r.stageOrder, name)
			}
		}
	case progress.StageProgress:
		if ev.Agent == nil || ev.Progress == nil {
			return
		}
		name := *ev.Agent
		if _, ok := r.stages[name]; !ok && !r.inOrder(name) {
			r.stageOrder = append(r.stageOrder, name)
		}
		r.stages[name] = ev
		r.current = name
	case progress.AgentStart:
		if ev.Agent != nil {
			r.current = *ev.Agent
		}
	case progress.AgentDone:
		r.errors = max(r.errors, ev.Errors)
		r.warnings = max(r.warnings, ev.Warnings)
	case progress.Host:
		if ev.Host == nil {
			return
		}
		r.applyHost(ev)
	case progress.Log:
		if ev.Log == nil {
			return
		}
		switch ev.Log.Level {
		case "warn":
			r.warnings++
		case "error":
			r.errors++
		}
	case progress.ScanEnd:
		if ev.ScanEnd != nil {
			end := *ev.ScanEnd
			r.end = &end
		}
	}
}

func (r *RunState) inOrder(name string) bool {
	for _, s := range r.stageOrder {
		if s == name {
			return true
		}
	}
	return false
}

func (r *RunState) applyHost(ev progress.Event) {
	ip := ev.Host.IP
	if _, ok := r.hosts[ip]; ok || len(r.hosts) < r.maxHosts {
		r.hosts[ip] = ev
		return
	}
	r.truncated = true
	if r.overflow == nil {
		r.overflow = make(map[string]struct{})
	}
	if _, ok := r.overflow[ip]; ok {
		return
	}
	if len(r.overflow) < maxOverflowTracked {
		r.overflow[ip] = struct{}{}
		return
	}
	r.extra++
}

// Replay returns the state as a sequence of ordinary events: the scan_start,
// then one stage_progress per stage in stage order, then one host per host in
// IP order. Each is a copy of the event it was reduced from, Seq included, so
// a consumer handles it exactly like a live event.
func (r *RunState) Replay() []progress.Event {
	out := make([]progress.Event, 0, 1+len(r.stages)+len(r.hosts))
	if r.scanStart != nil {
		out = append(out, *r.scanStart)
	}
	for _, name := range r.stageOrder {
		if ev, ok := r.stages[name]; ok {
			out = append(out, ev)
		}
	}
	for _, ip := range r.sortedIPs() {
		out = append(out, r.hosts[ip])
	}
	return out
}

// Hosts returns the stored hosts in IP order and whether hosts were dropped
// because of the cap.
func (r *RunState) Hosts() (hosts []progress.HostSummary, truncated bool) {
	hosts = make([]progress.HostSummary, 0, len(r.hosts))
	for _, ip := range r.sortedIPs() {
		hosts = append(hosts, *r.hosts[ip].Host)
	}
	return hosts, r.truncated
}

// Counts returns the error and warning counts (see the RunState doc) and the
// number of distinct hosts seen, including hosts dropped by the cap.
func (r *RunState) Counts() (errors, warnings, hosts int) {
	return r.errors, r.warnings, len(r.hosts) + len(r.overflow) + r.extra
}

// CurrentStage returns the stage most recently started or reported, with its
// latest counts (zero when the stage has not reported progress yet).
func (r *RunState) CurrentStage() (name string, done, total int) {
	if r.current == "" {
		return "", 0, 0
	}
	if ev, ok := r.stages[r.current]; ok {
		return r.current, ev.Progress.Done, ev.Progress.Total
	}
	return r.current, 0, 0
}

// LastSeq returns the highest Seq applied, or -1 before any event.
func (r *RunState) LastSeq() int { return r.lastSeq }

// End returns the scan_end info, or nil while the scan has not ended.
func (r *RunState) End() *progress.ScanEndInfo {
	if r.end == nil {
		return nil
	}
	end := *r.end
	return &end
}

// clone returns an independent copy. Event values are shared by value; their
// pointer sub-objects are never mutated after publish, so sharing them is safe.
func (r *RunState) clone() *RunState {
	c := *r
	c.stageOrder = append([]string(nil), r.stageOrder...)
	c.stages = make(map[string]progress.Event, len(r.stages))
	for k, v := range r.stages {
		c.stages[k] = v
	}
	c.hosts = make(map[string]progress.Event, len(r.hosts))
	for k, v := range r.hosts {
		c.hosts[k] = v
	}
	if r.overflow != nil {
		c.overflow = make(map[string]struct{}, len(r.overflow))
		for k := range r.overflow {
			c.overflow[k] = struct{}{}
		}
	}
	if r.scanStart != nil {
		s := *r.scanStart
		c.scanStart = &s
	}
	if r.end != nil {
		e := *r.end
		c.end = &e
	}
	return &c
}

// sortedIPs orders host keys by address when both parse, else by string, so
// 10.0.0.9 sorts before 10.0.0.10. Addresses sort before unparsable keys.
func (r *RunState) sortedIPs() []string {
	type key struct {
		s    string
		addr netip.Addr
		ok   bool
	}
	keys := make([]key, 0, len(r.hosts))
	for ip := range r.hosts {
		a, err := netip.ParseAddr(ip)
		keys = append(keys, key{s: ip, addr: a, ok: err == nil})
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		switch {
		case a.ok && b.ok:
			if c := a.addr.Compare(b.addr); c != 0 {
				return c < 0
			}
		case a.ok != b.ok:
			return a.ok
		}
		return a.s < b.s
	})
	ips := make([]string, len(keys))
	for i, k := range keys {
		ips[i] = k.s
	}
	return ips
}
