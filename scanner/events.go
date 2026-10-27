// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"sync"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/progress"
)

// progressThrottle is the minimum spacing between two stage_progress events of
// the same stage (T-13-05): a /16 sweep would otherwise flood the consumer.
const progressThrottle = 250 * time.Millisecond

// maxLogRunes caps a log message (T-13-04). Rune-aware so a multi-byte rune is
// never split.
const maxLogRunes = 512

// eventEmitter is the single owner of progress sequencing for one Run (D-08,
// D-26). Stages report concurrently via the ScanState observer, so stamping
// Seq/TS AND invoking the sink happen under one mutex: the sink is never called
// concurrently and delivery order equals Seq order. The sink must therefore not
// call back into the emitter.
type eventEmitter struct {
	mu           sync.Mutex
	seq          int
	sink         ProgressSink
	detailed     bool
	now          func() time.Time
	lastProgress map[string]time.Time
}

// newEventEmitter returns an emitter delivering to sink (nil = discard, Seq
// still advances). detailed gates every opt-in kind (D-05).
func newEventEmitter(sink ProgressSink, detailed bool) *eventEmitter {
	return &eventEmitter{
		sink:         sink,
		detailed:     detailed,
		now:          time.Now,
		lastProgress: map[string]time.Time{},
	}
}

// emit stamps Seq/TS on ev and delivers it under the lock.
func (em *eventEmitter) emit(ev progress.Event) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.emitLocked(ev)
}

func (em *eventEmitter) emitLocked(ev progress.Event) {
	ev.Seq = em.seq
	ev.TS = float64(em.now().UnixNano()) / 1e9
	em.seq++
	if em.sink != nil {
		em.sink(ev)
	}
}

// lifecycle emits a legacy phase_*/agent_* event (always, in both modes).
func (em *eventEmitter) lifecycle(kind progress.Kind, agent *string, assets int) {
	em.emit(progress.Event{Kind: kind, Phase: "collect", Agent: agent, Assets: assets})
}

// progress emits a throttled stage_progress event. The first event of a stage
// and its done==total event always pass; others pass once progressThrottle has
// elapsed since that stage's last emitted event.
func (em *eventEmitter) progress(stage string, done, total int) {
	if !em.detailed {
		return
	}
	em.mu.Lock()
	defer em.mu.Unlock()
	now := em.now()
	last, seen := em.lastProgress[stage]
	if seen && done != total && now.Sub(last) < progressThrottle {
		return
	}
	em.lastProgress[stage] = now
	name := stage
	em.emitLocked(progress.Event{
		Kind: progress.StageProgress, Phase: "collect", Agent: &name,
		Progress: &progress.StageCounts{Done: done, Total: total},
	})
}

// host emits a host event.
func (em *eventEmitter) host(h progress.HostSummary) {
	if !em.detailed {
		return
	}
	em.emit(progress.Event{Kind: progress.Host, Phase: "collect", Host: &h})
}

// log emits a sanitised log event.
func (em *eventEmitter) log(level, msg string) {
	if !em.detailed {
		return
	}
	em.emit(progress.Event{
		Kind: progress.Log, Phase: "collect",
		Log: &progress.LogLine{Level: level, Message: sanitiseLogText(msg)},
	})
}

// scanStart emits scan_start. scope is copied into a non-nil slice.
func (em *eventEmitter) scanStart(scope, stages []string, caps capabilities.Capabilities) {
	if !em.detailed {
		return
	}
	em.emit(progress.Event{
		Kind: progress.ScanStart, Phase: "collect",
		Scan: &progress.ScanInfo{
			Scope:  append([]string{}, scope...),
			Stages: append([]string{}, stages...),
			Capabilities: progress.CapabilityInfo{
				UnprivilegedICMP: caps.UnprivilegedICMP,
				SystemPing:       caps.SystemPing,
				ARPCache:         caps.ARPCache,
			},
		},
	})
}

// scanEnd emits scan_end. errText is set only for status "failed".
func (em *eventEmitter) scanEnd(status string, errText *string, assets int) {
	if !em.detailed {
		return
	}
	em.emit(progress.Event{
		Kind: progress.ScanEnd, Phase: "collect",
		ScanEnd: &progress.ScanEndInfo{Status: status, Error: errText, Assets: assets},
	})
}

// sanitiseLogText strips control runes (below 0x20 and DEL), caps the length at
// maxLogRunes without splitting a rune, and trims surrounding whitespace. It
// mirrors the engine's hostname sanitiser. Markup is left verbatim — rendering
// safety is the consumer's job.
func sanitiseLogText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if n >= maxLogRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// hostSummaryFromAsset maps an accumulated asset to its compact wire view.
func hostSummaryFromAsset(a payload.AssetItem) progress.HostSummary {
	h := progress.HostSummary{
		ExternalID:        a.ExternalID,
		Hostname:          a.Hostname,
		MAC:               a.MACAddress,
		MACVendor:         a.MACVendor,
		OSGuess:           a.OSGuess,
		OSGuessConfidence: a.OSGuessConfidence,
		Services:          make([]progress.ServiceSummary, 0, len(a.Services)),
	}
	if a.IPAddress != nil {
		h.IP = *a.IPAddress
	}
	for _, s := range a.Services {
		h.Services = append(h.Services, progress.ServiceSummary{
			Port:           s.Port,
			Protocol:       s.Protocol,
			ServiceName:    s.ServiceName,
			Product:        s.Product,
			ServiceVersion: s.ServiceVersion,
		})
	}
	return h
}

// observerFor adapts the accumulator's observer hooks onto the emitter.
func observerFor(em *eventEmitter) *scanstate.Observer {
	return &scanstate.Observer{
		OnAsset: func(a payload.AssetItem) {
			if a.IPAddress == nil || *a.IPAddress == "" {
				return
			}
			em.host(hostSummaryFromAsset(a))
		},
		OnProgress: em.progress,
		OnHostSeen: func(ip string) {
			em.host(progress.HostSummary{IP: ip, Services: []progress.ServiceSummary{}})
		},
		OnLog: em.log,
	}
}
