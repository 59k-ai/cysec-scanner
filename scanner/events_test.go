// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/progress"
)

// TestEmitterSeqContiguousConcurrent proves the emitter stamps a contiguous,
// duplicate-free seq when many goroutines emit at once (run under -race).
func TestEmitterSeqContiguousConcurrent(t *testing.T) {
	const workers, per = 64, 200
	var mu sync.Mutex
	var got []progress.Event
	em := newEventEmitter(func(ev progress.Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	}, true)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				em.log("info", "x")
			}
		}()
	}
	wg.Wait()

	if len(got) != workers*per {
		t.Fatalf("got %d events, want %d", len(got), workers*per)
	}
	// Sink runs under the emitter lock, so delivery order equals seq order.
	for i, ev := range got {
		if ev.Seq != i {
			t.Fatalf("event %d seq = %d (gap or duplicate)", i, ev.Seq)
		}
	}
}

// TestThrottleStageProgress proves the 250 ms per-stage throttle always passes
// a stage's first event and its done==total event, and nothing between.
func TestThrottleStageProgress(t *testing.T) {
	var got []progress.Event
	em := newEventEmitter(func(ev progress.Event) { got = append(got, ev) }, true)
	clock := time.Unix(1_700_000_000, 0)
	em.now = func() time.Time { return clock }

	for d := 1; d <= 999; d++ {
		em.progress("port", d, 1000)
	}
	if len(got) != 1 || got[0].Progress.Done != 1 {
		t.Fatalf("within window got %d events, want only the first", len(got))
	}
	em.progress("port", 1000, 1000)
	if len(got) != 2 || got[1].Progress.Done != 1000 {
		t.Fatalf("done==total not passed: %d events", len(got))
	}

	// Per-stage: another stage's first event is not throttled by "port".
	em.progress("fingerprint", 1, 10)
	if len(got) != 3 || *got[2].Agent != "fingerprint" {
		t.Fatalf("per-stage throttle wrong: %d events", len(got))
	}

	em.progress("fingerprint", 2, 10)
	if len(got) != 3 {
		t.Fatalf("second fingerprint event inside window was not throttled")
	}
	clock = clock.Add(250 * time.Millisecond)
	em.progress("fingerprint", 3, 10)
	if len(got) != 4 || got[3].Progress.Done != 3 {
		t.Fatalf("event after window not passed: %d events", len(got))
	}
	if got[3].Kind != progress.StageProgress {
		t.Errorf("kind = %q", got[3].Kind)
	}
}

// TestSanitiseLogText proves control runes are stripped, length is capped
// rune-aware at 512, whitespace is trimmed, and markup is left verbatim.
func TestSanitiseLogText(t *testing.T) {
	if got := sanitiseLogText("  a\x00b\x1bc\x7fd\ne  "); got != "abcde" {
		t.Errorf("control strip = %q", got)
	}
	long := strings.Repeat("ä", 2000)
	got := sanitiseLogText(long)
	if n := len([]rune(got)); n != 512 {
		t.Errorf("cap = %d runes, want 512", n)
	}
	if !strings.HasPrefix(long, got) {
		t.Error("cap split a rune")
	}
	if got := sanitiseLogText("<img src=x>"); got != "<img src=x>" {
		t.Errorf("markup altered: %q", got)
	}
}

// TestHostSummaryFromAsset proves the asset -> host summary mapping.
func TestHostSummaryFromAsset(t *testing.T) {
	ip, mac, vendor, osg := "192.0.2.4", "aa:bb:cc:dd:ee:ff", "Acme", "Linux"
	conf := 0.9
	prod, ver := "OpenSSH", "9.6"
	a := payload.AssetItem{
		ExternalID: "ip:192.0.2.4", Hostname: "h1", IPAddress: &ip,
		MACAddress: &mac, MACVendor: &vendor, OSGuess: &osg, OSGuessConfidence: &conf,
		Services: []payload.ServiceItem{{Port: 22, Protocol: "tcp", ServiceName: "ssh", Product: &prod, ServiceVersion: &ver}},
	}
	h := hostSummaryFromAsset(a)
	if h.IP != ip || h.ExternalID != a.ExternalID || h.Hostname != "h1" {
		t.Errorf("identity fields = %+v", h)
	}
	if *h.MAC != mac || *h.MACVendor != vendor || *h.OSGuess != osg || *h.OSGuessConfidence != conf {
		t.Errorf("nullable fields = %+v", h)
	}
	if len(h.Services) != 1 {
		t.Fatalf("services = %d", len(h.Services))
	}
	s := h.Services[0]
	if s.Port != 22 || s.Protocol != "tcp" || s.ServiceName != "ssh" || *s.Product != prod || *s.ServiceVersion != ver {
		t.Errorf("service = %+v", s)
	}

	empty := hostSummaryFromAsset(payload.AssetItem{})
	if empty.Services == nil || len(empty.Services) != 0 {
		t.Errorf("empty services = %#v, want non-nil empty", empty.Services)
	}
}
