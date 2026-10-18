// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package portscan is the pipeline's port-scan stage (PORT-01/PORT-02/PORT-04/
// PORT-05). It reads the live hosts the discovery stage recorded in the shared
// accumulator, connect-probes a curated set of TCP ports over an unprivileged
// dial (no raw socket, no CGO), grabs a bounded plaintext banner on each open
// port, classifies the host, and MERGES services plus a refined classification
// back into the same AssetItem the discovery stage populated.
//
// Load shaping (PORT-02, D-04): every connect passes a SINGLE scan-wide token
// bucket (one shared rate.Limiter, never per host) before acquiring a bounded
// worker-pool slot — the semaphore caps in-flight sockets, the limiter caps the
// packets-per-second rate, and both are required. Each probe reports a graded
// outcome (open/refused/timeout/error) into one shared sliding window that the
// adaptive-backoff hook reads (D-05), so a later plan fills the throttle-down
// logic in timing.go without re-touching this orchestrator.
//
// Provenance (D-08): every value this stage writes is low-confidence and
// source-labeled in the classification evidence map, so a later higher-fidelity
// stage can override it. The compliance verdict itself is never decided here.
//
// The pipeline control-flow package and its StageFunc signature are untouched
// (D-12): the stage is a closure built in main.go that captures the accumulator.
package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/time/rate"

	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/oui"
	"github.com/cysec-watch/cysec-scanner/internal/payload"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// Options carries the resolved per-scan settings: the timing tier (load budget)
// and the set of TCP ports to probe per host.
type Options struct {
	Tier  Tier
	Ports []int
}

// probe is the injectable connect-probe seam, mirroring discovery's sweep seam so
// tests can drive graded outcomes and banners without real packets. It returns a
// graded outcome and (on an open port) the captured banner.
var probe = dialProbe

// adjustRate is the injectable adaptive-backoff call site. The default delegates
// to the tier's Adjust hook; a test swaps it to observe that Run feeds the window
// and invokes the hook, and a later plan fills Tier.Adjust without touching Run.
var adjustRate = func(t Tier, l *rate.Limiter, w *outcomeWindow) { t.Adjust(l, w) }

// openPort is one open port on a host, carrying the banner captured from it.
type openPort struct {
	port   int
	banner bannerResult
}

// workItem is one (asset, host, port) probe target.
type workItem struct {
	assetID string
	host    string
	port    int
}

// Run executes the port stage over the accumulator's discovered assets. It
// returns nil on an empty asset set (no work, no mutation, no hang) so a
// fully-degraded run still yields a complete, strict-valid payload. Each open
// port becomes exactly one ServiceItem under its asset, emitted in ascending port
// order, and a merged classification is written back under the accumulator lock.
func Run(ctx context.Context, st *scanstate.ScanState, caps capabilities.Capabilities, opts Options) error {
	_ = caps // capabilities reserved for later privileged probe paths

	assets := st.Assets()
	if len(assets) == 0 {
		return nil
	}

	// Build the flat (asset,host,port) work list from each asset's IP × ports.
	var items []workItem
	for _, a := range assets {
		if a.IPAddress == nil || *a.IPAddress == "" {
			continue
		}
		for _, p := range opts.Ports {
			items = append(items, workItem{assetID: a.ExternalID, host: *a.IPAddress, port: p})
		}
	}
	if len(items) == 0 {
		return nil
	}

	// One shared token bucket (scan-wide PPS ceiling, D-04), one bounded worker
	// pool (in-flight socket cap), and one shared outcome window the backoff hook
	// reads. The semaphore alone is not a rate cap, so both gates are present.
	limiter := rate.NewLimiter(rate.Limit(opts.Tier.PPS), opts.Tier.Burst)
	sem := make(chan struct{}, opts.Tier.Workers)
	window := newOutcomeWindow(opts.Tier.BackoffWindow)

	var wg sync.WaitGroup
	var mu sync.Mutex
	openByAsset := map[string][]openPort{}

	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		// Gate every connect on the scan-wide PPS ceiling BEFORE taking a worker
		// slot (D-04): the limiter is the rate, the pool is the fd bound.
		if err := limiter.Wait(ctx); err != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it workItem) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			outcome, banner := probe(ctx, it.host, it.port, opts.Tier)
			mu.Lock()
			window.record(outcome)
			if outcome == outcomeOpen {
				openByAsset[it.assetID] = append(openByAsset[it.assetID], openPort{port: it.port, banner: banner})
			}
			// Drive the adaptive-backoff hook on the live limiter under the same
			// lock that guards the window (no-op this phase).
			adjustRate(opts.Tier, limiter, window)
			mu.Unlock()
		}(it)
	}
	wg.Wait()

	// Per asset: assemble services + classification deterministically and merge
	// them back under the accumulator lock.
	for id, ports := range openByAsset {
		finalizeAsset(st, id, ports)
	}
	return nil
}

// finalizeAsset builds the sorted service list and classification verdict for one
// asset's open ports and merges them into the accumulator.
func finalizeAsset(st *scanstate.ScanState, externalID string, ports []openPort) {
	sort.Slice(ports, func(i, j int) bool { return ports[i].port < ports[j].port })

	openPorts := make([]int, 0, len(ports))
	bannersByPort := map[int]bannerResult{}
	services := make([]payload.ServiceItem, 0, len(ports))
	for _, op := range ports {
		openPorts = append(openPorts, op.port)
		bannersByPort[op.port] = op.banner
		product, version := parseServiceIdentity(op.port, op.banner)
		services = append(services, payload.ServiceItem{
			Port:           op.port,
			Protocol:       "tcp",
			ServiceName:    serviceNameByPort[op.port],
			ExposureLevel:  "internal",
			TLSVersion:     op.banner.TLSVersion,
			Product:        product,
			ServiceVersion: version,
		})
	}

	// Single aggregated product/OS hint by ascending-port precedence (D-10): the
	// lowest-numbered open port supplying a non-empty hint wins.
	productHint, osCue := aggregateHints(openPorts, func(p int) (string, string) {
		return bannerHints(p, bannersByPort[p])
	})

	textBanners := map[int]string{}
	for p, b := range bannersByPort {
		textBanners[p] = b.Text
	}

	// Stash the already-captured text banners on the off-wire side-channel so the
	// fingerprint stage can match them without a second dial. A pure addition: it
	// does not change the classify/merge behavior below, and raw banners never
	// reach the wire payload.
	st.SetServiceBanners(externalID, textBanners)

	st.UpdateAsset(externalID, func(a *payload.AssetItem) {
		in := classifyInput{
			OpenPorts:        openPorts,
			Banners:          textBanners,
			ProductHint:      productHint,
			OSCue:            osCue,
			OUIVendor:        vendorFor(a.MACAddress),
			ExistingEvidence: existingEvidence(a),
		}
		a.Services = mergeServices(a.Services, services)
		mergeVerdict(a, classify(in))
		// Service-identity provenance rides the classification evidence map, never
		// a new wire field (D-07/D-08/D-12). mergeVerdict already made Evidence
		// non-nil, so these keys land safely.
		for k, v := range serviceIdentityProvenance(services) {
			a.Classification.Evidence[k] = v
		}
	})
}

// aggregateHints reduces the per-port banner hints to a single product hint and a
// single OS cue by ascending-port precedence: the lowest-numbered open port that
// supplies a non-empty hint wins for each, independently. The result is fully
// deterministic for a given open-port set (D-10).
func aggregateHints(openPorts []int, hint func(port int) (productHint, osCue string)) (productHint, osCue string) {
	sorted := append([]int(nil), openPorts...)
	sort.Ints(sorted)
	for _, p := range sorted {
		ph, oc := hint(p)
		if productHint == "" && ph != "" {
			productHint = ph
		}
		if osCue == "" && oc != "" {
			osCue = oc
		}
		if productHint != "" && osCue != "" {
			break
		}
	}
	return productHint, osCue
}

// serviceIdentityProvenance emits the D-08 source/confidence labels for every
// service that carries a parsed product or service version. This is the single
// place the port stage labels a Phase-4 product/version value (low confidence,
// source "port-banner-v1") — written onto the classification evidence map, never
// a new wire field. It returns an empty map when nothing parsed, which is the
// reality until the banner parser is filled in a later plan.
func serviceIdentityProvenance(services []payload.ServiceItem) map[string]string {
	out := map[string]string{}
	for _, s := range services {
		if s.Product == nil && s.ServiceVersion == nil {
			continue
		}
		port := strconv.Itoa(s.Port)
		out["service_identity_source:"+port] = classifySource
		out["service_identity_confidence:"+port] = "low"
	}
	return out
}

// dialProbe is the default connect probe: it dials with the tier's connect
// deadline and, on success, grabs a bounded banner; on a dial error it grades the
// failure and never grabs a banner. It never raises — every error path returns a
// graded outcome. The host is one of our own scope-enumerated addresses passed as
// a discrete argument (no shell), so there is no injection surface.
func dialProbe(ctx context.Context, host string, port int, tier Tier) (probeOutcome, bannerResult) {
	d := net.Dialer{Timeout: tier.ConnectTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return classifyDialError(err), bannerResult{}
	}
	defer conn.Close()
	return outcomeOpen, grabBanner(ctx, conn, host, port, tier)
}

// wsaeconnrefused is the winsock error code (WSAECONNREFUSED, 10061) a refused
// connect surfaces on Windows. The Go stdlib's syscall.ECONNREFUSED is a
// separate invented constant there and Errno.Is does not bridge the two, so a
// genuine Windows RST must be matched on the raw errno explicitly.
const wsaeconnrefused = syscall.Errno(10061)

// isConnRefused reports whether a dial error is a refused connection on any
// platform: errors.Is handles the POSIX ECONNREFUSED chain, and a direct errno
// comparison catches the Windows winsock code (WSAECONNREFUSED, 10061) that
// errors.Is does not map. The errno comparison is a plain integer check that
// compiles and runs on every platform, so the Windows path is testable on Linux.
func isConnRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == wsaeconnrefused
}

// classifyDialError grades a dial failure so the backoff can tell a healthy
// network from a stressed one: a fast RST (refused — POSIX ECONNREFUSED or
// Windows WSAECONNREFUSED, matched via isConnRefused) is a reachable closed
// port, a timeout (deadline or net.Error timeout) is filtered/ambiguous, and
// anything else is the genuine-stress bucket.
func classifyDialError(err error) probeOutcome {
	if err == nil {
		return outcomeOpen
	}
	if isConnRefused(err) {
		return outcomeRefused
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return outcomeTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return outcomeTimeout
	}
	return outcomeError
}

// mergeServices appends newly-discovered services to the existing list, skipping
// any port already present so a probed port is never double-counted.
func mergeServices(existing, added []payload.ServiceItem) []payload.ServiceItem {
	if existing == nil {
		existing = []payload.ServiceItem{}
	}
	seen := map[int]bool{}
	for _, s := range existing {
		seen[s.Port] = true
	}
	for _, s := range added {
		if seen[s.Port] {
			continue
		}
		seen[s.Port] = true
		existing = append(existing, s)
	}
	return existing
}

// vendorFor resolves the OUI vendor for an asset MAC, or nil when none.
func vendorFor(mac *string) *string {
	if mac == nil || *mac == "" {
		return nil
	}
	return oui.LookupVendor(*mac)
}

// existingEvidence returns a copy of the asset's current classification evidence
// (nil-safe), so the classifier can read discovery's signals without aliasing.
func existingEvidence(a *payload.AssetItem) map[string]string {
	if a.Classification == nil || a.Classification.Evidence == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(a.Classification.Evidence))
	for k, v := range a.Classification.Evidence {
		out[k] = v
	}
	return out
}
