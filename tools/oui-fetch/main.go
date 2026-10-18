// Command oui-fetch refreshes the vendored IEEE OUI snapshot (MA-L/MA-M/MA-S)
// and the SHA-256 pins recorded in data/allowlist.json. It is the engine of the
// scheduled oui-refresh workflow (D-07): it GETs the three IEEE CSVs, compares
// each against its pin, and — on a diff — rewrites the CSV plus the allowlist
// entry (sha256, upstream_snapshot, fetch_date). The refresh is always a
// reviewable PR, never a live build dependency, so this tool is NEVER invoked
// from the engine build path.
//
// IEEE's Registration Authority rate-limits/blocks non-browser clients and HEAD
// probes with HTTP 418 (RESEARCH Pitfall 1). This tool therefore sends a
// browser-like User-Agent, uses GET (never HEAD), and retries with exponential
// backoff. A persistent failure exits non-zero and fails ONLY the refresh job;
// the pinned snapshot is already vendored, so no build is affected.
//
// Exit codes (the contract the workflow branches on):
//
//	0  — no change (every fetched CSV already matches its pin)
//	10 — changes present and written (the workflow opens a pin-bump PR)
//	1  — hard error (fetch failed, bad status, garbage body, or I/O error)
//
// Usage:
//
//	go run ./tools/oui-fetch [--root .]
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// browserUserAgent is a browser-like UA string. A bare/HEAD request or a
// non-browser UA draws HTTP 418 from standards-oui.ieee.org; a full GET with
// this UA returns the real CSV (RESEARCH Pitfall 1, VERIFIED 2026-10-18).
const browserUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// csvHeaderPrefix is the leading field set of every IEEE OUI CSV. We refuse to
// overwrite a good pin with a truncated/anti-bot error page that lacks it.
const csvHeaderPrefix = "Registry,Assignment"

const (
	exitNoChange = 0
	exitError    = 1
	exitChanged  = 10
)

// Exit codes above are deliberately distinct so a successful "changes present"
// run (10) is never confused with a fetch failure (1).

type entry struct {
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	License          string `json:"license"`
	LicenseNote      string `json:"license_note,omitempty"`
	Copyright        string `json:"copyright,omitempty"`
	ProvenanceURL    string `json:"provenance_url"`
	UpstreamSnapshot string `json:"upstream_snapshot,omitempty"`
	FetchDate        string `json:"fetch_date,omitempty"`
	RegistryBlock    string `json:"registry_block,omitempty"`
	PrefixBits       int    `json:"prefix_bits,omitempty"`
}

type manifest struct {
	SchemaVersion int     `json:"schema_version"`
	Entries       []entry `json:"entries"`
}

func main() {
	root := flag.String("root", ".", "repository root (data/allowlist.json is read/written under it)")
	flag.Parse()
	os.Exit(run(*root, &http.Client{Timeout: 60 * time.Second}))
}

func run(root string, hc *http.Client) int {
	manifestPath := filepath.Join(root, "data", "allowlist.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oui-fetch: read allowlist: %v\n", err)
		return exitError
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		fmt.Fprintf(os.Stderr, "oui-fetch: parse allowlist: %v\n", err)
		return exitError
	}

	today := time.Now().UTC().Format("2006-01-02")
	changed := false

	for i := range m.Entries {
		e := &m.Entries[i]
		if !strings.HasPrefix(e.Path, "data/oui/") {
			continue // only the IEEE OUI snapshot is refreshed here
		}
		body, err := fetch(hc, e.ProvenanceURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "oui-fetch: fetch %s (%s): %v\n", e.Path, e.ProvenanceURL, err)
			return exitError
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(body))
		if sum == e.SHA256 {
			fmt.Printf("oui-fetch: %s unchanged (%s)\n", e.Path, e.RegistryBlock)
			continue
		}
		// A diff: rewrite the vendored CSV and update the pin + dates.
		outPath := filepath.Join(root, filepath.FromSlash(e.Path))
		if err := os.WriteFile(outPath, body, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "oui-fetch: write %s: %v\n", outPath, err)
			return exitError
		}
		fmt.Printf("oui-fetch: %s CHANGED %s -> %s\n", e.Path, e.SHA256, sum)
		e.SHA256 = sum
		e.UpstreamSnapshot = today
		e.FetchDate = today
		changed = true
	}

	if !changed {
		fmt.Println("oui-fetch: no change — every OUI pin already current")
		return exitNoChange
	}

	out, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "oui-fetch: marshal allowlist: %v\n", err)
		return exitError
	}
	out = append(out, '\n')
	if err := os.WriteFile(manifestPath, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "oui-fetch: write allowlist: %v\n", err)
		return exitError
	}
	fmt.Println("oui-fetch: changes present — allowlist pins bumped")
	return exitChanged
}

// fetch GETs url with a browser User-Agent and exponential backoff, retrying a
// transient 418 (anti-bot) or 5xx. It returns an error (not a short file) if no
// attempt yields a 200 with a valid IEEE CSV header, so a diff never overwrites
// a good pin with an anti-bot error page.
func fetch(hc *http.Client, url string) ([]byte, error) {
	const maxAttempts = 4
	var lastErr error
	backoff := 2 * time.Second
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		body, err := fetchOnce(hc, url)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

func fetchOnce(hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUserAgent)
	req.Header.Set("Accept", "text/csv,text/plain,*/*")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// 418 (anti-bot) and 5xx are retryable; a 404 means the URL moved and
		// must surface loudly rather than silently vendoring an error page.
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	if !strings.HasPrefix(string(body), csvHeaderPrefix) {
		return nil, fmt.Errorf("body missing IEEE CSV header %q (anti-bot/truncated?)", csvHeaderPrefix)
	}
	return body, nil
}
