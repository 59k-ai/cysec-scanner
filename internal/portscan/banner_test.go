// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// startTCPServer starts a loopback TCP listener whose accepted connections are
// handed to handle (each in its own goroutine). It returns the dial address and
// registers cleanup. The listener is test-only — the production read-only guard
// excludes _test.go files.
func startTCPServer(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return ln.Addr().String()
}

// dialLoopback dials the fake server once and returns the client-side conn,
// registering cleanup. grabBanner/tlsPeek read the real bytes off this conn while
// the test chooses the semantic port it wants to exercise.
func dialLoopback(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// bannerTier is a fast banner budget so the silent-server case does not stall the
// suite while still proving the deadline collapses to an empty result.
func bannerTier() Tier {
	return Tier{BannerTimeout: 300 * time.Millisecond}
}

func TestBannerGrab(t *testing.T) {
	ctx := context.Background()

	t.Run("server-speaks-first captures the greeting", func(t *testing.T) {
		addr := startTCPServer(t, func(c net.Conn) {
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = c.Close()
		})
		got := grabBanner(ctx, dialLoopback(t, addr), "127.0.0.1", 22, bannerTier())
		if got.Text != "SSH-2.0-OpenSSH_9.6" {
			t.Fatalf("Text = %q, want %q", got.Text, "SSH-2.0-OpenSSH_9.6")
		}
	})

	t.Run("http port sends a HEAD probe and captures the response", func(t *testing.T) {
		addr := startTCPServer(t, func(c net.Conn) {
			buf := make([]byte, 512)
			n, _ := c.Read(buf)
			if !strings.HasPrefix(string(buf[:n]), "HEAD / HTTP/1.0") {
				// Signal the probe was wrong by sending nothing useful.
				_ = c.Close()
				return
			}
			_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"))
			_ = c.Close()
		})
		got := grabBanner(ctx, dialLoopback(t, addr), "127.0.0.1", 80, bannerTier())
		if !strings.Contains(got.Text, "Server: nginx/1.24.0") {
			t.Fatalf("Text = %q, want it to contain the Server header", got.Text)
		}
	})

	t.Run("unbounded stream truncates to exactly maxBannerBytes", func(t *testing.T) {
		addr := startTCPServer(t, func(c net.Conn) {
			blob := strings.Repeat("A", 100*1024)
			_, _ = c.Write([]byte(blob))
			_ = c.Close()
		})
		got := grabBanner(ctx, dialLoopback(t, addr), "127.0.0.1", 22, bannerTier())
		if len(got.Text) != maxBannerBytes {
			t.Fatalf("len(Text) = %d, want exactly %d", len(got.Text), maxBannerBytes)
		}
	})

	t.Run("silent server yields empty within the deadline", func(t *testing.T) {
		addr := startTCPServer(t, func(c net.Conn) {
			// Hold the connection open without writing until the test closes it.
			time.Sleep(2 * time.Second)
			_ = c.Close()
		})
		start := time.Now()
		got := grabBanner(ctx, dialLoopback(t, addr), "127.0.0.1", 22, bannerTier())
		if got.Text != "" {
			t.Fatalf("Text = %q, want empty on a silent server", got.Text)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("grab took %s, want it bounded near the banner deadline", elapsed)
		}
	})

	t.Run("server that closes immediately yields empty", func(t *testing.T) {
		addr := startTCPServer(t, func(c net.Conn) { _ = c.Close() })
		got := grabBanner(ctx, dialLoopback(t, addr), "127.0.0.1", 22, bannerTier())
		if got.Text != "" {
			t.Fatalf("Text = %q, want empty on an immediate close", got.Text)
		}
	})

	t.Run("non-banner port is never probed", func(t *testing.T) {
		probed := make(chan struct{}, 1)
		addr := startTCPServer(t, func(c net.Conn) {
			// If grabBanner read or wrote, this Read would unblock with data or EOF
			// only after the client acts; a non-banner port must send/read nothing.
			buf := make([]byte, 16)
			if n, _ := c.Read(buf); n > 0 {
				probed <- struct{}{}
			}
			_ = c.Close()
		})
		// Port 3389 (RDP) is not in bannerPorts — no probe must be sent.
		got := grabBanner(ctx, dialLoopback(t, addr), "127.0.0.1", 3389, bannerTier())
		if got.Text != "" {
			t.Fatalf("Text = %q, want empty for a non-banner port", got.Text)
		}
		select {
		case <-probed:
			t.Fatal("a non-banner port must not send a probe")
		case <-time.After(100 * time.Millisecond):
		}
	})
}

// selfSignedCert mints an in-memory self-signed leaf with the given CommonName —
// exactly the kind of cert the TLS peek must read as evidence without validating.
func selfSignedCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSServer wraps a loopback listener in a TLS server presenting cert and
// drives the server-side handshake on each accepted connection. A plain net.Dial
// to the returned address yields a RAW conn the test hands to tlsPeek, which does
// the client handshake — proving the peek needs no second dial of its own.
func startTLSServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsLn := tls.NewListener(ln, cfg)
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = c.Close()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestTLSPeek(t *testing.T) {
	ctx := context.Background()
	tier := Tier{BannerTimeout: time.Second}

	t.Run("reads version + CN despite no chain validation, no second dial", func(t *testing.T) {
		addr := startTLSServer(t, selfSignedCert(t, "printer.local"))
		got := tlsPeek(ctx, dialLoopback(t, addr), "printer.local", tier)
		if !strings.Contains(got.Text, "CN=printer.local") {
			t.Fatalf("Text = %q, want it to contain CN=printer.local", got.Text)
		}
		if !strings.HasPrefix(got.TLSVersion, "TLS") {
			t.Fatalf("TLSVersion = %q, want a negotiated TLS version", got.TLSVersion)
		}
	})

	t.Run("plaintext server on a TLS port fails handshake -> empty, not closed", func(t *testing.T) {
		addr := startTCPServer(t, func(c net.Conn) {
			_, _ = c.Write([]byte("not a tls record\r\n"))
			_ = c.Close()
		})
		got := tlsPeek(ctx, dialLoopback(t, addr), "127.0.0.1", tier)
		if got.Text != "" || got.TLSVersion != "" {
			t.Fatalf("got %+v, want an empty result on a handshake failure", got)
		}
	})

	t.Run("stalled handshake returns empty within the timeout", func(t *testing.T) {
		addr := startTCPServer(t, func(c net.Conn) {
			// Accept the TCP conn but never speak TLS — stall the ClientHello.
			time.Sleep(3 * time.Second)
			_ = c.Close()
		})
		shortTier := Tier{BannerTimeout: 300 * time.Millisecond}
		start := time.Now()
		got := tlsPeek(ctx, dialLoopback(t, addr), "127.0.0.1", shortTier)
		if got.Text != "" || got.TLSVersion != "" {
			t.Fatalf("got %+v, want empty on a stalled handshake", got)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("peek took %s, want it bounded near the handshake timeout", elapsed)
		}
	})
}

func strOrNil(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func TestParseServiceIdentity(t *testing.T) {
	cases := []struct {
		name        string
		banner      string
		wantProduct string // "<nil>" means expect nil
		wantVersion string
	}{
		{"ssh software and version split", "SSH-2.0-OpenSSH_9.6", "OpenSSH", "9.6"},
		{"ssh software only, no interior separator", "SSH-2.0-Dropbear", "Dropbear", "<nil>"},
		{"http server header product", "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n", "nginx/1.24.0", "<nil>"},
		{"no match yields nil pair", "random noise with no identity", "<nil>", "<nil>"},
		{"empty banner yields nil pair", "", "<nil>", "<nil>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			product, version := parseServiceIdentity(0, bannerResult{Text: tc.banner})
			if strOrNil(product) != tc.wantProduct {
				t.Errorf("product = %q, want %q", strOrNil(product), tc.wantProduct)
			}
			if strOrNil(version) != tc.wantVersion {
				t.Errorf("version = %q, want %q", strOrNil(version), tc.wantVersion)
			}
		})
	}
}

func TestBannerHints(t *testing.T) {
	cases := []struct {
		name        string
		banner      string
		wantProduct string
		wantOS      string
	}{
		{"openssh implies linux", "SSH-2.0-OpenSSH_9.6", "", "linux"},
		{"routeros implies a router", "HTTP/1.0 200 OK\r\nServer: Mikrotik RouterOS\r\n", "router", ""},
		{"openwrt product hint", "<html><title>OpenWrt</title></html>", "openwrt", ""},
		{"dvr implies a camera", "var g_dvr = 1; dvr console", "camera", ""},
		{"iis implies windows", "HTTP/1.0 200 OK\r\nServer: Microsoft-IIS/10.0\r\n", "", "windows"},
		{"nothing matches", "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n", "", ""},
		{"empty banner", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ph, oc := bannerHints(0, bannerResult{Text: tc.banner})
			if ph != tc.wantProduct {
				t.Errorf("productHint = %q, want %q", ph, tc.wantProduct)
			}
			if oc != tc.wantOS {
				t.Errorf("osCue = %q, want %q", oc, tc.wantOS)
			}
		})
	}
}

// TestRunServiceIdentityProvenanceEndToEnd drives the REAL portscan.Run against an
// SSH-banner loopback fixture and proves the full dial -> grabBanner ->
// parseServiceIdentity -> ServiceItem.Product -> serviceIdentityProvenance ->
// Evidence flow: both the parsed product/version land on the ServiceItem AND the
// already-wired (04-01) low-confidence provenance keys land on the classification
// evidence map. portscan.go is NOT edited here — only this test file registers the
// fixture's ephemeral port into the banner sets (restored in a defer).
func TestRunServiceIdentityProvenanceEndToEnd(t *testing.T) {
	addr := startTCPServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		_ = c.Close()
	})
	port := mustPort(t, addr)

	// Temporarily make the fixture's ephemeral port a server-speaks-first banner
	// port so the REAL grabBanner reads from it; restore the sets afterwards.
	ssfPrior, ssfHad := serverSpeaksFirst[port]
	bpPrior, bpHad := bannerPorts[port]
	serverSpeaksFirst[port] = true
	bannerPorts[port] = true
	defer func() {
		if ssfHad {
			serverSpeaksFirst[port] = ssfPrior
		} else {
			delete(serverSpeaksFirst, port)
		}
		if bpHad {
			bannerPorts[port] = bpPrior
		} else {
			delete(bannerPorts, port)
		}
	}()

	st := scanstate.New("full", "engine/test")
	seedAsset(st, "127.0.0.1")
	opts := Options{Tier: ResolveTier("polite"), Ports: []int{port}}
	if err := Run(context.Background(), st, capabilities.Capabilities{}, opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	assets := st.Assets()
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(assets))
	}
	a := assets[0]
	if len(a.Services) != 1 {
		t.Fatalf("got %d services, want exactly 1", len(a.Services))
	}
	svc := a.Services[0]
	if svc.Product == nil || *svc.Product != "OpenSSH" {
		t.Errorf("service Product = %v, want OpenSSH (real parseServiceIdentity ran via Run)", strOrNil(svc.Product))
	}
	if svc.ServiceVersion == nil || *svc.ServiceVersion != "9.6" {
		t.Errorf("service ServiceVersion = %v, want 9.6", strOrNil(svc.ServiceVersion))
	}

	if a.Classification == nil {
		t.Fatal("asset has no classification")
	}
	ev := a.Classification.Evidence
	srcKey := "service_identity_source:" + strconv.Itoa(port)
	confKey := "service_identity_confidence:" + strconv.Itoa(port)
	if ev[srcKey] != "port-banner-v1" {
		t.Errorf("%s = %q, want port-banner-v1 (provenance wired upstream)", srcKey, ev[srcKey])
	}
	if ev[confKey] != "low" {
		t.Errorf("%s = %q, want low", confKey, ev[confKey])
	}
}

// mustPort extracts the integer port from a host:port loopback address.
func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}
	return n
}
