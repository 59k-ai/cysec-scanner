// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
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
