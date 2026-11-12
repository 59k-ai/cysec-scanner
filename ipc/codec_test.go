// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// TestLineReaderBounds pins the per-line cap: a line of exactly max bytes is
// accepted, one byte more is refused and skipped without desynchronising the
// stream, a final unterminated line is still returned, and CR is not trimmed.
func TestLineReaderBounds(t *testing.T) {
	exact := strings.Repeat("a", 4096)
	over := strings.Repeat("b", 4097)
	input := exact + "\n" + over + "\n" + "next\n" + "crlf\r\n" + "tail"
	r := NewLineReader(strings.NewReader(input))

	got, err := r.ReadLine(4096)
	if err != nil || string(got) != exact {
		t.Fatalf("exact line: err=%v len=%d", err, len(got))
	}
	if _, err := r.ReadLine(4096); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("oversize line: want ErrLineTooLong, got %v", err)
	}
	got, err = r.ReadLine(4096)
	if err != nil || string(got) != "next" {
		t.Fatalf("line after oversize: %q %v", got, err)
	}
	got, err = r.ReadLine(4096)
	if err != nil || string(got) != "crlf\r" {
		t.Fatalf("crlf line: %q %v", got, err)
	}
	got, err = r.ReadLine(4096)
	if err != nil || string(got) != "tail" {
		t.Fatalf("unterminated final line: %q %v", got, err)
	}
	if _, err := r.ReadLine(4096); !errors.Is(err, io.EOF) {
		t.Fatalf("after last line: want io.EOF, got %v", err)
	}
}

// TestLineReaderOversizeAtEOF proves an oversize unterminated tail reports the
// cap and then EOF rather than a truncated line.
func TestLineReaderOversizeAtEOF(t *testing.T) {
	r := NewLineReader(strings.NewReader(strings.Repeat("x", 100)))
	if _, err := r.ReadLine(10); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("want ErrLineTooLong, got %v", err)
	}
	if _, err := r.ReadLine(10); !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
}

// countingWriter records every Write call so the test can prove one call per
// line.
type countingWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	return w.buf.Write(p)
}

// TestLineWriterAtomic proves concurrent writers never tear a line and that an
// oversize value is refused before any byte reaches the stream.
func TestLineWriterAtomic(t *testing.T) {
	cw := &countingWriter{}
	lw := NewLineWriter(cw, 1024)

	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				v := map[string]any{"g": g, "i": i, "pad": strings.Repeat("p", 64), "nl": "a\nb"}
				if err := lw.WriteJSON(v); err != nil {
					t.Errorf("WriteJSON: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(cw.buf.String(), "\n"), "\n")
	if len(lines) != 10000 {
		t.Fatalf("want 10000 lines, got %d", len(lines))
	}
	if cw.writes != 10000 {
		t.Fatalf("want one Write per line (10000), got %d", cw.writes)
	}
	for i, l := range lines {
		var v map[string]any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("line %d does not decode: %v", i, err)
		}
	}

	before := cw.buf.Len()
	err := lw.WriteJSON(map[string]string{"big": strings.Repeat("z", 2048)})
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("oversize: want ErrLineTooLong, got %v", err)
	}
	if cw.buf.Len() != before {
		t.Fatalf("oversize value wrote %d bytes", cw.buf.Len()-before)
	}
}

// TestErrorShape pins the error object and the result/error exclusivity of a
// response envelope.
func TestErrorShape(t *testing.T) {
	e := &Error{Code: CodeRunInProgress, Message: "run already in progress", Data: map[string]string{"run_id": "r1"}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"code":-32002,"message":"run already in progress","data":{"run_id":"r1"}}`; string(b) != want {
		t.Fatalf("error bytes:\n got %s\nwant %s", b, want)
	}
	if got := e.Error(); got != "ipc: -32002 run already in progress" {
		t.Fatalf("Error(): %q", got)
	}

	b, err = json.Marshal(Response{JSONRPC: "2.0", ID: json.RawMessage("7"), Error: &Error{Code: CodeMethodNotFound, Message: "method not found"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"method not found"}}`; string(b) != want {
		t.Fatalf("error response:\n got %s\nwant %s", b, want)
	}

	b, err = json.Marshal(Response{JSONRPC: "2.0", ID: json.RawMessage("8"), Result: map[string]bool{"accepted": true}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"jsonrpc":"2.0","id":8,"result":{"accepted":true}}`; string(b) != want {
		t.Fatalf("result response:\n got %s\nwant %s", b, want)
	}

	b, err = json.Marshal(Notification{JSONRPC: "2.0", Method: NotifySessionClosing, Params: map[string]any{"code": CodeShuttingDown, "reason": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"jsonrpc":"2.0","method":"session.closing","params":{"code":-32011,"reason":"x"}}`; string(b) != want {
		t.Fatalf("notification:\n got %s\nwant %s", b, want)
	}
}
