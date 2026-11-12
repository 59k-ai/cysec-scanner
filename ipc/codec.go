// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// Line limits, in bytes, excluding the terminating newline. The pre-auth cap
// keeps an unauthenticated peer from making the server buffer much at all;
// the server write cap keeps every line well under the GUI's read cap.
const (
	MaxPreAuthLine = 4 << 10
	MaxRequestLine = 64 << 10
	MaxServerLine  = 256 << 10
)

// ErrLineTooLong reports a line over the caller's cap. On read the oversize
// line has already been skipped, so the next ReadLine starts on a fresh line.
var ErrLineTooLong = errors.New("ipc: line too long")

// readerChunk is the bufio buffer size. Lines longer than this are assembled
// from several ReadSlice chunks, so memory per line is bounded by the cap
// passed to ReadLine, not by what the peer sends.
const readerChunk = 4 << 10

// LineReader splits a stream into newline-terminated lines with a per-call
// length cap. It is not safe for concurrent use.
type LineReader struct {
	br *bufio.Reader
}

// NewLineReader wraps r.
func NewLineReader(r io.Reader) *LineReader {
	return &LineReader{br: bufio.NewReaderSize(r, readerChunk)}
}

// ReadLine returns the next line without its newline. A carriage return is
// kept, so a CRLF line fails JSON decoding later instead of being silently
// accepted. A line longer than max is discarded through its newline and
// reported as ErrLineTooLong. A final line without a newline is returned at
// EOF; after that ReadLine returns io.EOF.
func (lr *LineReader) ReadLine(max int) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := lr.br.ReadSlice('\n')
		if !tooLong {
			n := len(chunk)
			if err == nil {
				n-- // drop the newline
			}
			if len(line)+n > max {
				tooLong = true
				line = nil
			} else {
				line = append(line, chunk[:n]...)
			}
		}
		switch {
		case err == nil:
			if tooLong {
				return nil, ErrLineTooLong
			}
			if line == nil {
				line = []byte{}
			}
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case tooLong:
			return nil, ErrLineTooLong
		case errors.Is(err, io.EOF) && len(line) > 0:
			return line, nil
		default:
			return nil, err
		}
	}
}

// LineWriter writes one JSON value per line. Each line goes out in a single
// Write call under a mutex, so concurrent writers (responses and
// notifications on one session) can never interleave into a torn line.
type LineWriter struct {
	mu  sync.Mutex
	w   io.Writer
	max int
}

// NewLineWriter wraps w with a per-line cap of max bytes, newline excluded.
func NewLineWriter(w io.Writer, max int) *LineWriter {
	return &LineWriter{w: w, max: max}
}

// WriteJSON marshals v and writes it as one line. json.Marshal escapes any
// newline inside strings, so the value cannot break the framing. A value
// whose encoding exceeds the cap returns ErrLineTooLong and writes nothing:
// a truncated line would be worse than a missing one.
func (lw *LineWriter) WriteJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > lw.max {
		return ErrLineTooLong
	}
	b = append(b, '\n')
	lw.mu.Lock()
	defer lw.mu.Unlock()
	n, err := lw.w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}
