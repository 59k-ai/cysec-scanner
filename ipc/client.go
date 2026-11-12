// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
)

// Client limits. The read cap matches the GUI client's per-line cap; the
// notification buffer is deep enough for a full snapshot replay.
const (
	MaxClientLine       = 1 << 20
	clientNotifyBacklog = 4096
)

// ErrClientClosed is returned by Call once the connection has ended.
var ErrClientClosed = errors.New("ipc: client closed")

// Client is a minimal Go client for tests and tooling. It is safe for
// concurrent Calls.
type Client struct {
	conn   net.Conn
	w      *LineWriter
	nextID atomic.Int64

	mu      sync.Mutex
	pending map[int64]chan clientReply
	err     error

	notes     chan Notification
	done      chan struct{}
	closeOnce sync.Once
}

type clientReply struct {
	result json.RawMessage
	err    *Error
}

func (r clientReply) decode(out any) error {
	if r.err != nil {
		return r.err
	}
	if out != nil {
		return json.Unmarshal(r.result, out)
	}
	return nil
}

type clientLine struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *Error          `json:"error"`
}

// NewClient starts reading conn. Call Hello before anything else.
func NewClient(conn net.Conn) *Client {
	c := &Client{
		conn:    conn,
		w:       NewLineWriter(conn, MaxRequestLine),
		pending: make(map[int64]chan clientReply),
		notes:   make(chan Notification, clientNotifyBacklog),
		done:    make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *Client) readLoop() {
	defer close(c.notes)
	lr := NewLineReader(c.conn)
	for {
		line, err := lr.ReadLine(MaxClientLine)
		if err != nil {
			c.fail(err)
			return
		}
		var m clientLine
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		if len(m.ID) == 0 && m.Method != "" {
			select {
			case c.notes <- Notification{JSONRPC: JSONRPCVersion, Method: m.Method, Params: m.Params}:
			default:
				// A consumer that cannot keep up gets disconnected rather than
				// stalling the reader, as the server does with slow clients.
				c.fail(errors.New("ipc: notification backlog full"))
				return
			}
			continue
		}
		id, err := strconv.ParseInt(string(m.ID), 10, 64)
		if err != nil {
			continue
		}
		c.mu.Lock()
		ch := c.pending[id]
		delete(c.pending, id)
		c.mu.Unlock()
		if ch != nil {
			ch <- clientReply{result: m.Result, err: m.Error}
		}
	}
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	c.closeOnce.Do(func() {
		c.conn.Close()
		close(c.done)
	})
}

// Hello authenticates the session.
func (c *Client) Hello(ctx context.Context, token string, client Endpoint) (HelloResult, error) {
	var res HelloResult
	err := c.Call(ctx, MethodHello, HelloParams{Protocol: ProtocolVersion, Token: token, Client: client}, &res)
	return res, err
}

// Call sends a request and decodes the result into out (unless out is nil).
// An error response is returned as *Error.
func (c *Client) Call(ctx context.Context, method string, params, out any) error {
	id := c.nextID.Add(1)
	req := Request{JSONRPC: JSONRPCVersion, ID: json.RawMessage(strconv.FormatInt(id, 10)), Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = b
	}
	ch := make(chan clientReply, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return ErrClientClosed
	}
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if err := c.w.WriteJSON(req); err != nil {
		return err
	}
	select {
	case r := <-ch:
		return r.decode(out)
	case <-c.done:
		// A reply may have landed just before the connection ended.
		select {
		case r := <-ch:
			return r.decode(out)
		default:
		}
		return ErrClientClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Notifications delivers server notifications in arrival order; Params holds
// the undecoded json.RawMessage. The channel is closed when the connection
// ends.
func (c *Client) Notifications() <-chan Notification { return c.notes }

// Close ends the connection.
func (c *Client) Close() error {
	c.fail(ErrClientClosed)
	return nil
}
