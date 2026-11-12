// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the only wire protocol revision this package speaks. A
// client announces its revision in session.hello; any other value is refused
// with CodeUnsupportedProtocol so both sides fail loudly instead of guessing.
const ProtocolVersion = 1

// JSONRPCVersion is the literal carried in every envelope.
const JSONRPCVersion = "2.0"

// Request methods (client to server).
const (
	MethodHello           = "session.hello"
	MethodStatusGet       = "status.get"
	MethodRunStart        = "run.start"
	MethodRunCancel       = "run.cancel"
	MethodEventsSubscribe = "events.subscribe"
)

// Notification methods (server to client). Notifications carry no id.
const (
	NotifyProgress       = "progress"
	NotifySnapshotDone   = "snapshot.done"
	NotifyRunState       = "run.state"
	NotifySessionClosing = "session.closing"
)

// Error codes. The first five are the JSON-RPC 2.0 standard codes; the rest
// sit in the implementation-defined server range.
const (
	CodeParse               = -32700
	CodeInvalidRequest      = -32600
	CodeMethodNotFound      = -32601
	CodeInvalidParams       = -32602
	CodeInternal            = -32603
	CodeUnauthenticated     = -32001
	CodeRunInProgress       = -32002
	CodeNotRunning          = -32003
	CodeRunMismatch         = -32004
	CodeUnsupportedProtocol = -32005
	CodeSlowConsumer        = -32010
	CodeShuttingDown        = -32011
)

// Request is a client-to-server line. A request without an id is a
// notification and gets no response.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response answers exactly one request. Exactly one of Result and Error is
// set; ID is null only when the request id could not be read.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Notification is a server-to-client line without an id. On the receiving
// side of Client, Params holds the undecoded json.RawMessage.
type Notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// Error is the JSON-RPC error object. Handlers return *Error to send a
// specific code and message; any other error becomes CodeInternal with a
// fixed message so internal detail never reaches the wire.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("ipc: %d %s", e.Code, e.Message) }

// Endpoint names one side of a session for diagnostics.
type Endpoint struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HelloParams are the session.hello request parameters.
type HelloParams struct {
	Protocol int      `json:"protocol"`
	Token    string   `json:"token"`
	Client   Endpoint `json:"client"`
}

// HelloResult answers a successful session.hello.
type HelloResult struct {
	Protocol int      `json:"protocol"`
	Server   Endpoint `json:"server"`
	Methods  []string `json:"methods"`
}

// ClosingParams are the session.closing notification parameters, sent before
// the server drops a session.
type ClosingParams struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
}
