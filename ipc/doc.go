// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package ipc is a local, filesystem-only control-and-observe channel between
// a long-running scanner host and a GUI on the same machine.
//
// The wire format is JSON-RPC 2.0 shaped and framed as NDJSON: one UTF-8 JSON
// object per newline-terminated line, in both directions. Progress
// notifications embed the unchanged progress.Event object, so this package
// extends the existing NDJSON event stream rather than replacing it.
//
// Every session must authenticate before any method runs. The first line has
// to be a session.hello request carrying an opaque capability token, and the
// connecting peer's operating-system identity is checked by a host-supplied
// authorizer. Both factors must pass. The token is a local bearer secret that
// only privileged local principals can read; it never travels off the host.
//
// The package never opens a network listener. A Server consumes a
// net.Listener handed to it by the host, and all product-specific names,
// paths, principals and token prefixes are injected through options. The scan
// engine never imports this package: only a host process that drives the
// engine and serves a GUI does.
package ipc
