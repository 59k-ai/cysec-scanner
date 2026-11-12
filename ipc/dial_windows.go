// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// dialAccess is the access a client asks for. It stays inside the
// administrators ACE of AdminPipeSDDL: GENERIC_WRITE would include
// FILE_CREATE_PIPE_INSTANCE, which that ACE withholds on purpose.
const dialAccess = windows.GENERIC_READ | windows.FILE_WRITE_DATA | windows.FILE_WRITE_ATTRIBUTES

// Dial connects to a local named pipe created by Listen. The client offers
// only an identification-level token (SECURITY_SQOS_PRESENT |
// SECURITY_IDENTIFICATION): the server can read who the client is, but a
// squatting server could not act as the client.
func Dial(ctx context.Context, address string) (net.Conn, error) {
	if err := validPipeAddress(address); err != nil {
		return nil, err
	}
	return winio.DialPipeAccessImpLevel(ctx, address, dialAccess, winio.PipeImpLevelIdentification)
}
