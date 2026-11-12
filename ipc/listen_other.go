// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package ipc

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

func listen(ListenOptions) (Listener, error) {
	return nil, fmt.Errorf("%w: no local endpoint on %s", ErrInvalidAddress, runtime.GOOS)
}

// Dial is unavailable on platforms without a local endpoint.
func Dial(context.Context, string) (net.Conn, error) {
	return nil, fmt.Errorf("%w: no local endpoint on %s", ErrInvalidAddress, runtime.GOOS)
}
