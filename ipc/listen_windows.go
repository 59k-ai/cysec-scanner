// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

// listen_windows.go is the only place this package creates a named pipe.
//
// go-winio creates the first instance with FILE_CREATE, so a second
// listener on the same name fails instead of silently sharing it, and every
// instance carries FILE_PIPE_REJECT_REMOTE_CLIENTS. The DACL is required:
// the default named-pipe DACL lets Everyone read, which is not acceptable
// for a control channel.

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const localPipePrefix = `\\.\pipe\`

type winPipeListener struct {
	net.Listener
}

func (winPipeListener) Identify() IdentifyFunc { return identifyPeer }

func listen(o ListenOptions) (Listener, error) {
	if err := validPipeAddress(o.Address); err != nil {
		return nil, err
	}
	if o.Pipe.SDDL == "" {
		return nil, fmt.Errorf("%w: a named pipe needs an explicit SDDL", ErrInvalidAddress)
	}
	size := o.Pipe.BufferSize
	if size <= 0 {
		size = DefaultPipeBufferSize
	}
	l, err := winio.ListenPipe(o.Address, &winio.PipeConfig{
		SecurityDescriptor: o.Pipe.SDDL,
		InputBufferSize:    size,
		OutputBufferSize:   size,
	})
	if err != nil {
		// The first instance could not be created: someone else owns the
		// name, either a squatter or a second instance of this host. The
		// caller logs it and retries later.
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) ||
			errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return nil, fmt.Errorf("%w: %s: %v", ErrAddressInUse, o.Address, err)
		}
		return nil, err
	}
	return winPipeListener{l}, nil
}

func validPipeAddress(addr string) error {
	if len(addr) <= len(localPipePrefix) || !strings.EqualFold(addr[:len(localPipePrefix)], localPipePrefix) {
		return fmt.Errorf("%w: pipe address must start with %s", ErrInvalidAddress, localPipePrefix)
	}
	if strings.IndexByte(addr, 0) >= 0 {
		return fmt.Errorf("%w: NUL byte in pipe address", ErrInvalidAddress)
	}
	return nil
}
