// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly || windows)

package main

import (
	"errors"

	"github.com/59k-ai/cysec-scanner/ipc"
)

var errUnsupported = errors.New("the reference host does not support this platform")

func acquireLock(string) (func(), error) { return nil, errUnsupported }

func listenOptions(string) (ipc.ListenOptions, error) { return ipc.ListenOptions{}, errUnsupported }
