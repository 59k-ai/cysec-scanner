// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QString>
#include <QtGlobal>

#include <functional>

// Description of a local IPC host the GUI may connect to.
//
// The address is a filesystem endpoint only: an absolute AF_UNIX socket path
// on Linux and macOS, or a \\.\pipe\ name on Windows. Abstract socket names
// are never used, because any local user can bind them first.
//
// The server policy decides which process may sit behind the endpoint. It is
// checked by the connector after the transport is open and before the GUI
// writes a single byte, so a process that squatted the endpoint never sees
// the token.
//
// Everything product specific (address, token file, client name) is injected
// by the embedding application; this module carries no defaults for it.

struct IpcServerIdentity
{
    qint64 pid = -1; // server process id, -1 when the OS did not report one
    qint64 uid = -1; // Unix: effective uid of the server, -1 when unknown
    QString sid;     // Windows: string SID of the server process token user
};

struct IpcServerPolicy
{
    enum Kind {
        SameUser,   // the server runs as the same user as the GUI
        Privileged, // Unix uid 0; Windows LocalSystem (S-1-5-18)
        Custom,     // the injected accept() alone decides
    };

    Kind kind = Privileged;
    // Returns true when the identified server may be trusted. An empty
    // function refuses every server.
    std::function<bool(const IpcServerIdentity &)> accept;

    static IpcServerPolicy sameUser();
    static IpcServerPolicy privileged();
    static IpcServerPolicy custom(std::function<bool(const IpcServerIdentity &)> accept);
};

struct IpcEndpoint
{
    QString address;
    QString tokenFile;
    IpcServerPolicy policy = IpcServerPolicy::privileged();
    QString clientName;
    QString clientVersion;
};
