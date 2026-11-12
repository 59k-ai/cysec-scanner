// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ipcendpoint.h"

#include <QByteArray>
#include <QLocalSocket>
#include <QString>

#include <optional>

// Per-OS connectors for the local IPC host (ipcconnect_unix.cpp,
// ipcconnect_win.cpp; exactly one is compiled).
//
// ipcConnect opens the endpoint, identifies the server process and applies
// the endpoint's policy. On success the socket is connected and nothing has
// been written yet; on any failure the socket is left unconnected.
//
// ipcReadToken reads the shared secret the GUI presents in session.hello.
// The file is re-read on every connect, so a host that minted a new token at
// restart is picked up without restarting the GUI. On Unix a token file that
// is group or world writable, or that is not owned by the principal the
// policy expects, is refused. The token is never logged.

enum class IpcConnectError {
    None,
    InvalidAddress,
    NotFound,
    Busy,
    AccessDenied,
    ServerNotTrusted,
    Other,
};

IpcConnectError ipcConnect(QLocalSocket *socket, const IpcEndpoint &endpoint, int timeoutMs);

bool ipcAddressIsValid(const QString &address);

std::optional<QByteArray> ipcReadToken(const QString &path, const IpcServerPolicy &policy);

namespace IpcDetail {

constexpr qsizetype kMaxTokenBytes = 512;

// Trims one trailing newline (LF or CRLF) and requires a non-empty run of
// printable ASCII without spaces. Returns nullopt otherwise.
inline std::optional<QByteArray> normalizeToken(QByteArray raw)
{
    if (raw.size() > kMaxTokenBytes)
        return std::nullopt;
    if (raw.endsWith('\n')) {
        raw.chop(1);
        if (raw.endsWith('\r'))
            raw.chop(1);
    }
    if (raw.isEmpty())
        return std::nullopt;
    for (char c : std::as_const(raw)) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x21 || u > 0x7e)
            return std::nullopt;
    }
    return raw;
}

} // namespace IpcDetail
