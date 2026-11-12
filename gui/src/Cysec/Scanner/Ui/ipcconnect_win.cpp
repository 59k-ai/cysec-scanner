// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Windows connector: named pipe under \\.\pipe\, opened by this file rather
// than by Qt.
//
// Why not QLocalSocket's own connect: Qt opens the pipe with CreateFile and
// FILE_FLAG_OVERLAPPED only. Without SECURITY_SQOS_PRESENT the client grants
// the default impersonation level, so a non-administrator process that
// created the pipe name before the real host could impersonate an elevated
// GUI. Here the handle is opened with SECURITY_SQOS_PRESENT |
// SECURITY_IDENTIFICATION (the server may identify the client, never act as
// it), the server process is identified and checked against the policy, and
// only then is the handle given to QLocalSocket via setSocketDescriptor.

#include "ipcconnect.h"

#include <QDeadlineTimer>
#include <QFile>
#include <QLocalSocket>

#include <windows.h>
#include <sddl.h>

#include <memory>

namespace {

const QLatin1StringView kPipePrefix("\\\\.\\pipe\\");
constexpr qsizetype kMaxPipeNameChars = 200;
const QLatin1StringView kLocalSystemSid("S-1-5-18");

struct HandleCloser
{
    void operator()(HANDLE h) const
    {
        if (h && h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

QString tokenUserSid(HANDLE process)
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &rawToken))
        return {};
    UniqueHandle token(rawToken);

    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    if (size == 0)
        return {};
    QByteArray buf(qsizetype(size), Qt::Uninitialized);
    if (!GetTokenInformation(token.get(), TokenUser, buf.data(), size, &size))
        return {};
    const auto *user = reinterpret_cast<const TOKEN_USER *>(buf.constData());

    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &text))
        return {};
    const QString sid = QString::fromWCharArray(text);
    LocalFree(text);
    return sid;
}

QString currentUserSid()
{
    return tokenUserSid(GetCurrentProcess());
}

IpcServerIdentity serverIdentity(HANDLE pipe)
{
    IpcServerIdentity id;
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid))
        return id;
    id.pid = qint64(pid);
    UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process)
        return id; // sid stays empty: privileged and same-user both refuse
    id.sid = tokenUserSid(process.get());
    return id;
}

} // namespace

IpcServerPolicy IpcServerPolicy::sameUser()
{
    IpcServerPolicy p;
    p.kind = SameUser;
    p.accept = [](const IpcServerIdentity &id) {
        if (id.sid.isEmpty())
            return false;
        const QString mine = currentUserSid();
        return !mine.isEmpty() && id.sid == mine;
    };
    return p;
}

IpcServerPolicy IpcServerPolicy::privileged()
{
    IpcServerPolicy p;
    p.kind = Privileged;
    p.accept = [](const IpcServerIdentity &id) { return id.sid == kLocalSystemSid; };
    return p;
}

IpcServerPolicy IpcServerPolicy::custom(std::function<bool(const IpcServerIdentity &)> accept)
{
    IpcServerPolicy p;
    p.kind = Custom;
    p.accept = std::move(accept);
    return p;
}

bool ipcAddressIsValid(const QString &address)
{
    if (!address.startsWith(kPipePrefix))
        return false;
    const QStringView name = QStringView(address).mid(kPipePrefix.size());
    if (name.isEmpty() || name.size() > kMaxPipeNameChars)
        return false;
    return !name.contains(QLatin1Char('\\')) && !name.contains(QChar(0));
}

IpcConnectError ipcConnect(QLocalSocket *socket, const IpcEndpoint &endpoint, int timeoutMs)
{
    if (!socket || !ipcAddressIsValid(endpoint.address))
        return IpcConnectError::InvalidAddress;

    const std::wstring path = endpoint.address.toStdWString();
    const QDeadlineTimer deadline(timeoutMs);
    HANDLE h = INVALID_HANDLE_VALUE;
    for (;;) {
        h = CreateFileW(path.c_str(), GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0,
                        nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                        nullptr);
        if (h != INVALID_HANDLE_VALUE)
            break;
        const DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY) {
            const qint64 remaining = deadline.remainingTime();
            if (remaining <= 0)
                return IpcConnectError::Busy;
            // Wait for an instance; a failed wait (timeout) loops back to
            // the deadline check, which then reports Busy.
            WaitNamedPipeW(path.c_str(), DWORD(qMax<qint64>(1, remaining)));
            if (deadline.hasExpired())
                return IpcConnectError::Busy;
            continue;
        }
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            return IpcConnectError::NotFound;
        if (err == ERROR_ACCESS_DENIED)
            return IpcConnectError::AccessDenied;
        return IpcConnectError::Other;
    }

    const IpcServerIdentity id = serverIdentity(h);
    if (!endpoint.policy.accept || !endpoint.policy.accept(id)) {
        CloseHandle(h);
        return IpcConnectError::ServerNotTrusted;
    }

    if (!socket->setSocketDescriptor(reinterpret_cast<qintptr>(h), QLocalSocket::ConnectedState,
                                     QIODevice::ReadWrite)) {
        CloseHandle(h);
        return IpcConnectError::Other;
    }
    return IpcConnectError::None;
}

std::optional<QByteArray> ipcReadToken(const QString &path, const IpcServerPolicy &policy)
{
    // On Windows the token file lives in a directory whose protected ACL
    // admits only SYSTEM and Administrators; the file inherits it. Ownership
    // is therefore not re-checked here.
    Q_UNUSED(policy);
    if (path.isEmpty())
        return std::nullopt;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return std::nullopt;
    if (f.size() > IpcDetail::kMaxTokenBytes)
        return std::nullopt;
    QByteArray raw = f.read(IpcDetail::kMaxTokenBytes + 1);
    return IpcDetail::normalizeToken(std::move(raw));
}
