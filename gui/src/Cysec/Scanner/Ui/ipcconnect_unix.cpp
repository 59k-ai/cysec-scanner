// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Unix connector: AF_UNIX socket at an absolute path, server identified by
// the kernel's peer credentials. The socket's filesystem permissions are the
// first gate; the peer uid check here is the second, and it is what stops a
// process that bound the path before the real host from receiving the token.

#include "ipcconnect.h"

#include <QLocalSocket>

#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/ucred.h>
#endif

namespace {

// sizeof(sockaddr_un::sun_path) is 104 on macOS and 108 on Linux; one byte
// is the terminating NUL. Use the smaller limit everywhere.
constexpr qsizetype kMaxSocketPathBytes = 103;

IpcServerIdentity peerIdentity(qintptr fd)
{
    IpcServerIdentity id;
    if (fd < 0)
        return id;
    const int s = static_cast<int>(fd);
#if defined(__linux__)
    struct ucred cred{};
    socklen_t len = sizeof(cred);
    if (::getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0 && len == sizeof(cred)) {
        id.pid = cred.pid;
        id.uid = cred.uid;
    }
#elif defined(__APPLE__)
    struct xucred cred{};
    socklen_t len = sizeof(cred);
    if (::getsockopt(s, SOL_LOCAL, LOCAL_PEERCRED, &cred, &len) == 0
        && cred.cr_version == XUCRED_VERSION) {
        id.uid = cred.cr_uid;
    }
    pid_t pid = -1;
    len = sizeof(pid);
    if (::getsockopt(s, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0)
        id.pid = pid;
#else
    uid_t uid = 0;
    gid_t gid = 0;
    if (::getpeereid(s, &uid, &gid) == 0)
        id.uid = uid;
#endif
    return id;
}

} // namespace

IpcServerPolicy IpcServerPolicy::sameUser()
{
    IpcServerPolicy p;
    p.kind = SameUser;
    p.accept = [](const IpcServerIdentity &id) {
        return id.uid >= 0 && id.uid == static_cast<qint64>(::geteuid());
    };
    return p;
}

IpcServerPolicy IpcServerPolicy::privileged()
{
    IpcServerPolicy p;
    p.kind = Privileged;
    p.accept = [](const IpcServerIdentity &id) { return id.uid == 0; };
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
    if (address.isEmpty() || !address.startsWith(QLatin1Char('/')))
        return false;
    if (address.contains(QChar(0)))
        return false;
    return address.toUtf8().size() <= kMaxSocketPathBytes;
}

IpcConnectError ipcConnect(QLocalSocket *socket, const IpcEndpoint &endpoint, int timeoutMs)
{
    if (!socket || !ipcAddressIsValid(endpoint.address))
        return IpcConnectError::InvalidAddress;

    // An absolute name is used as the socket path verbatim; no socket
    // option is set, so Qt never falls back to an abstract name.
    socket->connectToServer(endpoint.address, QIODevice::ReadWrite);
    if (socket->state() != QLocalSocket::ConnectedState && !socket->waitForConnected(timeoutMs)) {
        const QLocalSocket::LocalSocketError err = socket->error();
        socket->abort();
        switch (err) {
        case QLocalSocket::ServerNotFoundError:
        case QLocalSocket::ConnectionRefusedError:
            return IpcConnectError::NotFound;
        case QLocalSocket::SocketAccessError:
            return IpcConnectError::AccessDenied;
        case QLocalSocket::SocketTimeoutError:
            return IpcConnectError::Busy;
        default:
            return IpcConnectError::Other;
        }
    }

    const IpcServerIdentity id = peerIdentity(socket->socketDescriptor());
    if (!endpoint.policy.accept || !endpoint.policy.accept(id)) {
        socket->abort();
        return IpcConnectError::ServerNotTrusted;
    }
    return IpcConnectError::None;
}

std::optional<QByteArray> ipcReadToken(const QString &path, const IpcServerPolicy &policy)
{
    if (path.isEmpty())
        return std::nullopt;
    const QByteArray native = path.toLocal8Bit();
    const int fd = ::open(native.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return std::nullopt;

    struct stat st{};
    bool ok = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode)
              && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0
              && st.st_size <= IpcDetail::kMaxTokenBytes;
    if (ok) {
        switch (policy.kind) {
        case IpcServerPolicy::Privileged:
            ok = st.st_uid == 0;
            break;
        case IpcServerPolicy::SameUser:
            ok = st.st_uid == ::geteuid();
            break;
        case IpcServerPolicy::Custom:
            // A custom server policy still never accepts a token that a
            // third user could have planted.
            ok = st.st_uid == 0 || st.st_uid == ::geteuid();
            break;
        }
    }

    QByteArray raw;
    if (ok) {
        char buf[IpcDetail::kMaxTokenBytes + 1];
        qsizetype total = 0;
        while (total < qsizetype(sizeof(buf))) {
            const ssize_t n = ::read(fd, buf + total, sizeof(buf) - size_t(total));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                ok = n == 0;
                break;
            }
            total += n;
        }
        if (ok)
            raw = QByteArray(buf, total);
        // Do not leave a copy of the secret on the stack.
        volatile char *p = buf;
        for (size_t i = 0; i < sizeof(buf); ++i)
            p[i] = 0;
    }
    ::close(fd);
    if (!ok)
        return std::nullopt;
    return IpcDetail::normalizeToken(std::move(raw));
}
