// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "ipcchannel.h"

#include "ipcconnect.h"

#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonValue>
#include <QList>
#include <QLocalSocket>

#include <algorithm>
#include <climits>
#include <cmath>

namespace {

constexpr int kProtocolVersion = 1;
constexpr int kConnectTimeoutMs = 2000;
// The host closes a session that has not authenticated within 5 s; this is
// only a backstop for a host that accepts and then says nothing.
constexpr int kHelloTimeoutMs = 10000;

constexpr int kErrUnauthenticated = -32001;
constexpr int kErrUnsupportedProtocol = -32005;
constexpr int kErrShuttingDown = -32011;

// JSON numbers are doubles; an id or code is accepted only when it is an
// exact integer inside the range a double represents without loss.
bool integral(const QJsonValue &v, qint64 *out)
{
    if (!v.isDouble())
        return false;
    const double d = v.toDouble();
    if (!std::isfinite(d) || std::trunc(d) != d || std::fabs(d) > 9007199254740992.0)
        return false;
    *out = static_cast<qint64>(d);
    return true;
}

void wipe(QByteArray &bytes)
{
    bytes.fill('\0');
    bytes.clear();
}

} // namespace

IpcChannel::IpcChannel(IpcEndpoint endpoint, QObject *parent)
    : QObject(parent)
    , m_endpoint(std::move(endpoint))
{
    m_reconnectTimer.setSingleShot(true);
    connect(&m_reconnectTimer, &QTimer::timeout, this, &IpcChannel::attempt);
    m_helloTimer.setSingleShot(true);
    m_helloTimer.setInterval(kHelloTimeoutMs);
    connect(&m_helloTimer, &QTimer::timeout, this, &IpcChannel::onHelloTimeout);
}

IpcChannel::~IpcChannel()
{
    m_wantOpen = false;
    m_reconnectTimer.stop();
    m_helloTimer.stop();
    if (m_socket) {
        disconnect(m_socket, nullptr, this, nullptr);
        m_socket->abort();
    }
}

void IpcChannel::open()
{
    if (m_wantOpen && m_state != Disconnected)
        return;
    m_wantOpen = true;
    m_backoffMs = m_backoffInitialMs;
    m_reconnectTimer.stop();
    attempt();
}

void IpcChannel::close()
{
    m_wantOpen = false;
    m_reconnectTimer.stop();
    teardown();
    setState(Disconnected);
}

IpcChannel::State IpcChannel::state() const
{
    return m_state;
}

IpcChannel::Failure IpcChannel::lastFailure() const
{
    return m_lastFailure;
}

QJsonObject IpcChannel::helloResult() const
{
    return m_helloResult;
}

void IpcChannel::setBackoff(int initialMs, int maxMs)
{
    m_backoffInitialMs = std::max(1, initialMs);
    m_backoffMaxMs = std::max(m_backoffInitialMs, maxMs);
    m_backoffMs = m_backoffInitialMs;
}

qint64 IpcChannel::call(const QString &method, const QJsonObject &params)
{
    if (m_state != Ready || !m_socket)
        return -1;
    const qint64 id = m_nextId++;
    const QJsonObject message{{QStringLiteral("jsonrpc"), QStringLiteral("2.0")},
                              {QStringLiteral("id"), id},
                              {QStringLiteral("method"), method},
                              {QStringLiteral("params"), params}};
    if (!writeMessage(message))
        return -1;
    m_pending.insert(id);
    return id;
}

void IpcChannel::attempt()
{
    if (!m_wantOpen)
        return;
    setState(Connecting);

    // A malformed address cannot become valid by waiting: no retry.
    if (!ipcAddressIsValid(m_endpoint.address)) {
        fail(ServiceUnavailable, Retry::No);
        return;
    }
    // A missing token file means the host is not running (yet).
    if (!QFileInfo::exists(m_endpoint.tokenFile)) {
        fail(ServiceUnavailable, Retry::Yes);
        return;
    }
    std::optional<QByteArray> token = ipcReadToken(m_endpoint.tokenFile, m_endpoint.policy);
    if (!token) {
        fail(NotAuthorized, Retry::Yes);
        return;
    }

    auto *socket = new QLocalSocket(this);
    const IpcConnectError err = ipcConnect(socket, m_endpoint, kConnectTimeoutMs);
    if (err != IpcConnectError::None) {
        delete socket;
        wipe(*token);
        fail(err == IpcConnectError::ServerNotTrusted ? ServerNotTrusted : ServiceUnavailable,
             Retry::Yes);
        return;
    }

    ++m_generation;
    m_socket = socket;
    m_lines.reset();
    connect(socket, &QLocalSocket::readyRead, this, &IpcChannel::onReadyRead);
    connect(socket, &QLocalSocket::disconnected, this, &IpcChannel::onDisconnected);
    setState(Authenticating);

    m_helloId = m_nextId++;
    const QJsonObject client{{QStringLiteral("name"), m_endpoint.clientName},
                             {QStringLiteral("version"), m_endpoint.clientVersion}};
    const QJsonObject params{{QStringLiteral("protocol"), kProtocolVersion},
                             {QStringLiteral("token"), QString::fromLatin1(*token)},
                             {QStringLiteral("client"), client}};
    wipe(*token);
    const QJsonObject hello{{QStringLiteral("jsonrpc"), QStringLiteral("2.0")},
                            {QStringLiteral("id"), m_helloId},
                            {QStringLiteral("method"), QStringLiteral("session.hello")},
                            {QStringLiteral("params"), params}};
    m_helloTimer.start();
    if (!writeMessage(hello))
        fail(ServiceUnavailable, Retry::Yes);
}

bool IpcChannel::writeMessage(const QJsonObject &message)
{
    if (!m_socket)
        return false;
    QByteArray line = QJsonDocument(message).toJson(QJsonDocument::Compact);
    line.append('\n');
    const bool ok = m_socket->write(line) == line.size();
    // The hello line carries the token; do not leave the serialized copy.
    wipe(line);
    if (ok)
        m_socket->flush();
    return ok;
}

void IpcChannel::onReadyRead()
{
    if (!m_socket)
        return;
    const quint64 gen = m_generation;
    const QList<QByteArray> lines = m_lines.append(m_socket->readAll());
    if (m_lines.overflowed()) {
        // The host never writes a line this long; treat it as hostile.
        fail(ProtocolError, Retry::Yes);
        return;
    }
    for (const QByteArray &line : lines) {
        if (!handleLine(line) || gen != m_generation)
            return;
    }
}

void IpcChannel::onDisconnected()
{
    if (!m_socket)
        return;
    // Process what the host wrote before it closed (for example a hello
    // error followed by the close).
    const quint64 gen = m_generation;
    if (m_socket->bytesAvailable() > 0) {
        onReadyRead();
        if (gen != m_generation)
            return;
    }
    fail(ServiceUnavailable, Retry::Yes);
}

void IpcChannel::onHelloTimeout()
{
    if (m_state == Authenticating)
        fail(ProtocolError, Retry::Yes);
}

bool IpcChannel::handleLine(const QByteArray &line)
{
    QJsonParseError perr{};
    const QJsonDocument doc = QJsonDocument::fromJson(line, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        fail(ProtocolError, Retry::Yes);
        return false;
    }
    const QJsonObject o = doc.object();
    if (o.value(QLatin1StringView("jsonrpc")) != QJsonValue(QStringLiteral("2.0"))) {
        fail(ProtocolError, Retry::Yes);
        return false;
    }

    const QJsonValue idValue = o.value(QLatin1StringView("id"));
    const QJsonValue methodValue = o.value(QLatin1StringView("method"));

    if (!idValue.isUndefined()) {
        // A response. The host never sends requests to the client.
        qint64 id = 0;
        const bool hasResult = o.contains(QLatin1StringView("result"));
        const bool hasError = o.contains(QLatin1StringView("error"));
        if (!integral(idValue, &id) || !methodValue.isUndefined() || hasResult == hasError) {
            fail(ProtocolError, Retry::Yes);
            return false;
        }
        const QJsonValue result = o.value(QLatin1StringView("result"));
        const QJsonValue error = o.value(QLatin1StringView("error"));
        qint64 code = 0;
        if ((hasResult && !result.isObject())
            || (hasError
                && (!error.isObject()
                    || !integral(error.toObject().value(QLatin1StringView("code")), &code)))) {
            fail(ProtocolError, Retry::Yes);
            return false;
        }

        if (m_state == Authenticating && id == m_helloId) {
            const quint64 gen = m_generation;
            handleHelloAnswer(o);
            return gen == m_generation;
        }
        if (!m_pending.remove(id))
            return true; // not ours (or already failed by close): ignore
        if (hasResult) {
            emit replied(id, result.toObject());
        } else {
            const QJsonObject e = error.toObject();
            const QJsonValue message = e.value(QLatin1StringView("message"));
            const QJsonValue data = e.value(QLatin1StringView("data"));
            emit callFailed(id, int(std::clamp<qint64>(code, INT_MIN, INT_MAX)),
                            message.isString() ? message.toString() : QString(),
                            data.isObject() ? data.toObject() : QJsonObject());
        }
        return true;
    }

    if (!methodValue.isString()) {
        fail(ProtocolError, Retry::Yes);
        return false;
    }
    const QJsonValue paramsValue = o.value(QLatin1StringView("params"));
    if (!paramsValue.isUndefined() && !paramsValue.isObject()) {
        fail(ProtocolError, Retry::Yes);
        return false;
    }
    const QString method = methodValue.toString();
    const QJsonObject params = paramsValue.toObject();

    if (method == QLatin1StringView("session.closing")) {
        qint64 code = 0;
        if (!integral(params.value(QLatin1StringView("code")), &code))
            code = 0;
        const QJsonValue reason = params.value(QLatin1StringView("reason"));
        teardown();
        const quint64 gen = m_generation;
        emit closing(int(std::clamp<qint64>(code, INT_MIN, INT_MAX)),
                     reason.isString() ? reason.toString() : QString());
        if (gen == m_generation)
            scheduleReconnect();
        return false;
    }

    if (m_state == Ready)
        emit notification(method, params);
    return true;
}

void IpcChannel::handleHelloAnswer(const QJsonObject &message)
{
    m_helloTimer.stop();
    m_helloId = -1;
    const QJsonValue error = message.value(QLatin1StringView("error"));
    if (error.isObject()) {
        qint64 code = 0;
        integral(error.toObject().value(QLatin1StringView("code")), &code);
        if (code == kErrUnauthenticated)
            fail(NotAuthorized, Retry::Yes);
        else if (code == kErrUnsupportedProtocol)
            fail(ProtocolMismatch, Retry::No);
        else
            fail(ProtocolError, Retry::Yes);
        return;
    }

    const QJsonObject result = message.value(QLatin1StringView("result")).toObject();
    qint64 protocol = 0;
    if (!integral(result.value(QLatin1StringView("protocol")), &protocol)
        || protocol != kProtocolVersion) {
        fail(ProtocolMismatch, Retry::No);
        return;
    }
    m_helloResult = result;
    m_lastFailure = NoFailure;
    m_backoffMs = m_backoffInitialMs;
    setState(Ready);
    emit ready();
}

void IpcChannel::teardown()
{
    ++m_generation;
    m_helloTimer.stop();
    m_helloId = -1;
    m_lines.reset();
    if (m_socket) {
        QLocalSocket *s = m_socket;
        m_socket = nullptr;
        disconnect(s, nullptr, this, nullptr);
        s->abort();
        s->deleteLater();
    }
    if (m_pending.isEmpty())
        return;
    QList<qint64> ids(m_pending.cbegin(), m_pending.cend());
    m_pending.clear();
    std::sort(ids.begin(), ids.end());
    for (qint64 id : std::as_const(ids))
        emit callFailed(id, kErrShuttingDown, QStringLiteral("closed"), QJsonObject());
}

void IpcChannel::fail(Failure f, Retry retry)
{
    teardown();
    const quint64 gen = m_generation;
    m_lastFailure = f;
    if (retry == Retry::No)
        m_wantOpen = false;
    scheduleReconnect();
    if (gen == m_generation)
        emit failure(f);
}

void IpcChannel::scheduleReconnect()
{
    if (!m_wantOpen) {
        setState(Disconnected);
        return;
    }
    setState(Backoff);
    m_reconnectTimer.start(m_backoffMs);
    m_backoffMs = std::min(m_backoffMs * 2, m_backoffMaxMs);
}

void IpcChannel::setState(State s)
{
    if (m_state == s)
        return;
    m_state = s;
    emit stateChanged(s);
}
