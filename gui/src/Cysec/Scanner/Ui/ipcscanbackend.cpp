// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "ipcscanbackend.h"

#include "ndjsonparser.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonValue>

#include <utility>

namespace {

constexpr int kErrUnauthenticated = -32001;
constexpr int kErrRunInProgress = -32002;
constexpr int kErrNotRunning = -32003;
constexpr int kErrUnsupportedProtocol = -32005;
constexpr int kErrShuttingDown = -32011; // also used by IpcChannel for "closed"

constexpr qsizetype kDiagnosticLines = 50;
constexpr qsizetype kDiagnosticChars = 300;
// Wire contract: a snapshot carries at most 10,000 hosts plus a few stage
// items; anything beyond this while a start is unanswered is not ours.
constexpr qsizetype kMaxBuffered = 12000;

double nowSeconds()
{
    return double(QDateTime::currentMSecsSinceEpoch()) / 1000.0;
}

// started_at is RFC 3339; a missing or malformed value falls back to now so
// elapsed time starts at zero rather than at the epoch.
double epochSeconds(const QJsonValue &value)
{
    if (!value.isString())
        return nowSeconds();
    const QDateTime t = QDateTime::fromString(value.toString(), Qt::ISODate);
    if (!t.isValid())
        return nowSeconds();
    return double(t.toMSecsSinceEpoch()) / 1000.0;
}

QString stringField(const QJsonObject &o, QLatin1StringView key)
{
    const QJsonValue v = o.value(key);
    return v.isString() ? v.toString() : QString();
}

ScanBackend::EndStatus endStatusFor(const QString &outcome)
{
    if (outcome == QLatin1StringView("completed") || outcome == QLatin1StringView("shipped")
        || outcome == QLatin1StringView("buffered") || outcome == QLatin1StringView("skipped")
        || outcome == QLatin1StringView("skipped_unpaired")) {
        return ScanBackend::Completed;
    }
    if (outcome == QLatin1StringView("cancelled"))
        return ScanBackend::Cancelled;
    // rejected, failed, already_running and anything a newer host invents.
    return ScanBackend::Failed;
}

ScanBackend::StartError startErrorFor(IpcChannel::Failure failure)
{
    switch (failure) {
    case IpcChannel::NotAuthorized:
        return ScanBackend::NotAuthorized;
    case IpcChannel::ProtocolMismatch:
    case IpcChannel::ProtocolError:
        return ScanBackend::ProtocolMismatch;
    case IpcChannel::ServerNotTrusted:
        return ScanBackend::ServerNotTrusted;
    case IpcChannel::NoFailure:
    case IpcChannel::ServiceUnavailable:
        break;
    }
    return ScanBackend::ServiceUnavailable;
}

QString diagnosticFor(IpcChannel::Failure failure)
{
    switch (failure) {
    case IpcChannel::NotAuthorized:
        return QStringLiteral("ipc: the local service refused this client");
    case IpcChannel::ProtocolMismatch:
        return QStringLiteral("ipc: the local service speaks another protocol version");
    case IpcChannel::ServerNotTrusted:
        return QStringLiteral("ipc: the endpoint is not served by the expected process");
    case IpcChannel::ProtocolError:
        return QStringLiteral("ipc: the local service sent an invalid message");
    case IpcChannel::NoFailure:
    case IpcChannel::ServiceUnavailable:
        break;
    }
    return QStringLiteral("ipc: the local service is not reachable");
}

} // namespace

IpcScanBackend::IpcScanBackend(IpcEndpoint endpoint, QObject *parent)
    : IpcScanBackend(std::move(endpoint), Options{}, parent)
{
}

IpcScanBackend::IpcScanBackend(IpcEndpoint endpoint, Options options, QObject *parent)
    : ScanBackend(parent)
    , m_channel(new IpcChannel(std::move(endpoint), this))
    , m_options(options)
{
    connect(m_channel, &IpcChannel::ready, this, &IpcScanBackend::onReady);
    connect(m_channel, &IpcChannel::failure, this, &IpcScanBackend::onChannelFailure);
    connect(m_channel, &IpcChannel::replied, this, &IpcScanBackend::onReplied);
    connect(m_channel, &IpcChannel::callFailed, this, &IpcScanBackend::onCallFailed);
    connect(m_channel, &IpcChannel::notification, this, &IpcScanBackend::onNotification);
}

IpcScanBackend::~IpcScanBackend()
{
    // Leaving never cancels the run; the service keeps it going.
    disconnect(m_channel, nullptr, this, nullptr);
    m_channel->close();
}

void IpcScanBackend::attach()
{
    m_channel->open();
}

void IpcScanBackend::detach()
{
    // Forget every outstanding call first: close() fails them, and those
    // answers must not turn into start errors.
    m_startQueued = false;
    m_subscribeId = -1;
    m_startId = -1;
    m_statusId = -1;
    m_statusRunId.clear();
    m_stopAfterStart = false;
    m_subscribed = false;
    m_running = false;
    m_buffered.clear();
    m_channel->close();
}

QString IpcScanBackend::runId() const
{
    return m_runId;
}

IpcChannel *IpcScanBackend::channel() const
{
    return m_channel;
}

void IpcScanBackend::start(const ScanRequest &request)
{
    m_request = request;
    m_stopAfterStart = false;
    if (m_channel->state() == IpcChannel::Ready && m_subscribed) {
        sendStart();
        return;
    }
    // Learn first whether a run is already active (D-09).
    m_startQueued = true;
    attach();
}

void IpcScanBackend::requestStop()
{
    if (m_running && !m_runId.isEmpty()) {
        sendCancel();
        return;
    }
    if (m_startId != -1 || m_statusId != -1) {
        m_stopAfterStart = true;
        return;
    }
    if (m_startQueued) {
        // Nothing was started yet: withdraw the request.
        m_startQueued = false;
        emit finished(Cancelled, 0, QString());
    }
}

bool IpcScanBackend::isRunning() const
{
    return m_running || m_startQueued || m_startId != -1 || m_statusId != -1;
}

QStringList IpcScanBackend::diagnosticsTail() const
{
    return m_diagnostics;
}

void IpcScanBackend::onReady()
{
    m_subscribed = false;
    m_subscribeId = m_channel->call(QStringLiteral("events.subscribe"), QJsonObject());
}

void IpcScanBackend::onChannelFailure(IpcChannel::Failure failure)
{
    m_subscribed = false;
    m_subscribeId = -1;
    addDiagnostic(diagnosticFor(failure));
    if (m_startQueued)
        failStart(startErrorFor(failure));
}

void IpcScanBackend::onReplied(qint64 id, const QJsonObject &result)
{
    if (id == m_subscribeId) {
        m_subscribeId = -1;
        handleSubscribed(result);
        return;
    }
    if (id == m_startId) {
        m_startId = -1;
        const QString runId = stringField(result, QLatin1StringView("run_id"));
        if (runId.isEmpty()) {
            addDiagnostic(QStringLiteral("ipc: run.start answered without a run id"));
            failStart(EngineFailedToStart);
            return;
        }
        // This client started the run: the session already shows it.
        m_runId = runId;
        m_running = true;
        flushBuffered();
        if (m_stopAfterStart && m_running)
            sendCancel();
        return;
    }
    if (id == m_statusId) {
        m_statusId = -1;
        const QJsonObject run = result.value(QLatin1StringView("run")).toObject();
        const double startedAt = stringField(run, QLatin1StringView("run_id")) == m_statusRunId
            ? epochSeconds(run.value(QLatin1StringView("started_at")))
            : nowSeconds();
        attachTo(m_statusRunId, startedAt);
        m_statusRunId.clear();
        flushBuffered();
        if (m_stopAfterStart && m_running)
            sendCancel();
        return;
    }
    // run.cancel answers {accepted:true}; nothing to do.
}

void IpcScanBackend::onCallFailed(qint64 id, int code, const QString &message,
                                  const QJsonObject &data)
{
    Q_UNUSED(message); // server text is never shown or logged verbatim
    if (id == m_subscribeId) {
        m_subscribeId = -1;
        if (code == kErrShuttingDown)
            return; // the channel reconnects and subscribes again
        addDiagnostic(QStringLiteral("ipc: events.subscribe was refused"));
        if (m_startQueued)
            failStart(ProtocolMismatch);
        return;
    }
    if (id == m_startId) {
        m_startId = -1;
        if (code == kErrRunInProgress) {
            // D-09: a run is already active; show that one instead.
            const QString runId = stringField(data, QLatin1StringView("run_id"));
            if (runId.isEmpty()) {
                failStart(EngineFailedToStart);
                return;
            }
            m_statusRunId = runId;
            m_statusId = m_channel->call(QStringLiteral("status.get"), QJsonObject());
            if (m_statusId == -1) {
                attachTo(runId, nowSeconds());
                m_statusRunId.clear();
                flushBuffered();
            }
            return;
        }
        if (code == kErrShuttingDown)
            failStart(ServiceUnavailable);
        else if (code == kErrUnsupportedProtocol)
            failStart(ProtocolMismatch);
        else if (code == kErrUnauthenticated)
            failStart(NotAuthorized);
        else {
            addDiagnostic(QStringLiteral("ipc: run.start was refused (code %1)").arg(code));
            failStart(EngineFailedToStart);
        }
        return;
    }
    if (id == m_statusId) {
        m_statusId = -1;
        attachTo(m_statusRunId, nowSeconds());
        m_statusRunId.clear();
        flushBuffered();
        return;
    }
    // run.cancel
    if (code == kErrNotRunning)
        return; // the run ended on its own meanwhile
    if (code == kErrShuttingDown) {
        m_stopAfterStart = true; // ask again after the reconnect
        return;
    }
    addDiagnostic(QStringLiteral("ipc: run.cancel was refused (code %1)").arg(code));
}

void IpcScanBackend::onNotification(const QString &method, const QJsonObject &params)
{
    if (buffering()) {
        if (m_buffered.size() < kMaxBuffered)
            m_buffered.append({method, params});
        return;
    }
    handleNotification(method, params);
}

void IpcScanBackend::handleNotification(const QString &method, const QJsonObject &params)
{
    const QString runId = stringField(params, QLatin1StringView("run_id"));

    if (method == QLatin1StringView("progress")) {
        // T-12-43: only the run being shown feeds the session.
        if (!m_running || runId.isEmpty() || runId != m_runId)
            return;
        const QJsonValue event = params.value(QLatin1StringView("event"));
        if (!event.isObject())
            return;
        const std::optional<ScanEvent> parsed = NdjsonParser::parseObject(event.toObject());
        if (!parsed)
            return;
        if (parsed->kind == ScanEventKind::Log)
            addDiagnostic(parsed->logLevel + QStringLiteral(": ") + parsed->logMessage);
        emit eventReceived(*parsed);
        return;
    }

    if (method == QLatin1StringView("run.state")) {
        if (runId.isEmpty())
            return;
        const QString state = stringField(params, QLatin1StringView("state"));
        if (state == QLatin1StringView("started")) {
            attachTo(runId, epochSeconds(params.value(QLatin1StringView("started_at"))));
        } else if (state == QLatin1StringView("ended")) {
            if (m_running && runId == m_runId)
                endCurrentRun(endStatusFor(stringField(params, QLatin1StringView("outcome"))));
        }
        return;
    }
    // snapshot.done and future notifications carry nothing the seam needs.
}

void IpcScanBackend::handleSubscribed(const QJsonObject &result)
{
    m_subscribed = true;
    const QJsonObject run = result.value(QLatin1StringView("run")).toObject();
    const QString runId = stringField(run, QLatin1StringView("run_id"));
    if (!runId.isEmpty()) {
        attachTo(runId, epochSeconds(run.value(QLatin1StringView("started_at"))));
        // D-09: a queued start joins the active run instead of failing.
        m_startQueued = false;
        if (m_stopAfterStart)
            sendCancel();
        return;
    }
    if (m_running) {
        // The run ended while this client was disconnected; its outcome is
        // unknown, which is not a completed run.
        addDiagnostic(QStringLiteral("ipc: the run ended while disconnected"));
        endCurrentRun(Failed);
    }
    if (m_startQueued) {
        m_startQueued = false;
        sendStart();
    }
}

void IpcScanBackend::sendStart()
{
    QJsonObject params;
    if (m_options.forwardScope) {
        params.insert(QStringLiteral("cidrs"), QJsonArray::fromStringList(m_request.cidrs));
        if (!m_request.portSpec.isEmpty())
            params.insert(QStringLiteral("ports"), m_request.portSpec);
        params.insert(QStringLiteral("probe_fragile"), m_request.probeFragile);
    }
    m_startId = m_channel->call(QStringLiteral("run.start"), params);
    if (m_startId == -1)
        failStart(ServiceUnavailable);
}

void IpcScanBackend::sendCancel()
{
    const QJsonObject params{{QStringLiteral("run_id"), m_runId}};
    if (m_channel->call(QStringLiteral("run.cancel"), params) == -1) {
        m_stopAfterStart = true; // not connected: ask after the reconnect
        return;
    }
    m_stopAfterStart = false;
}

void IpcScanBackend::attachTo(const QString &runId, double startedAtTs)
{
    if (runId.isEmpty() || (m_running && runId == m_runId))
        return;
    if (m_running) {
        // A different run is active, so the one shown ended unseen.
        addDiagnostic(QStringLiteral("ipc: the run ended while disconnected"));
        endCurrentRun(Failed);
    }
    m_runId = runId;
    m_running = true;
    emit runAttached(runId, startedAtTs);
}

void IpcScanBackend::endCurrentRun(EndStatus status)
{
    m_running = false;
    m_stopAfterStart = false;
    emit finished(status, 0, QString());
}

void IpcScanBackend::failStart(StartError error)
{
    m_startQueued = false;
    m_startId = -1;
    m_stopAfterStart = false;
    emit failedToStart(error);
    flushBuffered();
}

void IpcScanBackend::flushBuffered()
{
    if (buffering())
        return;
    const QList<QPair<QString, QJsonObject>> items = std::exchange(m_buffered, {});
    for (const auto &item : items)
        handleNotification(item.first, item.second);
}

bool IpcScanBackend::buffering() const
{
    return m_startId != -1 || m_statusId != -1;
}

void IpcScanBackend::addDiagnostic(const QString &line)
{
    // Plain text, one line, bounded: control characters become spaces.
    QString clean = line.left(kDiagnosticChars);
    for (QChar &c : clean) {
        if (c.category() == QChar::Other_Control || c.category() == QChar::Other_Format)
            c = u' ';
    }
    m_diagnostics.append(clean);
    while (m_diagnostics.size() > kDiagnosticLines)
        m_diagnostics.removeFirst();
}
