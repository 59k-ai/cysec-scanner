// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ipcchannel.h"
#include "ipcendpoint.h"
#include "scanbackend.h"

#include <QJsonObject>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QtQml/qqmlregistration.h>

// IpcScanBackend drives scans that run inside a local service, over the
// local IPC wire contract (protocol 1), behind the same ScanBackend seam as
// ProcessScanBackend. QML cannot tell the two apart.
//
//   start()       -> run.start (scope forwarded unless Options say not to)
//   requestStop() -> run.cancel for the run being shown
//   progress      -> the event object goes through NdjsonParser::parseObject
//                    and is emitted as eventReceived
//   run.state     -> started (a run this client did not start) emits
//                    runAttached; ended emits finished with no payload path
//                    (the service keeps the payload), and observing goes on
//
// attach() connects and subscribes without starting anything; a run already
// in progress is announced through runAttached with its own start time, and
// a later run started by someone else (a schedule, another client) is too.
// A start while a run is active attaches to that run instead of failing.
// detach() disconnects without cancelling, so closing a window can leave the
// run going.
//
// Every server field is untrusted: events are decoded by the same defensive
// parser as the stdout stream, events of any other run are ignored, and an
// unknown outcome counts as a failed run. Diagnostics are fixed English
// lines plus the plain text of log events; nothing here is translated or
// rendered.
class IpcScanBackend : public ScanBackend
{
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("created in C++")

public:
    struct Options
    {
        // Send the requested CIDRs, ports and probe flag with run.start. A
        // host that takes its scope from its own configuration needs {}.
        bool forwardScope = true;
    };

    explicit IpcScanBackend(IpcEndpoint endpoint, QObject *parent = nullptr);
    IpcScanBackend(IpcEndpoint endpoint, Options options, QObject *parent = nullptr);
    ~IpcScanBackend() override;

    void attach();
    void detach();
    QString runId() const;
    IpcChannel *channel() const;

    void start(const ScanRequest &request) override;
    void requestStop() override;
    bool isRunning() const override;
    QStringList diagnosticsTail() const override;

private:
    void onReady();
    void onChannelFailure(IpcChannel::Failure failure);
    void onReplied(qint64 id, const QJsonObject &result);
    void onCallFailed(qint64 id, int code, const QString &message, const QJsonObject &data);
    void onNotification(const QString &method, const QJsonObject &params);
    void handleNotification(const QString &method, const QJsonObject &params);
    void handleSubscribed(const QJsonObject &result);
    void sendStart();
    void sendCancel();
    void attachTo(const QString &runId, double startedAtTs);
    void endCurrentRun(ScanBackend::EndStatus status);
    void failStart(ScanBackend::StartError error);
    void flushBuffered();
    bool buffering() const;
    void addDiagnostic(const QString &line);

    IpcChannel *m_channel = nullptr;
    Options m_options;

    QString m_runId;      // the run being shown, empty before the first
    bool m_running = false;
    bool m_subscribed = false;

    // start() before the subscription is answered: the request waits so a
    // run already in progress can be attached to instead (D-09).
    bool m_startQueued = false;
    ScanRequest m_request;
    qint64 m_subscribeId = -1;
    qint64 m_startId = -1;
    qint64 m_statusId = -1;
    QString m_statusRunId; // the run whose start time status.get is asked for
    bool m_stopAfterStart = false;

    // Notifications that arrive while run.start (or the status.get that
    // follows a refused start) is unanswered: until the run id is known it
    // is not clear which run they belong to.
    QList<QPair<QString, QJsonObject>> m_buffered;
    // Set when a notification was dropped from m_buffered; the flush then
    // re-subscribes for a fresh snapshot.
    bool m_bufferOverflowed = false;

    QStringList m_diagnostics;
};
