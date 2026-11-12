// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "scanevent.h"

#include <QObject>
#include <QString>
#include <QStringList>
#include <QtQml/qqmlregistration.h>

// What the user asked to scan. Fields are validated (see Validators) before
// a request reaches a backend; a backend never re-interprets free text.
struct ScanRequest
{
    QStringList cidrs;
    QString portSpec;
    bool probeFragile = false;
};

// ScanBackend is the abstract transport seam between the session and the
// engine. QML only ever sees this type; it cannot create one, and the
// concrete transport (a child process or local IPC to a service) stays out
// of every QML-visible API.
//
// Contract fixed by plan 13-07; the process transport is implemented in
// plan 13-09. The local IPC transport extends it additively: new start
// errors are appended so existing values keep their numbers, and
// runAttached reports a run this client did not start (or is reconnecting
// to), so the session can show it as running.
class ScanBackend : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("ScanBackend is an abstract transport seam")

public:
    enum EndStatus { Completed, Cancelled, Failed };
    Q_ENUM(EndStatus)

    enum StartError {
        EngineNotFound, EngineFailedToStart,
        // Local IPC only: the service is not reachable, refused this
        // client, speaks another protocol version, or is not the process
        // the endpoint policy expects.
        ServiceUnavailable, NotAuthorized, ProtocolMismatch, ServerNotTrusted,
    };
    Q_ENUM(StartError)

    using QObject::QObject;

    virtual void start(const ScanRequest &request) = 0;
    virtual void requestStop() = 0;
    virtual bool isRunning() const = 0;

    // Last sanitised diagnostic lines from the engine, plain text only.
    virtual QStringList diagnosticsTail() const = 0;

signals:
    void eventReceived(const ScanEvent &event);
    // payloadPath is empty when the engine wrote no payload.
    void finished(ScanBackend::EndStatus status, int exitCode, const QString &payloadPath);
    void failedToStart(ScanBackend::StartError error);
    // A run is active that the session should show. startedAtTs is the
    // run's own start in seconds since the epoch, so elapsed time is right
    // for a run joined midway. Announcing the same runId again (a
    // reconnect) means "still the same run", not a new one.
    void runAttached(const QString &runId, double startedAtTs);
};
