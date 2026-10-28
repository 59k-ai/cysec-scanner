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
// concrete transport (a child process today, local IPC later) stays out of
// every QML-visible API.
//
// Contract fixed by plan 13-07; the process transport is implemented in
// plan 13-09.
class ScanBackend : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("ScanBackend is an abstract transport seam")

public:
    enum EndStatus { Completed, Cancelled, Failed };
    Q_ENUM(EndStatus)

    enum StartError { EngineNotFound, EngineFailedToStart };
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
};
