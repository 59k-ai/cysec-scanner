// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "scanbackend.h"

#include <QString>
#include <QStringList>
#include <QtQml/qqmlregistration.h>

class QProcess;

// ProcessScanBackend runs the scanner CLI as a child process and decodes its
// detailed NDJSON progress stream. The engine path comes from
// CYSEC_SCANNER_BIN or the directory of the running app, never from PATH or
// the working directory. Stop asks the engine to finish gracefully and only
// kills it after the grace period (default 3000 ms).
//
// The QProcess is a private implementation detail; nothing about it is
// QML-visible. Contract fixed by plan 13-07; implemented in plan 13-09.
class ProcessScanBackend : public ScanBackend
{
    Q_OBJECT
    QML_ELEMENT

public:
    explicit ProcessScanBackend(QObject *parent = nullptr);
    ~ProcessScanBackend() override;

    static QString resolveEnginePath();

    // Test hooks.
    void setEnginePath(const QString &path);
    void setStopGraceMs(int ms);

    static QStringList buildArguments(const ScanRequest &r, const QString &payloadPath);

    void start(const ScanRequest &request) override;
    void requestStop() override;
    bool isRunning() const override;
    QStringList diagnosticsTail() const override;

private:
    QProcess *m_process = nullptr;
    QString m_enginePath;
    int m_stopGraceMs = 3000;
    QStringList m_diagnostics;
};
