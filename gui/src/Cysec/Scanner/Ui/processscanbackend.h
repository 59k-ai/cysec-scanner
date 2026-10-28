// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ndjsonparser.h"
#include "scanbackend.h"

#include <QByteArray>
#include <QProcess>
#include <QString>
#include <QStringList>
#include <QtQml/qqmlregistration.h>

#include <memory>

class QTemporaryDir;
class QTimer;

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
    void onStdout();
    void onStderr();
    void onFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onErrorOccurred(QProcess::ProcessError error);
    void processLines(const QList<QByteArray> &lines);
    void appendDiagnostic(const QByteArray &raw);
    void flushStderrPending();

    QProcess *m_process = nullptr;
    QTimer *m_killTimer = nullptr;
    std::unique_ptr<QTemporaryDir> m_tempDir;
    QString m_enginePath;
    QString m_payloadPath;
    int m_stopGraceMs = 3000;
    bool m_stopRequested = false;
    bool m_overflowReported = false;
    NdjsonLineBuffer m_stdoutBuffer;
    QByteArray m_stderrPending;
    QStringList m_diagnostics; // sanitised stderr ring, capped by m_diagnosticsBytes
    qsizetype m_diagnosticsBytes = 0;
};
