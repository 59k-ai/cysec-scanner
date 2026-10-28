// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "processscanbackend.h"

#include <QProcess>

// Compile-only skeleton; plan 13-09 implements the process transport.

ProcessScanBackend::ProcessScanBackend(QObject *parent)
    : ScanBackend(parent)
{
}

ProcessScanBackend::~ProcessScanBackend() = default;

QString ProcessScanBackend::resolveEnginePath()
{
    return {};
}

void ProcessScanBackend::setEnginePath(const QString &path)
{
    m_enginePath = path;
}

void ProcessScanBackend::setStopGraceMs(int ms)
{
    m_stopGraceMs = ms;
}

QStringList ProcessScanBackend::buildArguments(const ScanRequest &r, const QString &payloadPath)
{
    Q_UNUSED(r);
    Q_UNUSED(payloadPath);
    return {};
}

void ProcessScanBackend::start(const ScanRequest &request)
{
    Q_UNUSED(request);
}

void ProcessScanBackend::requestStop()
{
}

bool ProcessScanBackend::isRunning() const
{
    return false;
}

QStringList ProcessScanBackend::diagnosticsTail() const
{
    return m_diagnostics;
}
