// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "scansession.h"

// Compile-only skeleton; plan 13-15 implements the session state machine.

ScanSession::ScanSession(QObject *parent)
    : QObject(parent)
    , m_hosts(new HostModel(this))
    , m_log(new LogModel(this))
{
}

ScanSession::~ScanSession() = default;

ScanBackend *ScanSession::backend() const
{
    return m_backend;
}

void ScanSession::setBackend(ScanBackend *backend)
{
    if (backend == m_backend)
        return;
    m_backend = backend;
    emit backendChanged();
}

HostModel *ScanSession::hosts() const
{
    return m_hosts;
}

LogModel *ScanSession::log() const
{
    return m_log;
}

ScanSession::State ScanSession::state() const
{
    return m_state;
}

int ScanSession::currentStageIndex() const
{
    return m_currentStageIndex;
}

QString ScanSession::currentStage() const
{
    return m_currentStage;
}

int ScanSession::stageDone() const
{
    return m_stageDone;
}

int ScanSession::stageTotal() const
{
    return m_stageTotal;
}

int ScanSession::elapsedSeconds() const
{
    return m_elapsedSeconds;
}

int ScanSession::hostsFound() const
{
    return m_hostsFound;
}

bool ScanSession::capabilitiesKnown() const
{
    return m_capabilitiesKnown;
}

bool ScanSession::unprivilegedIcmp() const
{
    return m_unprivilegedIcmp;
}

bool ScanSession::hasPayload() const
{
    return !m_payloadPath.isEmpty();
}

QString ScanSession::payloadPath() const
{
    return m_payloadPath;
}

bool ScanSession::partial() const
{
    return m_state == Partial;
}

ScanSession::Failure ScanSession::failure() const
{
    return m_failure;
}

int ScanSession::exitCode() const
{
    return m_exitCode;
}

QString ScanSession::failureDetail() const
{
    return m_failureDetail;
}

bool ScanSession::resultsExported() const
{
    return m_resultsExported;
}

bool ScanSession::hasUnexportedResults() const
{
    return false;
}

QStringList ScanSession::scope() const
{
    return m_scope;
}

void ScanSession::start(const QStringList &cidrs, const QString &portSpec, bool probeFragile)
{
    Q_UNUSED(cidrs);
    Q_UNUSED(portSpec);
    Q_UNUSED(probeFragile);
}

void ScanSession::stop()
{
}

void ScanSession::markExported()
{
}

void ScanSession::discardResults()
{
}
