// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "scansession.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QTimer>

// The session only ever talks to the abstract ScanBackend seam (D-18). It
// turns typed events into progress, host and log state and maps the
// backend's end status to a terminal state. Failure information is codes
// plus a raw plain-text detail; QML owns every user-visible string.

namespace {

constexpr int kNoStage = -1;
constexpr int kLastStage = 2;          // v0 shows three segments
constexpr int kTickMs = 250;           // finer than 1 s so the label never lags a whole second
constexpr int kDetailCap = 300;        // T-13-56
constexpr int kExitRejectedInput = 2;  // engine CLI usage/validation error

// Stage index for an agent name, or kNoStage when the agent is not a stage
// this GUI knows (a newer engine may add agents; they are ignored).
int stageIndexOf(const QString &agent)
{
    if (agent == QLatin1StringView("discovery"))
        return 0;
    if (agent == QLatin1StringView("port"))
        return 1;
    if (agent == QLatin1StringView("fingerprint"))
        return 2;
    if (agent.startsWith(QLatin1StringView("extra")))
        return kLastStage;
    return kNoStage;
}

} // namespace

ScanSession::ScanSession(QObject *parent)
    : QObject(parent)
    , m_hosts(new HostModel(this))
    , m_log(new LogModel(this))
    , m_tick(new QTimer(this))
{
    m_tick->setInterval(kTickMs);
    connect(m_tick, &QTimer::timeout, this, &ScanSession::updateElapsed);
    connect(m_hosts, &HostModel::countChanged, this, &ScanSession::updateHostsFound);
}

ScanSession::~ScanSession()
{
    // Do not react to the models or the backend while tearing down.
    if (m_backend)
        disconnect(m_backend, nullptr, this, nullptr);
    disconnect(m_hosts, nullptr, this, nullptr);
}

ScanBackend *ScanSession::backend() const
{
    return m_backend;
}

void ScanSession::setBackend(ScanBackend *backend)
{
    if (backend == m_backend)
        return;
    if (m_backend)
        disconnect(m_backend, nullptr, this, nullptr);
    m_backend = backend;
    if (m_backend) {
        connect(m_backend, &ScanBackend::eventReceived, this, &ScanSession::onEvent);
        connect(m_backend, &ScanBackend::finished, this, &ScanSession::onFinished);
        connect(m_backend, &ScanBackend::failedToStart, this, &ScanSession::onFailedToStart);
        connect(m_backend, &QObject::destroyed, this, [this](QObject *gone) {
            if (gone != m_backend)
                return;
            m_backend = nullptr;
            if (isActive()) {
                // The transport vanished mid-scan; no finished() will follow.
                m_tick->stop();
                updateElapsed();
                m_hosts->flushNow();
                setFailure(EngineExitedNonZero, -1, QString());
                m_partial = true;
                setState(Failed);
                updateExportState();
            }
            emit backendChanged();
        });
    }
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

bool ScanSession::systemPing() const
{
    return m_systemPing;
}

bool ScanSession::arpCache() const
{
    return m_arpCache;
}

bool ScanSession::hasPayload() const
{
    return m_hasPayload;
}

QString ScanSession::payloadPath() const
{
    return m_payloadPath;
}

bool ScanSession::partial() const
{
    return m_partial;
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
    return m_unexportedCache;
}

QStringList ScanSession::scope() const
{
    return m_scope;
}

void ScanSession::start(const QStringList &cidrs, const QString &portSpec, bool probeFragile)
{
    // D-13: one scan at a time (T-13-58).
    if (isActive())
        return;

    resetResults();
    setScope(cidrs);

    if (!m_backend) {
        setFailure(EngineNotFound, 0, QString());
        setState(Failed);
        updateExportState();
        return;
    }

    // Inputs were validated by the caller (Validators). A blank port spec
    // means the engine default set, so --ports is omitted rather than
    // passed as whitespace, which the engine would reject.
    ScanRequest request;
    request.cidrs = cidrs;
    request.portSpec = portSpec.trimmed();
    request.probeFragile = probeFragile;

    m_elapsed.start();
    m_tick->start();
    setState(Running);
    updateExportState();
    m_backend->start(request);
}

void ScanSession::stop()
{
    if (m_state != Running)
        return;
    setState(Stopping);
    if (m_backend)
        m_backend->requestStop();
}

void ScanSession::markExported()
{
    if (m_resultsExported)
        return;
    // resultsExported and hasUnexportedResults share one notify signal.
    m_resultsExported = true;
    m_unexportedCache = false;
    emit exportStateChanged();
}

void ScanSession::discardResults()
{
    if (isActive())
        return;
    resetResults();
    setScope({});
    setState(Idle);
    updateExportState();
}

void ScanSession::onEvent(const ScanEvent &event)
{
    if (!isActive())
        return;

    switch (event.kind) {
    case ScanEventKind::ScanStart:
        if (event.hasCapabilities)
            setCapabilities(true, event.capUnprivilegedIcmp, event.capSystemPing,
                            event.capArpCache);
        if (!event.scope.isEmpty())
            setScope(event.scope);
        break;
    case ScanEventKind::AgentStart: {
        const int index = stageIndexOf(event.agent);
        if (index != kNoStage)
            setProgress(index, event.agent, 0, 0);
        break;
    }
    case ScanEventKind::StageProgress: {
        const int index = stageIndexOf(event.agent);
        if (index == kNoStage)
            break;
        // Only the current agent moves the bar; a stray late counter from a
        // finished stage must not drag it backwards.
        if (event.agent == m_currentStage || m_currentStage.isEmpty())
            setProgress(index, event.agent, event.done, event.total);
        break;
    }
    case ScanEventKind::AgentDone:
        if (event.agent == m_currentStage)
            setProgress(m_currentStageIndex, m_currentStage, m_stageTotal, m_stageTotal);
        break;
    case ScanEventKind::Host:
        m_hosts->upsert(event.host);
        break;
    case ScanEventKind::Log:
        m_log->append(event.logLevel, event.logMessage);
        break;
    case ScanEventKind::ScanEnd:
        m_scanEndStatus = event.endStatus;
        break;
    case ScanEventKind::PhaseStart:
    case ScanEventKind::PhaseDone:
    case ScanEventKind::Unknown:
        // Legacy and future kinds carry nothing the session shows.
        break;
    }
}

void ScanSession::onFinished(ScanBackend::EndStatus status, int exitCode,
                             const QString &payloadPath)
{
    if (!isActive())
        return;

    m_tick->stop();
    updateElapsed();
    m_hosts->flushNow();

    // Fold in the final payload when the engine wrote one. Bytes are read
    // as-is; the payload is only parsed, never re-serialised (D-02).
    bool payloadCancelled = false;
    bool havePayload = false;
    if (!payloadPath.isEmpty()) {
        QFile file(payloadPath);
        if (file.open(QIODevice::ReadOnly)) {
            const QByteArray bytes = file.readAll();
            const QJsonDocument doc = QJsonDocument::fromJson(bytes);
            if (doc.isObject()) {
                havePayload = true;
                payloadCancelled = doc.object().value(QStringLiteral("scan_status")).toString()
                    == QLatin1StringView("cancelled");
                const bool changed = m_hosts->reconcileFromPayload(bytes);
                emit reconciled(changed);
            }
        }
    }
    setPayload(havePayload ? payloadPath : QString(), havePayload);

    State next = Completed;
    switch (status) {
    case ScanBackend::Completed:
        // The payload marker wins (T-13-57). Without a payload, the
        // scan_end status is the only remaining evidence.
        if (payloadCancelled
            || (!havePayload && m_scanEndStatus == QLatin1StringView("cancelled"))) {
            next = Partial;
        }
        setFailure(NoFailure, exitCode, QString());
        break;
    case ScanBackend::Cancelled:
        // Exit 130 + payload: cooperative cancel. Non-zero + no payload:
        // killed after the grace period; the live hosts are the result.
        next = Partial;
        setFailure(NoFailure, exitCode, QString());
        break;
    case ScanBackend::Failed:
        next = Failed;
        setFailure(exitCode == kExitRejectedInput ? EngineRejectedInput : EngineExitedNonZero,
                   exitCode, lastDiagnostic());
        break;
    }

    if (next == Completed) {
        // Every stage ran, even ones that emitted no events.
        const QString stage = m_currentStageIndex == kLastStage
            ? m_currentStage
            : QStringLiteral("fingerprint");
        setProgress(kLastStage, stage, m_stageTotal, m_stageTotal);
    }

    // Anything short of a completed scan is exported labelled partial.
    m_partial = next != Completed;
    setState(next);
    updateExportState();
}

void ScanSession::onFailedToStart(ScanBackend::StartError error)
{
    if (!isActive())
        return;
    m_tick->stop();
    updateElapsed();
    setFailure(error == ScanBackend::EngineNotFound ? EngineNotFound : EngineFailedToStart, 0,
               QString());
    m_partial = true;
    setState(Failed);
    updateExportState();
}

void ScanSession::setState(State state)
{
    // partial shares stateChanged, so emit even when only partial moved.
    m_state = state;
    emit stateChanged();
}

void ScanSession::setProgress(int index, const QString &stage, int done, int total)
{
    if (index == m_currentStageIndex && stage == m_currentStage && done == m_stageDone
        && total == m_stageTotal) {
        return;
    }
    m_currentStageIndex = index;
    m_currentStage = stage;
    m_stageDone = done;
    m_stageTotal = total;
    emit progressChanged();
}

void ScanSession::setCapabilities(bool known, bool unprivilegedIcmp, bool systemPing,
                                  bool arpCache)
{
    if (known == m_capabilitiesKnown && unprivilegedIcmp == m_unprivilegedIcmp
        && systemPing == m_systemPing && arpCache == m_arpCache)
        return;
    m_capabilitiesKnown = known;
    m_unprivilegedIcmp = unprivilegedIcmp;
    m_systemPing = systemPing;
    m_arpCache = arpCache;
    emit capabilitiesChanged();
}

void ScanSession::setFailure(Failure failure, int exitCode, const QString &detail)
{
    if (failure == m_failure && exitCode == m_exitCode && detail == m_failureDetail)
        return;
    m_failure = failure;
    m_exitCode = exitCode;
    m_failureDetail = detail;
    emit failureChanged();
}

void ScanSession::setPayload(const QString &path, bool has)
{
    if (path == m_payloadPath && has == m_hasPayload)
        return;
    m_payloadPath = path;
    m_hasPayload = has;
    emit payloadChanged();
}

void ScanSession::setScope(const QStringList &scope)
{
    if (scope == m_scope)
        return;
    m_scope = scope;
    emit scopeChanged();
}

void ScanSession::updateHostsFound()
{
    const int n = m_hosts->count();
    if (n == m_hostsFound)
        return;
    m_hostsFound = n;
    emit hostsFoundChanged();
    updateExportState();
}

void ScanSession::updateElapsed()
{
    // D-07: elapsed only, no ETA.
    const int seconds = m_elapsed.isValid() ? int(m_elapsed.elapsed() / 1000) : 0;
    if (seconds == m_elapsedSeconds)
        return;
    m_elapsedSeconds = seconds;
    emit elapsedSecondsChanged();
}

void ScanSession::updateExportState()
{
    const bool terminal = m_state == Completed || m_state == Partial || m_state == Failed;
    const bool unexported = terminal && m_hostsFound > 0 && !m_resultsExported;
    if (unexported == m_unexportedCache)
        return;
    m_unexportedCache = unexported;
    emit exportStateChanged();
}

void ScanSession::resetResults()
{
    m_tick->stop();
    m_elapsed.invalidate();
    if (m_elapsedSeconds != 0) {
        m_elapsedSeconds = 0;
        emit elapsedSecondsChanged();
    }
    m_hosts->clear();
    m_log->clear();
    updateHostsFound();
    setProgress(kNoStage, QString(), 0, 0);
    setCapabilities(false, false, false, false);
    setPayload(QString(), false);
    setFailure(NoFailure, 0, QString());
    m_partial = false;
    m_scanEndStatus.clear();
    if (m_resultsExported) {
        m_resultsExported = false;
        emit exportStateChanged();
    }
}

bool ScanSession::isActive() const
{
    return m_state == Running || m_state == Stopping;
}

QString ScanSession::lastDiagnostic() const
{
    if (!m_backend)
        return QString();
    const QStringList tail = m_backend->diagnosticsTail();
    for (auto it = tail.crbegin(); it != tail.crend(); ++it) {
        const QString line = it->trimmed();
        if (!line.isEmpty())
            return line.left(kDetailCap);
    }
    return QString();
}
