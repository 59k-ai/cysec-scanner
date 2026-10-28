// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// ScanSession: the transport-agnostic state machine between a ScanBackend
// and the QML views. The unit slots drive it through an in-test FakeBackend
// (D-18: the session only ever sees the abstract seam).

#include "hostmodel.h"
#include "logmodel.h"
#include "scanbackend.h"
#include "scanevent.h"
#include "scansession.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QtTest>

namespace {

QString fixture(const char *name)
{
    return QStringLiteral(CYSEC_GUI_FIXTURES_DIR "/") + QLatin1StringView(name);
}

ScanEvent agentStart(const QString &agent)
{
    ScanEvent ev;
    ev.kind = ScanEventKind::AgentStart;
    ev.agent = agent;
    return ev;
}

ScanEvent agentDone(const QString &agent)
{
    ScanEvent ev;
    ev.kind = ScanEventKind::AgentDone;
    ev.agent = agent;
    return ev;
}

ScanEvent stageProgress(const QString &agent, int done, int total)
{
    ScanEvent ev;
    ev.kind = ScanEventKind::StageProgress;
    ev.agent = agent;
    ev.done = done;
    ev.total = total;
    return ev;
}

ScanEvent hostEvent(const QString &ip)
{
    ScanEvent ev;
    ev.kind = ScanEventKind::Host;
    ev.host.ip = ip;
    ev.host.externalId = QStringLiteral("ip:") + ip;
    return ev;
}

ScanEvent logEvent(const QString &level, const QString &message)
{
    ScanEvent ev;
    ev.kind = ScanEventKind::Log;
    ev.logLevel = level;
    ev.logMessage = message;
    return ev;
}

ScanEvent scanStart(bool unprivilegedIcmp)
{
    ScanEvent ev;
    ev.kind = ScanEventKind::ScanStart;
    ev.scope = {QStringLiteral("192.0.2.0/24")};
    ev.stages = {QStringLiteral("discovery"), QStringLiteral("port"),
                 QStringLiteral("fingerprint")};
    ev.hasCapabilities = true;
    ev.capUnprivilegedIcmp = unprivilegedIcmp;
    return ev;
}

int payloadAssetCount(const char *name)
{
    QFile f(fixture(name));
    if (!f.open(QIODevice::ReadOnly))
        return -1;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    return int(doc.object().value(QStringLiteral("assets")).toArray().size());
}

} // namespace

// Records calls and lets the test emit the backend signals by hand.
class FakeBackend : public ScanBackend
{
    Q_OBJECT

public:
    using ScanBackend::ScanBackend;

    void start(const ScanRequest &request) override
    {
        ++startCalls;
        lastRequest = request;
        running = true;
    }
    void requestStop() override { ++stopCalls; }
    bool isRunning() const override { return running; }
    QStringList diagnosticsTail() const override { return tail; }

    void emitEvent(const ScanEvent &ev) { emit eventReceived(ev); }
    void emitFinished(EndStatus status, int code, const QString &path)
    {
        running = false;
        emit finished(status, code, path);
    }
    void emitFailedToStart(StartError error)
    {
        running = false;
        emit failedToStart(error);
    }

    int startCalls = 0;
    int stopCalls = 0;
    bool running = false;
    ScanRequest lastRequest;
    QStringList tail;
};

class TstSession : public QObject
{
    Q_OBJECT

private slots:
    void initialState();
    void startBuildsRequestAndClears();
    void startWhileRunningIgnored();
    void capabilitiesFromScanStart();
    void stageProgressFromEvents();
    void stageMappingExtraAgents();
    void hostEventsCountAfterFlush();
    void logWarningCounted();
    void stopTransitionsOnce();
    void cancelledWithPayloadIsPartial();
    void completedIsNotPartial();
    void completedButPayloadCancelledIsPartial();
    void failedNonZeroKeepsHosts();
    void failedExitTwoRejectedInput();
    void failureDetailCapped();
    void failedToStartEngineNotFound();
    void failedToStartEngineFailed();
    void killedWithoutPayloadKeepsHosts();
    void elapsedRunsAndFreezes();
    void unexportedResultsFlag();
    void discardResultsReturnsToIdle();
    void newScanClearsPreviousResults();
    void setBackendSwapsConnections();
};

void TstSession::initialState()
{
    ScanSession s;
    QCOMPARE(s.state(), ScanSession::Idle);
    QCOMPARE(s.currentStageIndex(), -1);
    QCOMPARE(s.hostsFound(), 0);
    QVERIFY(!s.capabilitiesKnown());
    QVERIFY(!s.hasPayload());
    QVERIFY(!s.partial());
    QCOMPARE(s.failure(), ScanSession::NoFailure);
    QVERIFY(!s.hasUnexportedResults());
    QVERIFY(s.hosts());
    QVERIFY(s.log());
}

void TstSession::startBuildsRequestAndClears()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    // Leftovers from a previous scan.
    s.hosts()->upsert(hostEvent(QStringLiteral("192.0.2.99")).host);
    s.hosts()->flushNow();
    s.log()->append(QStringLiteral("warn"), QStringLiteral("old"));
    QCOMPARE(s.hosts()->count(), 1);

    QSignalSpy stateSpy(&s, &ScanSession::stateChanged);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    QCOMPARE(b.startCalls, 1);
    QCOMPARE(b.lastRequest.cidrs, QStringList{QStringLiteral("192.0.2.0/24")});
    QVERIFY(b.lastRequest.portSpec.isEmpty());
    QVERIFY(!b.lastRequest.probeFragile);
    QCOMPARE(s.state(), ScanSession::Running);
    QVERIFY(stateSpy.count() >= 1);
    QCOMPARE(s.hosts()->count(), 0);
    QCOMPARE(s.log()->count(), 0);
    QCOMPARE(s.log()->warningCount(), 0);
    QCOMPARE(s.scope(), QStringList{QStringLiteral("192.0.2.0/24")});

    // A whitespace-only port spec is omitted (the engine rejects it).
    FakeBackend b2;
    ScanSession s2;
    s2.setBackend(&b2);
    s2.start({QStringLiteral("198.51.100.7/32")}, QStringLiteral("  22,80 "), true);
    QCOMPARE(b2.lastRequest.portSpec, QStringLiteral("22,80"));
    QVERIFY(b2.lastRequest.probeFragile);
}

void TstSession::startWhileRunningIgnored()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    s.start({QStringLiteral("198.51.100.0/24")}, QString(), false);
    QCOMPARE(b.startCalls, 1);
    QCOMPARE(b.lastRequest.cidrs, QStringList{QStringLiteral("192.0.2.0/24")});
    s.stop();
    QCOMPARE(s.state(), ScanSession::Stopping);
    s.start({QStringLiteral("198.51.100.0/24")}, QString(), false);
    QCOMPARE(b.startCalls, 1);
}

void TstSession::capabilitiesFromScanStart()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    QSignalSpy caps(&s, &ScanSession::capabilitiesChanged);
    b.emitEvent(scanStart(false));
    QVERIFY(s.capabilitiesKnown());
    QVERIFY(!s.unprivilegedIcmp());
    QCOMPARE(caps.count(), 1);

    // Same values again: no change notification.
    b.emitEvent(scanStart(false));
    QCOMPARE(caps.count(), 1);
}

void TstSession::stageProgressFromEvents()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(agentStart(QStringLiteral("discovery")));
    QCOMPARE(s.currentStageIndex(), 0);
    QCOMPARE(s.currentStage(), QStringLiteral("discovery"));
    b.emitEvent(agentDone(QStringLiteral("discovery")));

    b.emitEvent(agentStart(QStringLiteral("port")));
    QCOMPARE(s.currentStageIndex(), 1);
    QCOMPARE(s.stageDone(), 0);
    QCOMPARE(s.stageTotal(), 0);
    b.emitEvent(stageProgress(QStringLiteral("port"), 50, 200));
    QCOMPARE(s.currentStageIndex(), 1);
    QCOMPARE(s.stageDone(), 50);
    QCOMPARE(s.stageTotal(), 200);

    // Progress for an agent that is not the current one is ignored.
    b.emitEvent(stageProgress(QStringLiteral("discovery"), 1, 2));
    QCOMPARE(s.stageDone(), 50);
    QCOMPARE(s.stageTotal(), 200);

    b.emitEvent(agentDone(QStringLiteral("port")));
    QCOMPARE(s.stageDone(), 200);
    QCOMPARE(s.stageTotal(), 200);
}

void TstSession::stageMappingExtraAgents()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(agentStart(QStringLiteral("fingerprint")));
    QCOMPARE(s.currentStageIndex(), 2);
    b.emitEvent(agentStart(QStringLiteral("extra0")));
    QCOMPARE(s.currentStageIndex(), 2);
    QCOMPARE(s.currentStage(), QStringLiteral("extra0"));

    // Legacy and unknown kinds are tolerated without touching progress.
    ScanEvent legacy;
    legacy.kind = ScanEventKind::PhaseStart;
    b.emitEvent(legacy);
    ScanEvent unknown;
    unknown.kind = ScanEventKind::Unknown;
    b.emitEvent(unknown);
    QCOMPARE(s.currentStageIndex(), 2);
    QCOMPARE(s.state(), ScanSession::Running);
}

void TstSession::hostEventsCountAfterFlush()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    QSignalSpy found(&s, &ScanSession::hostsFoundChanged);
    b.emitEvent(hostEvent(QStringLiteral("192.0.2.10")));
    b.emitEvent(hostEvent(QStringLiteral("192.0.2.11")));
    s.hosts()->flushNow();
    QCOMPARE(s.hostsFound(), 2);
    QVERIFY(found.count() >= 1);
}

void TstSession::logWarningCounted()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(logEvent(QStringLiteral("warn"), QStringLiteral("host did not answer")));
    QCOMPARE(s.log()->count(), 1);
    QCOMPARE(s.log()->warningCount(), 1);
}

void TstSession::stopTransitionsOnce()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.stop(); // idle: nothing to stop
    QCOMPARE(b.stopCalls, 0);
    QCOMPARE(s.state(), ScanSession::Idle);

    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    s.stop();
    QCOMPARE(s.state(), ScanSession::Stopping);
    QCOMPARE(b.stopCalls, 1);
    s.stop();
    QCOMPARE(b.stopCalls, 1);
}

void TstSession::cancelledWithPayloadIsPartial()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(hostEvent(QStringLiteral("192.0.2.10")));
    b.emitEvent(hostEvent(QStringLiteral("192.0.2.11")));
    s.hosts()->flushNow();
    s.stop();

    QSignalSpy reconciled(&s, &ScanSession::reconciled);
    QSignalSpy payload(&s, &ScanSession::payloadChanged);
    b.emitFinished(ScanBackend::Cancelled, 130, fixture("payload-cancelled.json"));
    QCOMPARE(s.state(), ScanSession::Partial);
    QVERIFY(s.partial());
    QVERIFY(s.hasPayload());
    QCOMPARE(s.payloadPath(), fixture("payload-cancelled.json"));
    QCOMPARE(reconciled.count(), 1);
    QCOMPARE(reconciled.first().at(0).toBool(), true); // 192.0.2.11 removed
    QVERIFY(payload.count() >= 1);
    QCOMPARE(s.failure(), ScanSession::NoFailure);

    QCOMPARE(s.hosts()->count(), payloadAssetCount("payload-cancelled.json"));
    QCOMPARE(s.hostsFound(), s.hosts()->count());
    QCOMPARE(s.hosts()->hostAt(0).value(QStringLiteral("ip")).toString(),
             QStringLiteral("192.0.2.10"));
}

void TstSession::completedIsNotPartial()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(agentStart(QStringLiteral("port")));
    b.emitFinished(ScanBackend::Completed, 0, fixture("payload-complete.json"));
    QCOMPARE(s.state(), ScanSession::Completed);
    QVERIFY(!s.partial());
    QVERIFY(s.hasPayload());
    QCOMPARE(s.hosts()->count(), payloadAssetCount("payload-complete.json"));
    // A completed scan has run every stage.
    QCOMPARE(s.currentStageIndex(), 2);
    QCOMPARE(s.failure(), ScanSession::NoFailure);
    QCOMPARE(s.exitCode(), 0);
}

void TstSession::completedButPayloadCancelledIsPartial()
{
    // The payload's own marker wins over an exit status that claims success
    // (T-13-57: a partial result is never shown as complete).
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitFinished(ScanBackend::Completed, 0, fixture("payload-cancelled.json"));
    QCOMPARE(s.state(), ScanSession::Partial);
    QVERIFY(s.partial());
}

void TstSession::failedNonZeroKeepsHosts()
{
    FakeBackend b;
    b.tail = {QStringLiteral("level=INFO msg=starting"), QStringLiteral("level=ERROR msg=boom"),
              QString()};
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(hostEvent(QStringLiteral("192.0.2.10")));
    b.emitEvent(hostEvent(QStringLiteral("192.0.2.11")));

    QSignalSpy failure(&s, &ScanSession::failureChanged);
    b.emitFinished(ScanBackend::Failed, 1, QString());
    QCOMPARE(s.state(), ScanSession::Failed);
    QCOMPARE(s.failure(), ScanSession::EngineExitedNonZero);
    QCOMPARE(s.exitCode(), 1);
    QCOMPARE(s.failureDetail(), QStringLiteral("level=ERROR msg=boom"));
    QVERIFY(failure.count() >= 1);
    QVERIFY(!s.hasPayload());
    // Hosts received before the failure stay (pending ones are flushed).
    QCOMPARE(s.hosts()->count(), 2);
    QCOMPARE(s.hostsFound(), 2);
    QVERIFY(s.hasUnexportedResults());
}

void TstSession::failedExitTwoRejectedInput()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitFinished(ScanBackend::Failed, 2, QString());
    QCOMPARE(s.state(), ScanSession::Failed);
    QCOMPARE(s.failure(), ScanSession::EngineRejectedInput);
    QCOMPARE(s.exitCode(), 2);
    QVERIFY(s.failureDetail().isEmpty());
}

void TstSession::failureDetailCapped()
{
    FakeBackend b;
    b.tail = {QString(400, QLatin1Char('x'))};
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitFinished(ScanBackend::Failed, 1, QString());
    QCOMPARE(s.failureDetail().size(), 300);
}

void TstSession::failedToStartEngineNotFound()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitFailedToStart(ScanBackend::EngineNotFound);
    QCOMPARE(s.state(), ScanSession::Failed);
    QCOMPARE(s.failure(), ScanSession::EngineNotFound);
    QCOMPARE(s.hosts()->count(), 0);
    QVERIFY(!s.hasUnexportedResults());
}

void TstSession::failedToStartEngineFailed()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitFailedToStart(ScanBackend::EngineFailedToStart);
    QCOMPARE(s.state(), ScanSession::Failed);
    QCOMPARE(s.failure(), ScanSession::EngineFailedToStart);
}

void TstSession::killedWithoutPayloadKeepsHosts()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(hostEvent(QStringLiteral("192.0.2.10")));
    s.stop();
    QSignalSpy reconciled(&s, &ScanSession::reconciled);
    b.emitFinished(ScanBackend::Cancelled, 9, QString());
    QCOMPARE(s.state(), ScanSession::Partial);
    QVERIFY(s.partial());
    QVERIFY(!s.hasPayload());
    QCOMPARE(reconciled.count(), 0);
    QCOMPARE(s.hosts()->count(), 1);
    QCOMPARE(s.failure(), ScanSession::NoFailure);
}

void TstSession::elapsedRunsAndFreezes()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    QCOMPARE(s.elapsedSeconds(), 0);
    QTRY_VERIFY_WITH_TIMEOUT(s.elapsedSeconds() > 0, 2500);
    b.emitFinished(ScanBackend::Completed, 0, fixture("payload-complete.json"));
    const int frozen = s.elapsedSeconds();
    QVERIFY(frozen >= 1);
    QTest::qWait(1300);
    QCOMPARE(s.elapsedSeconds(), frozen);
}

void TstSession::unexportedResultsFlag()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    QVERIFY(!s.hasUnexportedResults());
    QSignalSpy exportState(&s, &ScanSession::exportStateChanged);
    b.emitFinished(ScanBackend::Completed, 0, fixture("payload-complete.json"));
    QVERIFY(s.hasUnexportedResults());
    QVERIFY(!s.resultsExported());
    QVERIFY(exportState.count() >= 1);

    s.markExported();
    QVERIFY(s.resultsExported());
    QVERIFY(!s.hasUnexportedResults());
}

void TstSession::discardResultsReturnsToIdle()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(logEvent(QStringLiteral("error"), QStringLiteral("x")));
    b.emitFinished(ScanBackend::Completed, 0, fixture("payload-complete.json"));
    QVERIFY(s.hosts()->count() > 0);

    s.discardResults();
    QCOMPARE(s.state(), ScanSession::Idle);
    QCOMPARE(s.hosts()->count(), 0);
    QCOMPARE(s.log()->count(), 0);
    QCOMPARE(s.hostsFound(), 0);
    QVERIFY(!s.hasPayload());
    QVERIFY(!s.partial());
    QVERIFY(!s.hasUnexportedResults());
    QCOMPARE(s.currentStageIndex(), -1);
}

void TstSession::newScanClearsPreviousResults()
{
    FakeBackend b;
    ScanSession s;
    s.setBackend(&b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    b.emitEvent(scanStart(true));
    b.emitFinished(ScanBackend::Failed, 1, QString());
    QCOMPARE(s.state(), ScanSession::Failed);

    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    QCOMPARE(b.startCalls, 2);
    QCOMPARE(s.state(), ScanSession::Running);
    QCOMPARE(s.failure(), ScanSession::NoFailure);
    QCOMPARE(s.exitCode(), 0);
    QVERIFY(s.failureDetail().isEmpty());
    QVERIFY(!s.capabilitiesKnown());
    QCOMPARE(s.elapsedSeconds(), 0);
    QCOMPARE(s.currentStageIndex(), -1);
}

void TstSession::setBackendSwapsConnections()
{
    FakeBackend a;
    FakeBackend b;
    ScanSession s;
    QSignalSpy changed(&s, &ScanSession::backendChanged);
    s.setBackend(&a);
    s.setBackend(&b);
    QCOMPARE(changed.count(), 2);
    QCOMPARE(s.backend(), &b);
    s.start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    QCOMPARE(a.startCalls, 0);
    QCOMPARE(b.startCalls, 1);
    // The old backend is disconnected.
    a.emitFinished(ScanBackend::Completed, 0, fixture("payload-complete.json"));
    QCOMPARE(s.state(), ScanSession::Running);

    // A destroyed backend is forgotten.
    {
        FakeBackend c;
        s.setBackend(&c);
    }
    QCOMPARE(s.backend(), nullptr);
}

QTEST_MAIN(TstSession)
#include "tst_session.moc"
