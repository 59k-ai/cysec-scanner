// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// End-to-end: the public C++ client (IpcChannel + IpcScanBackend behind a
// ScanSession) against the public Go reference host (tools/ipc-refhost)
// over a real AF_UNIX socket or named pipe.
//
// The host binary comes from CYSEC_IPC_REFHOST. Without it the test skips,
// unless CYSEC_REQUIRE_IPC_E2E=1, in which case it fails: CI sets both, so
// this proof cannot silently disappear from a GUI leg.
//
// The host is started with --exit-on-stdin-eof and stopped by closing its
// stdin (portable to Windows); its token is read from --token-file after the
// "READY <address>" line.

#include "ipcchannel.h"
#include "ipcendpoint.h"
#include "ipcscanbackend.h"
#include "scanbackend.h"
#include "scanevent.h"
#include "scansession.h"

#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRandomGenerator>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtTest>

#include <memory>

namespace {

constexpr int kRunTimeoutMs = 20000;

QString randomHex()
{
    return QString::number(QRandomGenerator::global()->generate64(), 16);
}

// One endpoint: a socket path in a fresh owner-only directory (Unix) or a
// unique pipe name (Windows), plus a token file in its own directory.
struct Endpoint
{
    Endpoint()
#ifdef Q_OS_WIN
        : socketDir()
#else
        // Short absolute path: AF_UNIX paths are limited to ~104 bytes.
        : socketDir(QStringLiteral("/tmp/ipce2e-XXXXXX"))
#endif
    {
#ifdef Q_OS_WIN
        address = QStringLiteral("\\\\.\\pipe\\scanner-ipc-e2e-") + randomHex();
#else
        address = socketDir.path() + QStringLiteral("/h.sock");
#endif
        tokenFile = tokenDir.path() + QStringLiteral("/token");
    }

    bool isValid() const { return socketDir.isValid() && tokenDir.isValid(); }

    IpcEndpoint ipc() const
    {
        IpcEndpoint e;
        e.address = address;
        e.tokenFile = tokenFile;
        e.policy = IpcServerPolicy::sameUser();
        e.clientName = QStringLiteral("scanner-ipc-e2e");
        e.clientVersion = QStringLiteral("0");
        return e;
    }

    QTemporaryDir socketDir;
    QTemporaryDir tokenDir;
    QString address;
    QString tokenFile;
};

class RefHost
{
public:
    ~RefHost() { stop(); }

    bool start(const QString &program, const Endpoint &ep, const QStringList &extra)
    {
        m_proc = std::make_unique<QProcess>();
        m_proc->setProcessChannelMode(QProcess::ForwardedErrorChannel);
        QStringList args{QStringLiteral("--address"), ep.address, QStringLiteral("--token-file"),
                         ep.tokenFile, QStringLiteral("--exit-on-stdin-eof")};
        args << extra;
        m_proc->start(program, args);
        if (!m_proc->waitForStarted(10000))
            return false;
        QElapsedTimer t;
        t.start();
        while (!m_proc->canReadLine() && t.elapsed() < 15000) {
            if (!m_proc->waitForReadyRead(200) && m_proc->state() == QProcess::NotRunning)
                return false;
        }
        const QByteArray line = m_proc->readLine().trimmed();
        return line == QByteArray("READY ") + ep.address.toUtf8();
    }

    void stop()
    {
        if (!m_proc)
            return;
        if (m_proc->state() != QProcess::NotRunning) {
            m_proc->closeWriteChannel();
            if (!m_proc->waitForFinished(10000)) {
                m_proc->kill();
                m_proc->waitForFinished(5000);
            }
        }
        m_proc.reset();
    }

private:
    std::unique_ptr<QProcess> m_proc;
};

QByteArray readFile(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return QByteArray();
    return f.readAll();
}

// A backend with a short reconnect backoff, so the tests stay fast.
std::unique_ptr<IpcScanBackend> makeBackend(const Endpoint &ep)
{
    auto b = std::make_unique<IpcScanBackend>(ep.ipc());
    b->channel()->setBackoff(50, 400);
    return b;
}

} // namespace

class TstIpcE2e : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();

    void startObserveComplete();
    void attachMidRun();
    void startWhileRunningAttaches();
    void cancelRun();
    void detachLeavesRunGoing();
    void reconnectAfterHostRestart();
    void wrongTokenRefused();

private:
    bool startHost(RefHost &host, const Endpoint &ep, const QStringList &extra = {});

    QString m_refhost;
};

void TstIpcE2e::initTestCase()
{
    m_refhost = qEnvironmentVariable("CYSEC_IPC_REFHOST");
    const bool required = qEnvironmentVariable("CYSEC_REQUIRE_IPC_E2E") == QLatin1StringView("1");
    if (m_refhost.isEmpty()) {
        if (required)
            QFAIL("CYSEC_REQUIRE_IPC_E2E=1 but CYSEC_IPC_REFHOST is not set");
        QSKIP("CYSEC_IPC_REFHOST is not set; build tools/ipc-refhost to run this test");
    }
    const QFileInfo info(m_refhost);
    if (!info.isFile() || !info.isExecutable())
        QFAIL("CYSEC_IPC_REFHOST does not name an executable file");
}

bool TstIpcE2e::startHost(RefHost &host, const Endpoint &ep, const QStringList &extra)
{
    return host.start(m_refhost, ep, extra);
}

void TstIpcE2e::startObserveComplete()
{
    Endpoint ep;
    QVERIFY(ep.isValid());
    RefHost host;
    QVERIFY(startHost(host, ep));

    auto b = makeBackend(ep);
    ScanSession s;
    s.setBackend(b.get());
    QSignalSpy events(b.get(), &ScanBackend::eventReceived);
    QSignalSpy attached(b.get(), &ScanBackend::runAttached);
    QSignalSpy failed(b.get(), &ScanBackend::failedToStart);
    QSignalSpy hosts(&s, &ScanSession::hostsFoundChanged);
    QSignalSpy progress(&s, &ScanSession::progressChanged);

    s.start({QStringLiteral("10.0.0.0/30")}, QStringLiteral("22"), false);
    QCOMPARE(s.state(), ScanSession::Running);
    QTRY_COMPARE_WITH_TIMEOUT(s.state(), ScanSession::Completed, kRunTimeoutMs);

    QCOMPARE(failed.count(), 0);
    QCOMPARE(attached.count(), 0); // this client started the run itself
    QVERIFY(!b->runId().isEmpty());
    QVERIFY(hosts.count() > 0);
    QVERIFY(progress.count() > 0);
    QCOMPARE(s.hostsFound(), 3);
    QCOMPARE(s.failure(), ScanSession::NoFailure);
    QVERIFY(!s.hasPayload());
    QVERIFY(!s.partial());
    QVERIFY(!b->isRunning());

    // The requested scope reached the host (forwardScope).
    bool sawStart = false;
    for (const QList<QVariant> &args : std::as_const(events)) {
        const ScanEvent ev = args.at(0).value<ScanEvent>();
        if (ev.kind != ScanEventKind::ScanStart)
            continue;
        QCOMPARE(ev.scope, QStringList{QStringLiteral("10.0.0.0/30")});
        sawStart = true;
        break;
    }
    QVERIFY(sawStart);
}

void TstIpcE2e::attachMidRun()
{
    Endpoint ep;
    QVERIFY(ep.isValid());
    RefHost host;
    QVERIFY(startHost(host, ep, {QStringLiteral("--autostart"), QStringLiteral("--step"),
                                 QStringLiteral("100ms")}));
    // Let the scheduled run find a host or two before the GUI shows up.
    QTest::qWait(650);

    auto b = makeBackend(ep);
    ScanSession s;
    s.setBackend(b.get());
    QSignalSpy attached(b.get(), &ScanBackend::runAttached);

    b->attach();
    QTRY_COMPARE_WITH_TIMEOUT(s.state(), ScanSession::Running, 5000);
    QCOMPARE(attached.count(), 1);
    QCOMPARE(attached.at(0).at(0).toString(), b->runId());
    QVERIFY(s.elapsedSeconds() >= 0);
    // The snapshot already carries the hosts found so far.
    QTRY_VERIFY_WITH_TIMEOUT(s.hostsFound() >= 1, 2000);

    QTRY_COMPARE_WITH_TIMEOUT(s.state(), ScanSession::Completed, kRunTimeoutMs);
    // Replayed and live host events upsert: no duplicates.
    QCOMPARE(s.hostsFound(), 3);
    QCOMPARE(attached.count(), 1);
    QCOMPARE(s.scope(), QStringList{QStringLiteral("192.0.2.0/29")});
}

void TstIpcE2e::startWhileRunningAttaches()
{
    Endpoint ep;
    QVERIFY(ep.isValid());
    RefHost host;
    QVERIFY(startHost(host, ep, {QStringLiteral("--autostart"), QStringLiteral("--step"),
                                 QStringLiteral("100ms")}));

    auto b = makeBackend(ep);
    ScanSession s;
    s.setBackend(b.get());
    QSignalSpy attached(b.get(), &ScanBackend::runAttached);
    QSignalSpy failed(b.get(), &ScanBackend::failedToStart);

    // A run is already active: the start joins it instead of failing.
    s.start({QStringLiteral("10.0.0.0/30")}, QString(), false);
    QTRY_COMPARE_WITH_TIMEOUT(attached.count(), 1, 5000);
    QCOMPARE(failed.count(), 0);
    QCOMPARE(s.state(), ScanSession::Running);
    QCOMPARE(attached.at(0).at(0).toString(), b->runId());

    QTRY_COMPARE_WITH_TIMEOUT(s.state(), ScanSession::Completed, kRunTimeoutMs);
    QCOMPARE(s.failure(), ScanSession::NoFailure);
    // The session follows the scheduled run, not the request it made.
    QCOMPARE(s.scope(), QStringList{QStringLiteral("192.0.2.0/29")});
    QCOMPARE(s.hostsFound(), 3);
}

void TstIpcE2e::cancelRun()
{
    Endpoint ep;
    QVERIFY(ep.isValid());
    RefHost host;
    QVERIFY(startHost(host, ep, {QStringLiteral("--step"), QStringLiteral("200ms")}));

    auto b = makeBackend(ep);
    ScanSession s;
    s.setBackend(b.get());
    QString outcome;
    QObject::connect(b->channel(), &IpcChannel::notification, &s,
                     [&outcome](const QString &method, const QJsonObject &params) {
                         if (method == QLatin1StringView("run.state")
                             && params.value(QLatin1StringView("state")).toString()
                                 == QLatin1StringView("ended")) {
                             outcome = params.value(QLatin1StringView("outcome")).toString();
                         }
                     });

    s.start({QStringLiteral("10.0.0.0/30")}, QString(), false);
    QTRY_VERIFY_WITH_TIMEOUT(s.hostsFound() >= 1, 10000);
    QVERIFY(b->isRunning());
    s.stop();
    QCOMPARE(s.state(), ScanSession::Stopping);
    QTRY_COMPARE_WITH_TIMEOUT(s.state(), ScanSession::Partial, kRunTimeoutMs);
    QCOMPARE(outcome, QStringLiteral("cancelled"));
    QVERIFY(s.partial());
    QCOMPARE(s.failure(), ScanSession::NoFailure);
    QVERIFY(s.hostsFound() >= 1);
}

void TstIpcE2e::detachLeavesRunGoing()
{
    Endpoint ep;
    QVERIFY(ep.isValid());
    RefHost host;
    QVERIFY(startHost(host, ep, {QStringLiteral("--step"), QStringLiteral("100ms")}));

    auto a = makeBackend(ep);
    ScanSession sa;
    sa.setBackend(a.get());
    sa.start({QStringLiteral("10.0.0.0/30")}, QString(), false);
    QTRY_VERIFY_WITH_TIMEOUT(!a->runId().isEmpty(), 5000);
    const QString runId = a->runId();

    // Declining to cancel on close: disconnect, the run keeps going.
    a->detach();
    QVERIFY(!a->isRunning());
    QCOMPARE(a->channel()->state(), IpcChannel::Disconnected);

    auto b = makeBackend(ep);
    ScanSession sb;
    sb.setBackend(b.get());
    QSignalSpy attached(b.get(), &ScanBackend::runAttached);
    b->attach();
    QTRY_COMPARE_WITH_TIMEOUT(attached.count(), 1, 5000);
    QCOMPARE(attached.at(0).at(0).toString(), runId);
    QCOMPARE(sb.state(), ScanSession::Running);
    // It was never cancelled: it runs to completion.
    QTRY_COMPARE_WITH_TIMEOUT(sb.state(), ScanSession::Completed, kRunTimeoutMs);
    QVERIFY(!sb.partial());
}

void TstIpcE2e::reconnectAfterHostRestart()
{
    Endpoint ep;
    QVERIFY(ep.isValid());
    auto first = std::make_unique<RefHost>();
    QVERIFY(startHost(*first, ep));
    const QByteArray firstToken = readFile(ep.tokenFile);
    QVERIFY(!firstToken.isEmpty());

    auto b = makeBackend(ep);
    ScanSession s;
    s.setBackend(b.get());
    QSignalSpy failed(b.get(), &ScanBackend::failedToStart);
    b->attach();
    QTRY_COMPARE_WITH_TIMEOUT(b->channel()->state(), IpcChannel::Ready, 5000);

    first->stop();
    first.reset();
    QTRY_VERIFY_WITH_TIMEOUT(b->channel()->state() != IpcChannel::Ready, 5000);

    // Same address and token file, a fresh token.
    RefHost second;
    QVERIFY(startHost(second, ep));
    const QByteArray secondToken = readFile(ep.tokenFile);
    QVERIFY(!secondToken.isEmpty());
    QVERIFY(secondToken != firstToken);

    QTRY_COMPARE_WITH_TIMEOUT(b->channel()->state(), IpcChannel::Ready, 10000);
    QSignalSpy replied(b->channel(), &IpcChannel::replied);
    const qint64 id = b->channel()->call(QStringLiteral("status.get"), QJsonObject());
    QVERIFY(id > 0);
    // The backend re-subscribes on its own after the reconnect, so its reply
    // can arrive on either side of ours; match ours by id.
    const auto replyIndex = [&replied, id] {
        for (qsizetype i = 0; i < replied.size(); ++i) {
            if (replied.at(i).at(0).toLongLong() == id)
                return i;
        }
        return qsizetype(-1);
    };
    QTRY_VERIFY_WITH_TIMEOUT(replyIndex() >= 0, 5000);
    QCOMPARE(replied.at(replyIndex()).at(1).toJsonObject().value(QLatin1StringView("state")).toString(),
             QStringLiteral("idle"));

    // The subscription is back too: a run started now is observed to the end.
    s.start({QStringLiteral("10.0.0.0/30")}, QString(), false);
    QTRY_COMPARE_WITH_TIMEOUT(s.state(), ScanSession::Completed, kRunTimeoutMs);
    QCOMPARE(s.hostsFound(), 3);
    QCOMPARE(failed.count(), 0);
}

void TstIpcE2e::wrongTokenRefused()
{
    Endpoint ep;
    QVERIFY(ep.isValid());
    RefHost host;
    QVERIFY(startHost(host, ep));
    {
        QFile f(ep.tokenFile);
        QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QVERIFY(f.write("not-the-token-of-this-host") > 0);
    }

    auto b = makeBackend(ep);
    ScanSession s;
    s.setBackend(b.get());
    QSignalSpy events(b.get(), &ScanBackend::eventReceived);
    QSignalSpy attached(b.get(), &ScanBackend::runAttached);

    s.start({QStringLiteral("10.0.0.0/30")}, QString(), false);
    QTRY_COMPARE_WITH_TIMEOUT(s.state(), ScanSession::Failed, 10000);
    QCOMPARE(s.failure(), ScanSession::NotAuthorized);
    QCOMPARE(b->channel()->lastFailure(), IpcChannel::NotAuthorized);
    QCOMPARE(events.count(), 0);
    QCOMPARE(attached.count(), 0);
}

QTEST_MAIN(TstIpcE2e)
#include "tst_ipc_e2e.moc"
