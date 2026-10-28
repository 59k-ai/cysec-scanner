// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// ProcessScanBackend against cysec-fake-engine: engine resolution (D-16),
// argv construction, every end state, the D-27 cancel escalation with a kill
// fallback, stderr draining, and no orphaned child.

#include "ndjsonparser.h"
#include "processscanbackend.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtTest>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <sys/types.h>
#endif

#ifndef CYSEC_FAKE_ENGINE_PATH
#error "tst_processbackend needs the cysec-fake-engine target"
#endif

namespace {

const char *const kFakeEnv[] = {
    "FAKE_ENGINE_FIXTURE",      "FAKE_ENGINE_PAYLOAD",      "FAKE_ENGINE_CANCEL_PAYLOAD",
    "FAKE_ENGINE_DELAY_MS",     "FAKE_ENGINE_HOLD_MS",      "FAKE_ENGINE_EXIT_CODE",
    "FAKE_ENGINE_IGNORE_STDIN", "FAKE_ENGINE_STDERR_BYTES", "FAKE_ENGINE_ARGV_OUT",
    "FAKE_ENGINE_PID_OUT",      "FAKE_ENGINE_DESCRIBE",     "CYSEC_SCANNER_BIN",
};

QString fixture(const char *name)
{
    return QStringLiteral(CYSEC_GUI_FIXTURES_DIR "/") + QLatin1StringView(name);
}

void setEnv(const char *name, const QString &value)
{
    qputenv(name, value.toLocal8Bit());
}

int fixtureLineCount(const char *name)
{
    QFile f(fixture(name));
    if (!f.open(QIODevice::ReadOnly))
        return -1;
    int n = 0;
    while (!f.atEnd()) {
        if (!f.readLine().trimmed().isEmpty())
            ++n;
    }
    return n;
}

qint64 readPid(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return -1;
    return f.readAll().trimmed().toLongLong();
}

// True when no process with this id exists any more (reaped, not a zombie).
bool processGone(qint64 pid)
{
#ifdef Q_OS_WIN
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, DWORD(pid));
    if (!h)
        return true;
    const bool exited = WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
    CloseHandle(h);
    return exited;
#else
    return ::kill(pid_t(pid), 0) == -1 && errno == ESRCH;
#endif
}

QString engineFileName()
{
#ifdef Q_OS_WIN
    return QStringLiteral("cysec-scanner.exe");
#else
    return QStringLiteral("cysec-scanner");
#endif
}

ScanRequest sampleRequest()
{
    ScanRequest r;
    r.cidrs = {QStringLiteral("192.0.2.0/24")};
    return r;
}

} // namespace

class TstProcessBackend : public QObject
{
    Q_OBJECT

private slots:
    void init();
    void cleanup();

    void resolveFromEnv();
    void resolveEnvMissingNoFallback();
    void resolveAppDirOnly();
    void resolveNeverPathOrCwd();
    void buildArguments();
    void buildArgumentsMinimal();
    void spawnedArgv();
    void happyPath();
    void cooperativeStop();
    void stubbornStopIsKilled();
    void engineMissing();
    void engineOverrideMissing();
    void stderrFloodNoDeadlock();
    void destroyWhileRunningKillsChild();

private:
    QTemporaryDir m_scratch;
    QString m_appDirEngine;
};

void TstProcessBackend::init()
{
    QVERIFY(m_scratch.isValid());
    for (const char *name : kFakeEnv)
        qunsetenv(name);
}

void TstProcessBackend::cleanup()
{
    for (const char *name : kFakeEnv)
        qunsetenv(name);
    if (!m_appDirEngine.isEmpty()) {
        QFile::remove(m_appDirEngine);
        m_appDirEngine.clear();
    }
}

void TstProcessBackend::resolveFromEnv()
{
    setEnv("CYSEC_SCANNER_BIN", QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
    QCOMPARE(ProcessScanBackend::resolveEnginePath(), QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
}

void TstProcessBackend::resolveEnvMissingNoFallback()
{
    // Even with an engine next to the app, a broken override never falls back.
    m_appDirEngine = QCoreApplication::applicationDirPath() + QLatin1Char('/') + engineFileName();
    QFile::remove(m_appDirEngine);
    QVERIFY(QFile::copy(QStringLiteral(CYSEC_FAKE_ENGINE_PATH), m_appDirEngine));
    setEnv("CYSEC_SCANNER_BIN", m_scratch.filePath(QStringLiteral("does-not-exist")));
    QVERIFY(ProcessScanBackend::resolveEnginePath().isEmpty());

    // A directory is not an engine either.
    setEnv("CYSEC_SCANNER_BIN", m_scratch.path());
    QVERIFY(ProcessScanBackend::resolveEnginePath().isEmpty());
}

void TstProcessBackend::resolveAppDirOnly()
{
    QVERIFY(ProcessScanBackend::resolveEnginePath().isEmpty());

    m_appDirEngine = QCoreApplication::applicationDirPath() + QLatin1Char('/') + engineFileName();
    QFile::remove(m_appDirEngine);
    QVERIFY(QFile::copy(QStringLiteral(CYSEC_FAKE_ENGINE_PATH), m_appDirEngine));
    QFile::setPermissions(m_appDirEngine, QFile::permissions(m_appDirEngine)
                                              | QFile::ExeOwner | QFile::ReadOwner);
    const QString resolved = ProcessScanBackend::resolveEnginePath();
    QCOMPARE(QFileInfo(resolved).canonicalFilePath(), QFileInfo(m_appDirEngine).canonicalFilePath());
}

void TstProcessBackend::resolveNeverPathOrCwd()
{
    // A planted engine on PATH and in the working directory is ignored.
    const QString planted = m_scratch.filePath(engineFileName());
    QFile::remove(planted);
    QVERIFY(QFile::copy(QStringLiteral(CYSEC_FAKE_ENGINE_PATH), planted));
    const QByteArray oldPath = qgetenv("PATH");
    const QString oldCwd = QDir::currentPath();
    qputenv("PATH", QFile::encodeName(m_scratch.path()) + QDir::listSeparator().toLatin1() + oldPath);
    QVERIFY(QDir::setCurrent(m_scratch.path()));

    const QString resolved = ProcessScanBackend::resolveEnginePath();

    QDir::setCurrent(oldCwd);
    qputenv("PATH", oldPath);
    QVERIFY2(resolved.isEmpty(), qPrintable(resolved));
}

void TstProcessBackend::buildArguments()
{
    ScanRequest r;
    r.cidrs = {QStringLiteral("192.0.2.0/24"), QStringLiteral("198.51.100.7/32")};
    r.portSpec = QStringLiteral("22,80");
    r.probeFragile = true;
    const QStringList expected = {
        "--payload-out", "/tmp/p.json",  "--events=detailed", "--cancel-on-stdin-eof",
        "--cidr",        "192.0.2.0/24", "--cidr",            "198.51.100.7/32",
        "--ports",       "22,80",        "--probe-fragile",
    };
    QCOMPARE(ProcessScanBackend::buildArguments(r, QStringLiteral("/tmp/p.json")), expected);
}

void TstProcessBackend::buildArgumentsMinimal()
{
    ScanRequest r;
    r.cidrs = {QStringLiteral("192.0.2.0/24")};
    const QStringList args = ProcessScanBackend::buildArguments(r, QStringLiteral("/tmp/p.json"));
    QCOMPARE(args, (QStringList{"--payload-out", "/tmp/p.json", "--events=detailed",
                                "--cancel-on-stdin-eof", "--cidr", "192.0.2.0/24"}));
    QVERIFY(!args.contains(QStringLiteral("--ports")));
    QVERIFY(!args.contains(QStringLiteral("--probe-fragile")));
    for (const QString &a : args)
        QVERIFY(!a.startsWith(QStringLiteral("--timing"))); // D-12
}

void TstProcessBackend::spawnedArgv()
{
    const QString argvOut = m_scratch.filePath(QStringLiteral("argv.txt"));
    setEnv("FAKE_ENGINE_ARGV_OUT", argvOut);
    ProcessScanBackend b;
    b.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
    QSignalSpy finished(&b, &ScanBackend::finished);
    ScanRequest r;
    r.cidrs = {QStringLiteral("192.0.2.0/24")};
    r.portSpec = QStringLiteral("22 80;x"); // passed as one argv element, never via a shell
    b.start(r);
    QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 5000);

    QFile f(argvOut);
    QVERIFY(f.open(QIODevice::ReadOnly));
    const QStringList got = QString::fromUtf8(f.readAll()).split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    QCOMPARE(got.size(), 8);
    QCOMPARE(got[0], QStringLiteral("--payload-out"));
    QVERIFY(QFileInfo(got[1]).fileName() == QStringLiteral("payload.json"));
    QCOMPARE(got.mid(2), (QStringList{"--events=detailed", "--cancel-on-stdin-eof", "--cidr",
                                      "192.0.2.0/24", "--ports", "22 80;x"}));
}

void TstProcessBackend::happyPath()
{
    setEnv("FAKE_ENGINE_FIXTURE", fixture("ndjson-detailed.ndjson"));
    setEnv("FAKE_ENGINE_PAYLOAD", fixture("payload-complete.json"));
    ProcessScanBackend b;
    b.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
    QSignalSpy events(&b, &ScanBackend::eventReceived);
    QSignalSpy finished(&b, &ScanBackend::finished);
    QSignalSpy failed(&b, &ScanBackend::failedToStart);

    b.start(sampleRequest());
    QVERIFY(b.isRunning());
    QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 5000);

    QCOMPARE(failed.count(), 0);
    QCOMPARE(events.count(), fixtureLineCount("ndjson-detailed.ndjson"));
    const ScanEvent first = events.first().first().value<ScanEvent>();
    QCOMPARE(first.kind, ScanEventKind::ScanStart);
    const ScanEvent last = events.last().first().value<ScanEvent>();
    QCOMPARE(last.kind, ScanEventKind::ScanEnd);

    const QList<QVariant> args = finished.first();
    QCOMPARE(args.at(0).value<ScanBackend::EndStatus>(), ScanBackend::Completed);
    QCOMPARE(args.at(1).toInt(), 0);
    const QString payload = args.at(2).toString();
    QVERIFY(QFileInfo::exists(payload));
    QVERIFY(QFileInfo(payload).size() > 0);
    QVERIFY(!b.isRunning());
}

void TstProcessBackend::cooperativeStop()
{
    setEnv("FAKE_ENGINE_FIXTURE", fixture("ndjson-detailed.ndjson"));
    setEnv("FAKE_ENGINE_CANCEL_PAYLOAD", fixture("payload-cancelled.json"));
    setEnv("FAKE_ENGINE_DELAY_MS", QStringLiteral("100"));
    setEnv("FAKE_ENGINE_HOLD_MS", QStringLiteral("30000"));
    ProcessScanBackend b;
    b.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
    QSignalSpy events(&b, &ScanBackend::eventReceived);
    QSignalSpy finished(&b, &ScanBackend::finished);

    b.start(sampleRequest());
    QTRY_VERIFY_WITH_TIMEOUT(events.count() >= 1, 5000);

    QElapsedTimer t;
    t.start();
    b.requestStop();
    QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 2000);
    QVERIFY2(t.elapsed() < 2000, "cooperative stop must not wait for the grace period");

    const QList<QVariant> args = finished.first();
    QCOMPARE(args.at(0).value<ScanBackend::EndStatus>(), ScanBackend::Cancelled);
    QCOMPARE(args.at(1).toInt(), 130);
    const QString payload = args.at(2).toString();
    QVERIFY(QFileInfo::exists(payload));
    QFile f(payload);
    QVERIFY(f.open(QIODevice::ReadOnly));
    QVERIFY(f.readAll().contains("\"scan_status\": \"cancelled\""));
}

void TstProcessBackend::stubbornStopIsKilled()
{
    const QString pidOut = m_scratch.filePath(QStringLiteral("stubborn.pid"));
    setEnv("FAKE_ENGINE_FIXTURE", fixture("ndjson-legacy.ndjson"));
    setEnv("FAKE_ENGINE_CANCEL_PAYLOAD", fixture("payload-cancelled.json"));
    setEnv("FAKE_ENGINE_IGNORE_STDIN", QStringLiteral("1"));
    setEnv("FAKE_ENGINE_HOLD_MS", QStringLiteral("30000"));
    setEnv("FAKE_ENGINE_PID_OUT", pidOut);
    ProcessScanBackend b;
    b.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
    b.setStopGraceMs(300);
    QSignalSpy events(&b, &ScanBackend::eventReceived);
    QSignalSpy finished(&b, &ScanBackend::finished);

    b.start(sampleRequest());
    QTRY_VERIFY_WITH_TIMEOUT(events.count() >= 5, 5000);
    const qint64 pid = readPid(pidOut);
    QVERIFY(pid > 0);

    QElapsedTimer t;
    t.start();
    b.requestStop();
    QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 3000);
    QVERIFY(t.elapsed() >= 250); // waited for the grace period first

    const QList<QVariant> args = finished.first();
    QCOMPARE(args.at(0).value<ScanBackend::EndStatus>(), ScanBackend::Cancelled);
    QVERIFY(args.at(1).toInt() != 0);
    QVERIFY(args.at(2).toString().isEmpty());
    QVERIFY(!b.isRunning());
    QVERIFY2(processGone(pid), "killed engine must not survive as an orphan");
}

void TstProcessBackend::engineMissing()
{
    setEnv("CYSEC_SCANNER_BIN", m_scratch.filePath(QStringLiteral("absent-engine")));
    ProcessScanBackend b;
    QSignalSpy failed(&b, &ScanBackend::failedToStart);
    QSignalSpy finished(&b, &ScanBackend::finished);
    b.start(sampleRequest());
    QTRY_COMPARE_WITH_TIMEOUT(failed.count(), 1, 2000);
    QCOMPARE(failed.first().at(0).value<ScanBackend::StartError>(), ScanBackend::EngineNotFound);
    QTest::qWait(100);
    QCOMPARE(finished.count(), 0);
    QVERIFY(!b.isRunning());
}

void TstProcessBackend::engineOverrideMissing()
{
    ProcessScanBackend b;
    b.setEnginePath(m_scratch.filePath(QStringLiteral("absent-engine")));
    QSignalSpy failed(&b, &ScanBackend::failedToStart);
    QSignalSpy finished(&b, &ScanBackend::finished);
    b.start(sampleRequest());
    QTRY_COMPARE_WITH_TIMEOUT(failed.count(), 1, 2000);
    QCOMPARE(failed.first().at(0).value<ScanBackend::StartError>(), ScanBackend::EngineNotFound);
    QCOMPARE(finished.count(), 0);
}

void TstProcessBackend::stderrFloodNoDeadlock()
{
    setEnv("FAKE_ENGINE_STDERR_BYTES", QString::number(200 * 1024));
    setEnv("FAKE_ENGINE_EXIT_CODE", QStringLiteral("1"));
    setEnv("FAKE_ENGINE_FIXTURE", fixture("ndjson-legacy.ndjson"));
    ProcessScanBackend b;
    b.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
    QSignalSpy finished(&b, &ScanBackend::finished);
    QSignalSpy events(&b, &ScanBackend::eventReceived);
    b.start(sampleRequest());
    QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 10000);

    const QList<QVariant> args = finished.first();
    QCOMPARE(args.at(0).value<ScanBackend::EndStatus>(), ScanBackend::Failed);
    QCOMPARE(args.at(1).toInt(), 1);
    QVERIFY(args.at(2).toString().isEmpty());
    QCOMPARE(events.count(), 5);

    const QStringList tail = b.diagnosticsTail();
    QVERIFY(!tail.isEmpty());
    QVERIFY(tail.size() <= 20);
    for (const QString &line : tail) {
        for (const QChar c : line)
            QVERIFY2(c.category() != QChar::Other_Control, qPrintable(line));
    }
    QVERIFY(tail.last().contains(QStringLiteral("line")));
}

void TstProcessBackend::destroyWhileRunningKillsChild()
{
    const QString pidOut = m_scratch.filePath(QStringLiteral("destroy.pid"));
    setEnv("FAKE_ENGINE_FIXTURE", fixture("ndjson-legacy.ndjson"));
    setEnv("FAKE_ENGINE_IGNORE_STDIN", QStringLiteral("1"));
    setEnv("FAKE_ENGINE_HOLD_MS", QStringLiteral("30000"));
    setEnv("FAKE_ENGINE_PID_OUT", pidOut);
    auto *b = new ProcessScanBackend;
    b->setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
    QSignalSpy events(b, &ScanBackend::eventReceived);
    b->start(sampleRequest());
    QTRY_VERIFY_WITH_TIMEOUT(events.count() >= 5, 5000);
    const qint64 pid = readPid(pidOut);
    QVERIFY(pid > 0);
    QVERIFY(!processGone(pid));

    delete b;
    QTRY_VERIFY_WITH_TIMEOUT(processGone(pid), 2000);
}

// QTEST_MAIN (QGuiApplication) because ctest passes -platform offscreen.
QTEST_MAIN(TstProcessBackend)
#include "tst_processbackend.moc"
