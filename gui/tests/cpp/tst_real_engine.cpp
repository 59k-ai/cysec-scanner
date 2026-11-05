// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// End-to-end check of the GUI stack against the real cysec-scanner engine:
// ScanSession over ProcessScanBackend, exactly as the app wires them. CI
// builds the engine and sets CYSEC_SCANNER_BIN; without it the test skips.
//
// The stop slot proves the cooperative cancel (stdin EOF) on every OS,
// including Windows, where there is no SIGTERM: the engine must write a
// payload marked cancelled and the session must end Partial.

#include "processscanbackend.h"
#include "scansession.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QObject>
#include <QStringList>
#include <QtTest>

#include <memory>

class TstRealEngine : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void complete();
    void stop();
    void noOrphan();
    void cleanupTestCase();

private:
    static QJsonObject readPayload(const QString &path);

    std::unique_ptr<ProcessScanBackend> m_backend;
    std::unique_ptr<ScanSession> m_session;
    int m_events = 0;
};

void TstRealEngine::initTestCase()
{
    if (qEnvironmentVariableIsEmpty("CYSEC_SCANNER_BIN"))
        QSKIP("CYSEC_SCANNER_BIN is not set; build the engine and point it at the binary "
              "to run the real-engine integration test");

    m_backend = std::make_unique<ProcessScanBackend>();
    m_session = std::make_unique<ScanSession>();
    m_session->setBackend(m_backend.get());
    connect(m_backend.get(), &ScanBackend::eventReceived, this, [this] { ++m_events; });
}

QJsonObject TstRealEngine::readPayload(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return {};
    return QJsonDocument::fromJson(f.readAll()).object();
}

void TstRealEngine::complete()
{
    m_session->start({QStringLiteral("127.0.0.1/32")}, QString(), false);
    QCOMPARE(m_session->state(), ScanSession::Running);

    QTRY_VERIFY_WITH_TIMEOUT(m_session->state() != ScanSession::Running, 120000);
    QVERIFY2(m_session->state() == ScanSession::Completed,
             qPrintable(QStringLiteral("state %1 failure %2 exit %3: %4")
                            .arg(int(m_session->state()))
                            .arg(int(m_session->failure()))
                            .arg(m_session->exitCode())
                            .arg(m_session->failureDetail())));
    QVERIFY(m_session->hasPayload());
    QVERIFY(!m_session->partial());

    const QJsonObject payload = readPayload(m_session->payloadPath());
    QVERIFY(!payload.isEmpty());
    QCOMPARE(payload.value(QStringLiteral("schema_version")).toInt(), 8);
    QVERIFY(payload.contains(QStringLiteral("scan_status")));
    QVERIFY(payload.value(QStringLiteral("scan_status")).isNull());
    QVERIFY(m_events > 0);
}

void TstRealEngine::stop()
{
    m_events = 0;
    // TEST-NET-1: nothing answers, so the scan runs long enough to stop.
    m_session->start({QStringLiteral("192.0.2.0/24")}, QString(), false);
    QCOMPARE(m_session->state(), ScanSession::Running);

    QTRY_VERIFY_WITH_TIMEOUT(m_events > 0, 15000);
    QCOMPARE(m_session->state(), ScanSession::Running);
    m_session->stop();
    QCOMPARE(m_session->state(), ScanSession::Stopping);

    QTRY_COMPARE_WITH_TIMEOUT(m_session->state(), ScanSession::Partial, 6000);
    QVERIFY(m_session->partial());
    QVERIFY(m_session->hasPayload());

    const QJsonObject payload = readPayload(m_session->payloadPath());
    QCOMPARE(payload.value(QStringLiteral("schema_version")).toInt(), 8);
    QCOMPARE(payload.value(QStringLiteral("scan_status")).toString(), QStringLiteral("cancelled"));
}

void TstRealEngine::noOrphan()
{
    // After the stop the child is gone, not merely detached.
    QVERIFY(!m_backend->isRunning());
}

void TstRealEngine::cleanupTestCase()
{
    m_session.reset();
    m_backend.reset();
}

QTEST_MAIN(TstRealEngine)
#include "tst_real_engine.moc"
