// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "engineinfo.h"

#include <QElapsedTimer>
#include <QFile>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QVariantMap>

// EngineInfo is the single source of the engine's self-description
// (SGUI-02, D-08/D-21/D-23): it must decode --describe strictly, re-validate
// every local network (the auth gate trusts them, T-13-47) and degrade
// cleanly when the engine is missing, hangs (T-13-48) or answers garbage.
class TestEngineInfo : public QObject
{
    Q_OBJECT

private:
    static QByteArray fixture(const char *name)
    {
        QFile f(QStringLiteral(CYSEC_GUI_FIXTURES_DIR "/") + QString::fromLatin1(name));
        if (!f.open(QIODevice::ReadOnly))
            return {};
        return f.readAll();
    }

    static QString fixturePath(const char *name)
    {
        return QStringLiteral(CYSEC_GUI_FIXTURES_DIR "/") + QString::fromLatin1(name);
    }

    static QVariantMap net(const QString &iface, const QString &cidr)
    {
        return {{QStringLiteral("interface"), iface}, {QStringLiteral("cidr"), cidr}};
    }

private slots:
    void cleanup()
    {
        qunsetenv("FAKE_ENGINE_DESCRIBE");
        qunsetenv("FAKE_ENGINE_DESCRIBE_HOLD_MS");
        qunsetenv("FAKE_ENGINE_ARGV_OUT");
        qunsetenv("CYSEC_SCANNER_BIN");
    }

    void loadsFullDescribe()
    {
        EngineInfo info;
        QSignalSpy spy(&info, &EngineInfo::changed);
        QVERIFY(info.loadFromJson(fixture("describe-full.json")));
        QVERIFY(spy.count() >= 1);
        QVERIFY(info.loaded());
        QVERIFY(!info.failed());
        QCOMPARE(info.engineVersion(), QStringLiteral("v0.2.0"));
        QVERIFY(info.unprivilegedIcmp());
        QVERIFY(info.systemPing());
        QVERIFY(info.arpCache());
        const QVariantList expected{net(QStringLiteral("eth0"), QStringLiteral("192.0.2.0/24")),
                                    net(QStringLiteral("wlan0"), QStringLiteral("198.51.100.0/24"))};
        QCOMPARE(info.networks(), expected);
        QCOMPARE(info.localCidrs(),
                 (QStringList{QStringLiteral("192.0.2.0/24"), QStringLiteral("198.51.100.0/24")}));
        QCOMPARE(info.defaultPorts().size(), 37);
        QCOMPARE(info.defaultPorts().first(), 21);
        QCOMPARE(info.defaultPorts().last(), 27017);
        QCOMPARE(info.timingTiers(), QStringList{QStringLiteral("polite")});
    }

    void noIcmpCapability()
    {
        EngineInfo info;
        QVERIFY(info.loadFromJson(fixture("describe-no-icmp.json")));
        QVERIFY(!info.unprivilegedIcmp());
        QVERIFY(info.systemPing());
        // The fallback network carries no interface name.
        QCOMPARE(info.networks(),
                 QVariantList{net(QString(), QStringLiteral("192.0.2.0/24"))});
    }

    void noNetworks()
    {
        EngineInfo info;
        QVERIFY(info.loadFromJson(fixture("describe-no-networks.json")));
        QVERIFY(info.loaded());
        QVERIFY(info.networks().isEmpty());
        QVERIFY(info.localCidrs().isEmpty());
        QVERIFY(!info.arpCache());
    }

    void invalidCidrsAreDropped()
    {
        EngineInfo info;
        QVERIFY(info.loadFromJson(
            "{\"engine_version\":\"v0.2.0\",\"capabilities\":{},"
            "\"networks\":[{\"interface\":\"eth1\",\"cidr\":\"not-a-cidr\"},"
            "{\"interface\":\"eth2\",\"cidr\":\"999.0.2.0/24\"},"
            "{\"interface\":\"eth3\",\"cidr\":\"198.51.100.0/24\"}],"
            "\"default_ports\":[22],\"timing_tiers\":[\"polite\"]}"));
        QCOMPARE(info.localCidrs(), QStringList{QStringLiteral("198.51.100.0/24")});
        QCOMPARE(info.networks().size(), 1);
    }

    void invalidInput_data()
    {
        QTest::addColumn<QByteArray>("json");
        QTest::newRow("not json") << QByteArray("garbage");
        QTest::newRow("empty") << QByteArray();
        QTest::newRow("array") << QByteArray("[]");
        QTest::newRow("version number")
            << QByteArray("{\"engine_version\":2,\"capabilities\":{},\"networks\":[],"
                          "\"default_ports\":[],\"timing_tiers\":[]}");
        QTest::newRow("capability not bool")
            << QByteArray("{\"engine_version\":\"v1\",\"capabilities\":{\"unprivileged_icmp\":1},"
                          "\"networks\":[],\"default_ports\":[],\"timing_tiers\":[]}");
        QTest::newRow("networks missing")
            << QByteArray("{\"engine_version\":\"v1\",\"capabilities\":{},"
                          "\"default_ports\":[],\"timing_tiers\":[]}");
        QTest::newRow("network not object")
            << QByteArray("{\"engine_version\":\"v1\",\"capabilities\":{},\"networks\":[\"x\"],"
                          "\"default_ports\":[],\"timing_tiers\":[]}");
        QTest::newRow("network cidr missing")
            << QByteArray("{\"engine_version\":\"v1\",\"capabilities\":{},"
                          "\"networks\":[{\"interface\":\"eth0\"}],"
                          "\"default_ports\":[],\"timing_tiers\":[]}");
        QTest::newRow("port string")
            << QByteArray("{\"engine_version\":\"v1\",\"capabilities\":{},\"networks\":[],"
                          "\"default_ports\":[\"22\"],\"timing_tiers\":[]}");
        QTest::newRow("port out of range")
            << QByteArray("{\"engine_version\":\"v1\",\"capabilities\":{},\"networks\":[],"
                          "\"default_ports\":[70000],\"timing_tiers\":[]}");
        QTest::newRow("tier not string")
            << QByteArray("{\"engine_version\":\"v1\",\"capabilities\":{},\"networks\":[],"
                          "\"default_ports\":[],\"timing_tiers\":[1]}");
    }

    void invalidInput()
    {
        QFETCH(QByteArray, json);
        EngineInfo info;
        QVERIFY(info.loadFromJson(fixture("describe-full.json")));
        QVERIFY(!info.loadFromJson(json));
        QVERIFY(!info.loaded());
        QVERIFY(info.failed());
        // Previous facts stay as they were.
        QCOMPARE(info.engineVersion(), QStringLiteral("v0.2.0"));
        QCOMPARE(info.localCidrs().size(), 2);
        QCOMPARE(info.defaultPorts().size(), 37);
    }

    void successAfterFailureClearsFailed()
    {
        EngineInfo info;
        QVERIFY(!info.loadFromJson("garbage"));
        QVERIFY(info.failed());
        QVERIFY(info.loadFromJson(fixture("describe-full.json")));
        QVERIFY(info.loaded());
        QVERIFY(!info.failed());
    }

    void versions()
    {
        EngineInfo info;
        QVERIFY(!info.guiVersion().isEmpty());
        QCOMPARE(info.guiVersion(), QStringLiteral(CYSEC_SCANNER_GUI_VERSION));
        QCOMPARE(info.qtVersion(), QString::fromLatin1(qVersion()));
    }

#ifdef CYSEC_FAKE_ENGINE_PATH
    void refreshRunsDescribe()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString argvOut = dir.filePath(QStringLiteral("argv.txt"));
        qputenv("FAKE_ENGINE_DESCRIBE", fixturePath("describe-full.json").toUtf8());
        qputenv("FAKE_ENGINE_ARGV_OUT", argvOut.toUtf8());

        EngineInfo info;
        info.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
        info.refresh();
        QTRY_VERIFY_WITH_TIMEOUT(info.loaded(), 5000);
        QVERIFY(!info.failed());
        QCOMPARE(info.engineVersion(), QStringLiteral("v0.2.0"));

        QFile f(argvOut);
        QVERIFY(f.open(QIODevice::ReadOnly));
        QCOMPARE(f.readAll(), QByteArray("--describe\n"));
    }

    void refreshResolvesEngineFromEnvironment()
    {
        qputenv("FAKE_ENGINE_DESCRIBE", fixturePath("describe-no-icmp.json").toUtf8());
        qputenv("CYSEC_SCANNER_BIN", QByteArray(CYSEC_FAKE_ENGINE_PATH));
        EngineInfo info;
        info.refresh();
        QTRY_VERIFY_WITH_TIMEOUT(info.loaded(), 5000);
        QVERIFY(!info.unprivilegedIcmp());
    }

    void refreshGarbageFails()
    {
        qputenv("FAKE_ENGINE_DESCRIBE", "garbage");
        EngineInfo info;
        info.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
        info.refresh();
        QTRY_VERIFY_WITH_TIMEOUT(info.failed(), 5000);
        QVERIFY(!info.loaded());
    }

    void refreshOversizedOutputFails()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString big = dir.filePath(QStringLiteral("big.json"));
        QFile f(big);
        QVERIFY(f.open(QIODevice::WriteOnly));
        // Valid JSON, but past the 256 KiB read cap.
        QByteArray body = fixture("describe-full.json").trimmed();
        body.chop(1);
        body += ",\"pad\":\"" + QByteArray(300 * 1024, 'x') + "\"}";
        f.write(body);
        f.close();
        qputenv("FAKE_ENGINE_DESCRIBE", big.toUtf8());

        EngineInfo info;
        info.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
        info.refresh();
        QTRY_VERIFY_WITH_TIMEOUT(info.failed(), 5000);
        QVERIFY(!info.loaded());
    }

    void refreshHungEngineIsKilled()
    {
        qputenv("FAKE_ENGINE_DESCRIBE", fixturePath("describe-full.json").toUtf8());
        qputenv("FAKE_ENGINE_DESCRIBE_HOLD_MS", "30000");
        EngineInfo info;
        info.setEnginePath(QStringLiteral(CYSEC_FAKE_ENGINE_PATH));
        QElapsedTimer timer;
        timer.start();
        info.refresh();
        QTRY_VERIFY_WITH_TIMEOUT(info.failed(), 9000);
        QVERIFY(!info.loaded());
        QVERIFY(timer.elapsed() >= 4500);
    }
#endif

    void refreshMissingEngineFails()
    {
        EngineInfo info;
        info.setEnginePath(QStringLiteral("/nonexistent/cysec-scanner"));
        QElapsedTimer timer;
        timer.start();
        info.refresh();
        QTRY_VERIFY_WITH_TIMEOUT(info.failed(), 2000);
        QVERIFY(!info.loaded());
        QVERIFY(timer.elapsed() < 2000);
    }

    void refreshUnresolvableEngineFails()
    {
        qputenv("CYSEC_SCANNER_BIN", "/nonexistent/cysec-scanner");
        EngineInfo info;
        info.refresh();
        QTRY_VERIFY_WITH_TIMEOUT(info.failed(), 2000);
        QVERIFY(!info.loaded());
    }
};

QTEST_MAIN(TestEngineInfo)

#include "tst_engineinfo.moc"
