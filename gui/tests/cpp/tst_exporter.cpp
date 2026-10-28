// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Exporter: JSON export is a verbatim byte copy of the engine payload
// (T-13-40), written atomically (T-13-42); CSV is RFC 4180 UTF-8 with a
// stable column set, a partial label on every row and a spreadsheet
// formula-injection guard (T-13-38).

#include "exporter.h"
#include "hostmodel.h"

#include <QDir>
#include <QFile>
#include <QRegularExpression>
#include <QTemporaryDir>
#include <QtTest>

namespace {

QString fixturePath(const char *name)
{
    return QStringLiteral(CYSEC_GUI_FIXTURES_DIR "/") + QLatin1StringView(name);
}

QByteArray readAll(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return {};
    return f.readAll();
}

ServiceFact svc(int port)
{
    ServiceFact s;
    s.port = port;
    s.protocol = QStringLiteral("tcp");
    return s;
}

HostFact hostileHost()
{
    HostFact h;
    h.ip = QStringLiteral("192.0.2.10");
    h.externalId = QStringLiteral("ip:192.0.2.10");
    h.hostname = QStringLiteral("=cmd|' /C calc'!A0");
    h.macVendor = QStringLiteral("Vendor, Inc.");
    h.services = {svc(22), svc(80)};
    h.servicesKnown = true;
    h.osGuess = QStringLiteral("Linux");
    return h;
}

// Minimal RFC 4180 reader: CRLF records, quoted fields with doubled quotes.
QList<QStringList> parseCsv(const QByteArray &bytes)
{
    const QString text = QString::fromUtf8(bytes);
    QList<QStringList> rows;
    QStringList row;
    QString cell;
    bool quoted = false;
    for (qsizetype i = 0; i < text.size(); ++i) {
        const QChar c = text.at(i);
        if (quoted) {
            if (c == u'"') {
                if (i + 1 < text.size() && text.at(i + 1) == u'"') {
                    cell += u'"';
                    ++i;
                } else {
                    quoted = false;
                }
            } else {
                cell += c;
            }
            continue;
        }
        if (c == u'"') {
            quoted = true;
        } else if (c == u',') {
            row.append(cell);
            cell.clear();
        } else if (c == u'\r' && i + 1 < text.size() && text.at(i + 1) == u'\n') {
            row.append(cell);
            cell.clear();
            rows.append(row);
            row.clear();
            ++i;
        } else {
            cell += c;
        }
    }
    if (!cell.isEmpty() || !row.isEmpty()) {
        row.append(cell);
        rows.append(row);
    }
    return rows;
}

} // namespace

class TestExporter : public QObject
{
    Q_OBJECT

private slots:
    void defaultFileNames();
    void jsonByteIdentical();
    void jsonMissingSource();
    void jsonUnwritableTargetLeavesNothing();
    void jsonInvalidSourceRejected();
    void jsonNonLocalTargetRejected();
    void csvHostileRowPartial();
    void csvCompleteAndGuards_data();
    void csvCompleteAndGuards();
    void csvRoundTrip();
    void csvExportFromHostModel();
    void csvExportNullModel();
};

void TestExporter::defaultFileNames()
{
    Exporter e;
    static const QRegularExpression jsonRe(QStringLiteral("^cysec-scan-\\d{8}-\\d{6}\\.json$"));
    static const QRegularExpression csvRe(
        QStringLiteral("^cysec-scan-\\d{8}-\\d{6}-partial\\.csv$"));
    QVERIFY2(jsonRe.match(e.defaultFileName(QStringLiteral("json"), false)).hasMatch(),
             qPrintable(e.defaultFileName(QStringLiteral("json"), false)));
    QVERIFY2(csvRe.match(e.defaultFileName(QStringLiteral("csv"), true)).hasMatch(),
             qPrintable(e.defaultFileName(QStringLiteral("csv"), true)));
    QVERIFY(e.defaultFileName(QStringLiteral("exe"), false).isEmpty());
}

void TestExporter::jsonByteIdentical()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString src = fixturePath("payload-export-cancelled.json");
    const QString out = dir.filePath(QStringLiteral("out.json"));
    Exporter e;
    const QVariantMap r = e.exportJson(src, QUrl::fromLocalFile(out));
    QVERIFY2(r.value("ok").toBool(), qPrintable(r.value("error").toString()));
    const QByteArray in = readAll(src);
    const QByteArray written = readAll(out);
    QVERIFY(!in.isEmpty());
    QCOMPARE(written, in);
    QVERIFY(written.contains("\"scan_status\": \"cancelled\""));
    // Non-canonical spellings survive only if nothing re-serialised them.
    QVERIFY(written.contains("1.50e-1"));
    QVERIFY(written.contains("\\u00e9"));
}

void TestExporter::jsonMissingSource()
{
    QTemporaryDir dir;
    Exporter e;
    const QString out = dir.filePath(QStringLiteral("out.json"));
    const QVariantMap r =
        e.exportJson(dir.filePath(QStringLiteral("nope.json")), QUrl::fromLocalFile(out));
    QVERIFY(!r.value("ok").toBool());
    QVERIFY(!r.value("error").toString().isEmpty());
    QVERIFY(!QFile::exists(out));
}

void TestExporter::jsonUnwritableTargetLeavesNothing()
{
    QTemporaryDir dir;
    const QString locked = dir.filePath(QStringLiteral("locked"));
    QVERIFY(QDir().mkdir(locked));
    QVERIFY(QFile::setPermissions(locked, QFileDevice::ReadOwner | QFileDevice::ExeOwner));
    Exporter e;
    const QString out = locked + QStringLiteral("/out.json");
    const QVariantMap r =
        e.exportJson(fixturePath("payload-export-cancelled.json"), QUrl::fromLocalFile(out));
    QFile::setPermissions(locked, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner);
    QVERIFY(!r.value("ok").toBool());
    QVERIFY(!r.value("error").toString().isEmpty());
    QVERIFY(QDir(locked).entryList(QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden)
                .isEmpty());
}

void TestExporter::jsonInvalidSourceRejected()
{
    QTemporaryDir dir;
    const QString src = dir.filePath(QStringLiteral("bad.json"));
    {
        QFile f(src);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("{\"schema_version\": 7, ");
    }
    const QString out = dir.filePath(QStringLiteral("out.json"));
    Exporter e;
    const QVariantMap r = e.exportJson(src, QUrl::fromLocalFile(out));
    QVERIFY(!r.value("ok").toBool());
    QVERIFY(!QFile::exists(out));
}

void TestExporter::jsonNonLocalTargetRejected()
{
    Exporter e;
    const QVariantMap r = e.exportJson(fixturePath("payload-export-cancelled.json"),
                                       QUrl(QStringLiteral("https://example.test/out.json")));
    QVERIFY(!r.value("ok").toBool());
}

void TestExporter::csvHostileRowPartial()
{
    const QByteArray csv = Exporter::csvForHosts({hostileHost()}, true);
    QVERIFY(!csv.startsWith("\xEF\xBB\xBF"));
    const QList<QByteArray> lines = csv.split('\n');
    QCOMPARE(lines.value(0), QByteArray("ip,hostname,mac,mac_vendor,open_ports,os_guess,scan_status\r"));
    QVERIFY(csv.endsWith("\r\n"));
    const QByteArray row = lines.value(1);
    QCOMPARE(row, QByteArray("192.0.2.10,'=cmd|' /C calc'!A0,,\"Vendor, Inc.\","
                             "22/tcp 80/tcp,Linux,partial\r"));
}

void TestExporter::csvCompleteAndGuards_data()
{
    QTest::addColumn<QString>("value");
    QTest::addColumn<QString>("cell");

    QTest::newRow("plain") << "host-a" << "host-a";
    QTest::newRow("empty") << "" << "";
    QTest::newRow("equals") << "=1+1" << "'=1+1";
    QTest::newRow("plus") << "+1" << "'+1";
    QTest::newRow("minus") << "-1" << "'-1";
    QTest::newRow("at") << "@SUM(A1)" << "'@SUM(A1)";
    QTest::newRow("tab") << "\tx" << "'\tx";
    QTest::newRow("cr") << "\rx" << "\"'\rx\"";
    QTest::newRow("quote doubles") << "a\"b" << "\"a\"\"b\"";
    QTest::newRow("comma quoted") << "a,b" << "\"a,b\"";
    QTest::newRow("newline quoted") << "a\nb" << "\"a\nb\"";
    QTest::newRow("inner equals untouched") << "a=b" << "a=b";
    QTest::newRow("utf8") << QString::fromUtf8("h\xC3\xA9te") << QString::fromUtf8("h\xC3\xA9te");
}

void TestExporter::csvCompleteAndGuards()
{
    QFETCH(QString, value);
    QFETCH(QString, cell);
    QCOMPARE(Exporter::csvCell(value), cell);

    HostFact h;
    h.ip = QStringLiteral("192.0.2.20");
    h.hostname = value;
    const QByteArray csv = Exporter::csvForHosts({h}, false);
    QVERIFY(csv.endsWith(",complete\r\n"));
}

void TestExporter::csvRoundTrip()
{
    HostFact a = hostileHost();
    HostFact b;
    b.ip = QStringLiteral("192.0.2.11");
    b.hostname = QStringLiteral("multi\nline \"quoted\"");
    b.mac = QStringLiteral("02:00:5e:10:00:11");
    b.macVendor = QString::fromUtf8("M\xC3\xBCller GmbH");
    b.osGuess = QStringLiteral("@risky");

    QTemporaryDir dir;
    const QString path = dir.filePath(QStringLiteral("rt.csv"));
    {
        QFile f(path);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write(Exporter::csvForHosts({a, b}, true));
    }
    const QList<QStringList> rows = parseCsv(readAll(path));
    QCOMPARE(rows.size(), 3);
    QCOMPARE(rows.at(0), (QStringList{"ip", "hostname", "mac", "mac_vendor", "open_ports",
                                      "os_guess", "scan_status"}));
    QCOMPARE(rows.at(1), (QStringList{a.ip, QStringLiteral("'") + a.hostname, QString(),
                                      a.macVendor, "22/tcp 80/tcp", a.osGuess, "partial"}));
    QCOMPARE(rows.at(2), (QStringList{b.ip, b.hostname, b.mac, b.macVendor, QString(),
                                      QStringLiteral("'@risky"), "partial"}));
}

void TestExporter::csvExportFromHostModel()
{
    HostModel model;
    model.upsert(hostileHost());
    QTemporaryDir dir;
    const QString out = dir.filePath(QStringLiteral("hosts.csv"));
    Exporter e;
    const QVariantMap r = e.exportCsv(&model, false, QUrl::fromLocalFile(out));
    QVERIFY2(r.value("ok").toBool(), qPrintable(r.value("error").toString()));
    QCOMPARE(readAll(out), Exporter::csvForHosts(model.hosts(), false));
}

void TestExporter::csvExportNullModel()
{
    QTemporaryDir dir;
    const QString out = dir.filePath(QStringLiteral("hosts.csv"));
    Exporter e;
    QVERIFY(!e.exportCsv(nullptr, true, QUrl::fromLocalFile(out)).value("ok").toBool());
    QVERIFY(!QFile::exists(out));
}

QTEST_MAIN(TestExporter)
#include "tst_exporter.moc"
