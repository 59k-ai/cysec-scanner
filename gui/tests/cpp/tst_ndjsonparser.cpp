// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// NdjsonParser + NdjsonLineBuffer: robust decoding of the engine's detailed
// NDJSON progress stream (split reads, CRLF, junk, oversized lines, unknown
// kinds, hostile strings).

#include "ndjsonparser.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QtTest>

namespace {

QByteArray readFixture(const char *name)
{
    QFile f(QStringLiteral(CYSEC_GUI_FIXTURES_DIR "/") + QLatin1StringView(name));
    if (!f.open(QIODevice::ReadOnly))
        return {};
    return f.readAll();
}

// Feeds a whole fixture through the line buffer, as the transport does.
QList<QByteArray> fixtureLines(const char *name)
{
    NdjsonLineBuffer buf;
    return buf.append(readFixture(name));
}

QList<ScanEvent> parseAll(const QList<QByteArray> &lines, int *rejected = nullptr)
{
    QList<ScanEvent> out;
    int bad = 0;
    for (const QByteArray &line : lines) {
        if (auto ev = NdjsonParser::parseLine(line))
            out.append(*ev);
        else
            ++bad;
    }
    if (rejected)
        *rejected = bad;
    return out;
}

} // namespace

class TstNdjsonParser : public QObject
{
    Q_OBJECT

private slots:
    void legacyFixture();
    void detailedFixture();
    void nullableHostFields();
    void servicesKnown();
    void unknownAndMalformed_data();
    void unknownAndMalformed();
    void junkFixture();
    void lineBufferSplitReads();
    void lineBufferSkipsEmptyLines();
    void lineBufferOverflow();
    void lineBufferOverflowCompleteLine();
    void lineBufferReset();
    void hostileStringsPreserved();
    void parseObjectMatchesParseLine_data();
    void parseObjectMatchesParseLine();
};

void TstNdjsonParser::legacyFixture()
{
    const QList<ScanEvent> ev = parseAll(fixtureLines("ndjson-legacy.ndjson"));
    QCOMPARE(ev.size(), 5);
    const ScanEventKind kinds[] = {ScanEventKind::PhaseStart, ScanEventKind::AgentStart,
                                   ScanEventKind::AgentStart, ScanEventKind::AgentStart,
                                   ScanEventKind::PhaseDone};
    const char *agents[] = {"", "discovery", "port", "fingerprint", ""};
    for (int i = 0; i < 5; ++i) {
        QCOMPARE(ev[i].kind, kinds[i]);
        QCOMPARE(ev[i].seq, i);
        QCOMPARE(ev[i].agent, QString::fromLatin1(agents[i]));
        QVERIFY(ev[i].ts > 1.7e9);
    }
}

void TstNdjsonParser::detailedFixture()
{
    const QList<ScanEvent> ev = parseAll(fixtureLines("ndjson-detailed.ndjson"));
    QCOMPARE(ev.size(), 12);

    const ScanEvent &start = ev[0];
    QCOMPARE(start.kind, ScanEventKind::ScanStart);
    QCOMPARE(start.scope, (QStringList{"192.0.2.0/24", "198.51.100.7/32"}));
    QCOMPARE(start.stages, (QStringList{"discovery", "port", "fingerprint"}));
    QVERIFY(start.hasCapabilities);
    QCOMPARE(start.capUnprivilegedIcmp, false);
    QCOMPARE(start.capSystemPing, true);
    QCOMPARE(start.capArpCache, true);

    QCOMPARE(ev[4].kind, ScanEventKind::AgentDone);
    QCOMPARE(ev[4].agent, QStringLiteral("discovery"));

    const ScanEvent &prog = ev[6];
    QCOMPARE(prog.kind, ScanEventKind::StageProgress);
    QCOMPARE(prog.agent, QStringLiteral("port"));
    QCOMPARE(prog.done, 1200);
    QCOMPARE(prog.total, 9472);

    const ScanEvent &host = ev[7];
    QCOMPARE(host.kind, ScanEventKind::Host);
    QCOMPARE(host.host.ip, QStringLiteral("192.0.2.10"));
    QCOMPARE(host.host.externalId, QStringLiteral("mac:02:00:5e:10:00:10"));
    QCOMPARE(host.host.hostname, QStringLiteral("host-a"));
    QCOMPARE(host.host.mac, QStringLiteral("02:00:5e:10:00:10"));
    QCOMPARE(host.host.macVendor, QStringLiteral("generic-vendor"));
    QCOMPARE(host.host.osGuess, QStringLiteral("generic-linux"));
    QCOMPARE(host.host.osGuessConfidence, 0.75);
    QVERIFY(host.host.servicesKnown);
    QCOMPARE(host.host.services.size(), 2);
    QCOMPARE(host.host.services[0].port, 22);
    QCOMPARE(host.host.services[0].protocol, QStringLiteral("tcp"));
    QCOMPARE(host.host.services[0].serviceName, QStringLiteral("ssh"));
    QVERIFY(host.host.services[0].product.isEmpty());
    QVERIFY(host.host.services[0].version.isEmpty());
    QCOMPARE(host.host.services[1].product, QStringLiteral("generic-httpd"));
    QCOMPARE(host.host.services[1].version, QStringLiteral("1.0.0"));

    const ScanEvent &log = ev[8];
    QCOMPARE(log.kind, ScanEventKind::Log);
    QCOMPARE(log.logLevel, QStringLiteral("warn"));
    QVERIFY(log.logMessage.contains(QStringLiteral("198.51.100.7")));

    const ScanEvent &end = ev[11];
    QCOMPARE(end.kind, ScanEventKind::ScanEnd);
    QCOMPARE(end.endStatus, QStringLiteral("cancelled"));
    QVERIFY(end.endError.isEmpty());
    QCOMPARE(end.endAssets, 3);
    QCOMPARE(end.seq, 11);
}

void TstNdjsonParser::nullableHostFields()
{
    const auto ev = NdjsonParser::parseLine(
        "{\"kind\":\"host\",\"seq\":3,\"ts\":1.5,\"phase\":\"scan\",\"agent\":\"discovery\",\"errors\":0,"
        "\"warnings\":0,\"assets\":1,\"host\":{\"ip\":\"192.0.2.20\",\"external_id\":\"ip:192.0.2.20\","
        "\"hostname\":\"\",\"mac\":null,\"mac_vendor\":null,\"os_guess\":null,\"os_guess_confidence\":null}}");
    QVERIFY(ev.has_value());
    QCOMPARE(ev->kind, ScanEventKind::Host);
    QVERIFY(ev->host.mac.isEmpty());
    QVERIFY(ev->host.macVendor.isEmpty());
    QVERIFY(ev->host.osGuess.isEmpty());
    QCOMPARE(ev->host.osGuessConfidence, -1.0);
}

void TstNdjsonParser::servicesKnown()
{
    const auto absent = NdjsonParser::parseLine(
        "{\"kind\":\"host\",\"seq\":0,\"ts\":0,\"phase\":\"scan\",\"agent\":\"discovery\",\"errors\":0,"
        "\"warnings\":0,\"assets\":1,\"host\":{\"ip\":\"192.0.2.1\"}}");
    QVERIFY(absent.has_value());
    QCOMPARE(absent->host.servicesKnown, false);
    QVERIFY(absent->host.services.isEmpty());

    const auto empty = NdjsonParser::parseLine(
        "{\"kind\":\"host\",\"seq\":0,\"ts\":0,\"phase\":\"scan\",\"agent\":\"port\",\"errors\":0,"
        "\"warnings\":0,\"assets\":1,\"host\":{\"ip\":\"192.0.2.1\",\"services\":[]}}");
    QVERIFY(empty.has_value());
    QCOMPARE(empty->host.servicesKnown, true);
    QVERIFY(empty->host.services.isEmpty());
}

void TstNdjsonParser::unknownAndMalformed_data()
{
    QTest::addColumn<QByteArray>("line");
    QTest::addColumn<bool>("decodes");
    QTest::addColumn<int>("kind");

    QTest::newRow("future_kind")
        << QByteArray("{\"kind\":\"future_kind\",\"seq\":9,\"ts\":1,\"phase\":\"scan\",\"agent\":null}")
        << true << int(ScanEventKind::Unknown);
    QTest::newRow("kind-missing") << QByteArray("{\"seq\":1}") << true
                                  << int(ScanEventKind::Unknown);
    QTest::newRow("kind-wrong-type") << QByteArray("{\"kind\":7}") << true
                                     << int(ScanEventKind::Unknown);
    QTest::newRow("malformed") << QByteArray("{\"kind\":\"host\",") << false << 0;
    QTest::newRow("array") << QByteArray("[{\"kind\":\"host\"}]") << false << 0;
    QTest::newRow("string") << QByteArray("\"phase_start\"") << false << 0;
    QTest::newRow("number") << QByteArray("42") << false << 0;
    QTest::newRow("empty") << QByteArray() << false << 0;
}

void TstNdjsonParser::unknownAndMalformed()
{
    QFETCH(QByteArray, line);
    QFETCH(bool, decodes);
    QFETCH(int, kind);
    const auto ev = NdjsonParser::parseLine(line);
    QCOMPARE(ev.has_value(), decodes);
    if (decodes)
        QCOMPARE(int(ev->kind), kind);
}

void TstNdjsonParser::junkFixture()
{
    const QList<QByteArray> lines = fixtureLines("ndjson-junk.ndjson");
    QCOMPARE(lines.size(), 9); // the empty line is skipped by the buffer
    int rejected = 0;
    const QList<ScanEvent> ev = parseAll(lines, &rejected);
    QCOMPARE(rejected, 4); // prose, array, truncated object, bare string
    QCOMPARE(ev.size(), 5);
    QCOMPARE(ev[0].kind, ScanEventKind::PhaseStart);
    QCOMPARE(ev[1].kind, ScanEventKind::Unknown);

    // Wrong-typed fields fall back to defaults instead of asserting.
    QCOMPARE(ev[2].kind, ScanEventKind::AgentStart);
    QCOMPARE(ev[2].seq, -1);
    QCOMPARE(ev[2].ts, 0.0);
    QVERIFY(ev[2].agent.isEmpty());
    QCOMPARE(ev[3].kind, ScanEventKind::StageProgress);
    QCOMPARE(ev[3].done, 0);
    QCOMPARE(ev[3].total, 0);

    QCOMPARE(ev[4].kind, ScanEventKind::PhaseDone);
    QCOMPARE(ev[4].seq, 5);
}

void TstNdjsonParser::lineBufferSplitReads()
{
    NdjsonLineBuffer buf;
    QVERIFY(buf.append("{\"kind\":\"pha").isEmpty());
    const QList<QByteArray> lines = buf.append("se_start\",\"seq\":0}\n"
                                               "{\"kind\":\"phase_done\",\"seq\":1}\r\n");
    QCOMPARE(lines.size(), 2);
    QCOMPARE(lines[0], QByteArray("{\"kind\":\"phase_start\",\"seq\":0}"));
    QCOMPARE(lines[1], QByteArray("{\"kind\":\"phase_done\",\"seq\":1}"));
    QVERIFY(!lines[1].endsWith('\r'));
    QCOMPARE(NdjsonParser::parseLine(lines[0])->kind, ScanEventKind::PhaseStart);
    QCOMPARE(NdjsonParser::parseLine(lines[1])->kind, ScanEventKind::PhaseDone);
    QVERIFY(!buf.overflowed());

    // Byte-at-a-time delivery yields the same line.
    NdjsonLineBuffer slow;
    const QByteArray whole = "{\"kind\":\"log\",\"seq\":2}"
                             "\r\n";
    QList<QByteArray> got;
    for (char c : whole)
        got += slow.append(QByteArray(1, c));
    QCOMPARE(got, (QList<QByteArray>{"{\"kind\":\"log\",\"seq\":2}"}));
}

void TstNdjsonParser::lineBufferSkipsEmptyLines()
{
    NdjsonLineBuffer buf;
    const QList<QByteArray> lines = buf.append("\n\r\n  \n{\"a\":1}\n\n");
    QCOMPARE(lines, (QList<QByteArray>{"{\"a\":1}"}));
}

void TstNdjsonParser::lineBufferOverflow()
{
    NdjsonLineBuffer buf;
    const QByteArray huge(NdjsonLineBuffer::kMaxLineBytes + 1, 'x');
    QVERIFY(buf.append(huge).isEmpty());
    QVERIFY(buf.overflowed());

    // The rest of the oversized line is discarded up to the next newline,
    // never accumulated; the following valid line still parses.
    QVERIFY(buf.append(QByteArray(4096, 'y')).isEmpty());
    const QList<QByteArray> lines = buf.append(
        "tail-of-oversized\n"
        "{\"kind\":\"phase_done\",\"seq\":7}"
        "\n");
    QCOMPARE(lines.size(), 1);
    const auto ev = NdjsonParser::parseLine(lines[0]);
    QVERIFY(ev.has_value());
    QCOMPARE(ev->kind, ScanEventKind::PhaseDone);
    QCOMPARE(ev->seq, 7);
    QVERIFY(buf.overflowed()); // sticky until reset()
}

void TstNdjsonParser::lineBufferOverflowCompleteLine()
{
    // An over-cap line that arrives with its newline is dropped too.
    NdjsonLineBuffer buf;
    QByteArray chunk(NdjsonLineBuffer::kMaxLineBytes + 10, 'z');
    chunk += "\n{\"kind\":\"log\"}\n";
    const QList<QByteArray> lines = buf.append(chunk);
    QCOMPARE(lines, (QList<QByteArray>{"{\"kind\":\"log\"}"}));
    QVERIFY(buf.overflowed());
}

void TstNdjsonParser::lineBufferReset()
{
    NdjsonLineBuffer buf;
    buf.append(QByteArray(NdjsonLineBuffer::kMaxLineBytes + 1, 'x'));
    QVERIFY(buf.overflowed());
    buf.reset();
    QVERIFY(!buf.overflowed());
    // After reset the buffer is no longer discarding.
    QCOMPARE(buf.append("{\"a\":1}\n"), (QList<QByteArray>{"{\"a\":1}"}));
}

void TstNdjsonParser::hostileStringsPreserved()
{
    const QList<ScanEvent> ev = parseAll(fixtureLines("ndjson-hostile.ndjson"));
    QCOMPARE(ev.size(), 2);
    QCOMPARE(ev[0].host.hostname, QStringLiteral("<img src=\"http://192.0.2.99/x\">"));
    QCOMPARE(ev[0].host.macVendor, QStringLiteral("<b>vendor</b>"));
    QCOMPARE(ev[0].host.services.value(0).product, QStringLiteral("<script>alert(1)</script>"));
    QCOMPARE(ev[1].logMessage, QStringLiteral("banner &amp;<b> from 192.0.2.66"));
}

namespace {

void compareEvents(const ScanEvent &a, const ScanEvent &b)
{
    QCOMPARE(a.kind, b.kind);
    QCOMPARE(a.seq, b.seq);
    QCOMPARE(a.ts, b.ts);
    QCOMPARE(a.agent, b.agent);
    QCOMPARE(a.done, b.done);
    QCOMPARE(a.total, b.total);
    QCOMPARE(a.host.ip, b.host.ip);
    QCOMPARE(a.host.externalId, b.host.externalId);
    QCOMPARE(a.host.hostname, b.host.hostname);
    QCOMPARE(a.host.mac, b.host.mac);
    QCOMPARE(a.host.macVendor, b.host.macVendor);
    QCOMPARE(a.host.osGuess, b.host.osGuess);
    QCOMPARE(a.host.osGuessConfidence, b.host.osGuessConfidence);
    QCOMPARE(a.host.servicesKnown, b.host.servicesKnown);
    QCOMPARE(a.host.services.size(), b.host.services.size());
    for (qsizetype i = 0; i < a.host.services.size(); ++i) {
        QCOMPARE(a.host.services[i].port, b.host.services[i].port);
        QCOMPARE(a.host.services[i].protocol, b.host.services[i].protocol);
        QCOMPARE(a.host.services[i].serviceName, b.host.services[i].serviceName);
        QCOMPARE(a.host.services[i].product, b.host.services[i].product);
        QCOMPARE(a.host.services[i].version, b.host.services[i].version);
    }
    QCOMPARE(a.logLevel, b.logLevel);
    QCOMPARE(a.logMessage, b.logMessage);
    QCOMPARE(a.endStatus, b.endStatus);
    QCOMPARE(a.endError, b.endError);
    QCOMPARE(a.endAssets, b.endAssets);
    QCOMPARE(a.scope, b.scope);
    QCOMPARE(a.stages, b.stages);
    QCOMPARE(a.hasCapabilities, b.hasCapabilities);
    QCOMPARE(a.capUnprivilegedIcmp, b.capUnprivilegedIcmp);
    QCOMPARE(a.capSystemPing, b.capSystemPing);
    QCOMPARE(a.capArpCache, b.capArpCache);
}

} // namespace

void TstNdjsonParser::parseObjectMatchesParseLine_data()
{
    QTest::addColumn<QByteArray>("line");
    const char *fixtures[] = {"ndjson-detailed.ndjson", "ndjson-hostile.ndjson",
                              "ndjson-junk.ndjson"};
    for (const char *name : fixtures) {
        const QList<QByteArray> lines = fixtureLines(name);
        for (qsizetype i = 0; i < lines.size(); ++i) {
            const QJsonDocument doc = QJsonDocument::fromJson(lines[i]);
            if (!doc.isObject())
                continue;
            QTest::addRow("%s:%lld", name, static_cast<long long>(i)) << lines[i];
        }
    }
}

void TstNdjsonParser::parseObjectMatchesParseLine()
{
    QFETCH(QByteArray, line);
    const auto fromLine = NdjsonParser::parseLine(line);
    const auto fromObject = NdjsonParser::parseObject(QJsonDocument::fromJson(line).object());
    QVERIFY(fromLine.has_value());
    QVERIFY(fromObject.has_value());
    compareEvents(*fromObject, *fromLine);
}

// QTEST_MAIN (QGuiApplication) because ctest passes -platform offscreen.
QTEST_MAIN(TstNdjsonParser)
#include "tst_ndjsonparser.moc"
