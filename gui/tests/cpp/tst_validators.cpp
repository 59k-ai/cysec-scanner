// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Validators: scope entries mirror netutil.parsePrefixOrAddr (Go netip,
// IPv4 only, masked), port specs mirror portscan.ParsePorts (strconv.Atoi
// per token), and the D-11 authorisation containment math (T-13-39, T-13-41).

#include "validators.h"

#include <QtTest>

class TestValidators : public QObject
{
    Q_OBJECT

private slots:
    void scopeEntry_data();
    void scopeEntry();
    void validateTargets_data();
    void validateTargets();
    void portSpec_data();
    void portSpec();
    void validatePorts_data();
    void validatePorts();
    void requiresAuthorisation_data();
    void requiresAuthorisation();
    void containsEdgeCases();
};

void TestValidators::scopeEntry_data()
{
    QTest::addColumn<QString>("input");
    QTest::addColumn<bool>("valid");
    QTest::addColumn<QString>("normalised");

    QTest::newRow("cidr masked") << "192.0.2.5/24" << true << "192.0.2.0/24";
    QTest::newRow("bare is /32") << "192.0.2.7" << true << "192.0.2.7/32";
    QTest::newRow("caller trimmed") << QStringView(u" 198.51.100.0/24 ").trimmed().toString()
                                    << true << "198.51.100.0/24";
    QTest::newRow("slash zero") << "192.0.2.7/0" << true << "0.0.0.0/0";
    QTest::newRow("zero octet ok") << "0.1.2.3" << true << "0.1.2.3/32";
    QTest::newRow("max") << "255.255.255.255/32" << true << "255.255.255.255/32";
    QTest::newRow("/33") << "192.0.2.0/33" << false << "";
    QTest::newRow("octet 256") << "256.1.1.1" << false << "";
    QTest::newRow("ipv6 link-local") << "fe80::1" << false << "";
    QTest::newRow("ipv6 prefix") << "2001:db8::/32" << false << "";
    QTest::newRow("v4-mapped") << "::ffff:1.2.3.4" << false << "";
    QTest::newRow("word") << "abc" << false << "";
    QTest::newRow("three octets") << "192.0.2" << false << "";
    QTest::newRow("five octets") << "1.2.3.4.5" << false << "";
    QTest::newRow("leading zero octet") << "192.0.02.7" << false << "";
    QTest::newRow("leading zero bits") << "192.0.2.7/08" << false << "";
    QTest::newRow("signed bits") << "192.0.2.7/+8" << false << "";
    QTest::newRow("empty bits") << "1.2.3.4/" << false << "";
    QTest::newRow("zone") << "1.2.3.4%eth0" << false << "";
    QTest::newRow("untrimmed") << " 1.2.3.4" << false << "";
    QTest::newRow("empty") << "" << false << "";
    QTest::newRow("empty octet") << "1..3.4" << false << "";
}

void TestValidators::scopeEntry()
{
    QFETCH(QString, input);
    QFETCH(bool, valid);
    QFETCH(QString, normalised);
    const auto p = Validators::parseScopeEntry(input);
    QCOMPARE(p.has_value(), valid);
    if (valid)
        QCOMPARE(p->toString(), normalised);
}

void TestValidators::validateTargets_data()
{
    QTest::addColumn<QString>("input");
    QTest::addColumn<bool>("ok");
    QTest::addColumn<int>("error");
    QTest::addColumn<QStringList>("cidrs");

    QTest::newRow("comma list") << "192.0.2.0/24, 198.51.100.7" << true << int(Validators::Ok)
                                << QStringList{"192.0.2.0/24", "198.51.100.7/32"};
    QTest::newRow("whitespace list") << "192.0.2.5/24\n\t198.51.100.7  " << true
                                     << int(Validators::Ok)
                                     << QStringList{"192.0.2.0/24", "198.51.100.7/32"};
    QTest::newRow("dedup after mask") << "192.0.2.1/24,192.0.2.9/24" << true << int(Validators::Ok)
                                      << QStringList{"192.0.2.0/24"};
    QTest::newRow("empty") << "" << false << int(Validators::Empty) << QStringList{};
    QTest::newRow("separators only") << " , ,\n" << false << int(Validators::Empty)
                                     << QStringList{};
    QTest::newRow("ipv6 mixed in") << "192.0.2.0/24 fe80::/64" << false
                                   << int(Validators::InvalidTarget) << QStringList{};
    QTest::newRow("argv-ish") << "--payload-out=/etc/x" << false << int(Validators::InvalidTarget)
                              << QStringList{};
}

void TestValidators::validateTargets()
{
    QFETCH(QString, input);
    QFETCH(bool, ok);
    QFETCH(int, error);
    QFETCH(QStringList, cidrs);
    Validators v;
    const QVariantMap r = v.validateTargets(input);
    QCOMPARE(r.value("ok").toBool(), ok);
    QCOMPARE(r.value("error").toInt(), error);
    if (ok)
        QCOMPARE(r.value("cidrs").toStringList(), cidrs);
}

void TestValidators::portSpec_data()
{
    QTest::addColumn<QString>("input");
    QTest::addColumn<bool>("valid");
    QTest::addColumn<QList<int>>("ports");

    QTest::newRow("list and range") << "22,80,8000-8002" << true
                                    << QList<int>{22, 80, 8000, 8001, 8002};
    QTest::newRow("trimmed tokens") << " 22 , 80 " << true << QList<int>{22, 80};
    QTest::newRow("trimmed range sides") << "1 - 3" << true << QList<int>{1, 2, 3};
    QTest::newRow("single-port range") << "443-443" << true << QList<int>{443};
    QTest::newRow("dedup sorted") << "80,22,80,21-23" << true << QList<int>{21, 22, 23, 80};
    QTest::newRow("atoi plus sign") << "+22" << true << QList<int>{22};
    QTest::newRow("atoi leading zero") << "022" << true << QList<int>{22};
    QTest::newRow("empty token") << "22,,80" << false << QList<int>{};
    QTest::newRow("trailing comma") << "22," << false << QList<int>{};
    QTest::newRow("zero") << "0" << false << QList<int>{};
    QTest::newRow("65536") << "65536" << false << QList<int>{};
    QTest::newRow("inverted") << "80-22" << false << QList<int>{};
    QTest::newRow("alpha") << "a" << false << QList<int>{};
    QTest::newRow("negative") << "-5" << false << QList<int>{};
    QTest::newRow("double dash") << "1--5" << false << QList<int>{};
    QTest::newRow("hex") << "0x16" << false << QList<int>{};
    QTest::newRow("huge") << "9999999999999999999999" << false << QList<int>{};
    QTest::newRow("empty") << "" << false << QList<int>{};
    QTest::newRow("whitespace only") << "   " << false << QList<int>{};
}

void TestValidators::portSpec()
{
    QFETCH(QString, input);
    QFETCH(bool, valid);
    QFETCH(QList<int>, ports);
    QList<int> out;
    QCOMPARE(Validators::parsePortSpec(input, &out), valid);
    if (valid)
        QCOMPARE(out, ports);
}

void TestValidators::validatePorts_data()
{
    QTest::addColumn<QString>("input");
    QTest::addColumn<bool>("ok");
    QTest::addColumn<int>("error");

    QTest::newRow("empty is default set") << "" << true << int(Validators::Ok);
    QTest::newRow("whitespace is default set") << "  " << true << int(Validators::Ok);
    QTest::newRow("full range") << "1-65535" << true << int(Validators::Ok);
    QTest::newRow("empty token") << "22,,80" << false << int(Validators::InvalidPorts);
    QTest::newRow("argv-ish") << "--timing=x" << false << int(Validators::InvalidPorts);
}

void TestValidators::validatePorts()
{
    QFETCH(QString, input);
    QFETCH(bool, ok);
    QFETCH(int, error);
    Validators v;
    const QVariantMap r = v.validatePorts(input);
    QCOMPARE(r.value("ok").toBool(), ok);
    QCOMPARE(r.value("error").toInt(), error);
    if (ok)
        QCOMPARE(r.value("ports").toString(), input.trimmed());
}

void TestValidators::requiresAuthorisation_data()
{
    QTest::addColumn<QStringList>("cidrs");
    QTest::addColumn<QStringList>("locals");
    QTest::addColumn<bool>("gate");

    QTest::newRow("inside local") << QStringList{"192.0.2.0/25"} << QStringList{"192.0.2.0/24"}
                                  << false;
    QTest::newRow("equal to local") << QStringList{"192.0.2.0/24"} << QStringList{"192.0.2.0/24"}
                                    << false;
    QTest::newRow("wider than local") << QStringList{"192.0.2.0/23"}
                                      << QStringList{"192.0.2.0/24"} << true;
    QTest::newRow("one outside") << QStringList{"192.0.2.7/32", "198.51.100.1/32"}
                                 << QStringList{"192.0.2.0/24"} << true;
    QTest::newRow("no locals known") << QStringList{"192.0.2.7/32"} << QStringList{} << true;
    QTest::newRow("second local covers")
        << QStringList{"192.0.2.7/32", "198.51.100.1/32"}
        << QStringList{"192.0.2.0/24", "198.51.100.0/24"} << false;
    QTest::newRow("adjacent not contained") << QStringList{"192.0.3.0/24"}
                                            << QStringList{"192.0.2.0/24"} << true;
    QTest::newRow("unparsable target gates") << QStringList{"fe80::/64"}
                                             << QStringList{"192.0.2.0/24"} << true;
}

void TestValidators::requiresAuthorisation()
{
    QFETCH(QStringList, cidrs);
    QFETCH(QStringList, locals);
    QFETCH(bool, gate);
    Validators v;
    QCOMPARE(v.requiresAuthorisation(cidrs, locals), gate);
}

void TestValidators::containsEdgeCases()
{
    const auto all = *Validators::parseScopeEntry(u"0.0.0.0/0");
    const auto host = *Validators::parseScopeEntry(u"203.0.113.9");
    const auto net = *Validators::parseScopeEntry(u"203.0.113.0/24");
    // mask(0) == 0: everything is inside /0.
    QVERIFY(Validators::contains(all, host));
    QVERIFY(Validators::contains(all, all));
    QVERIFY(Validators::contains(net, host));
    QVERIFY(!Validators::contains(host, net));
    QVERIFY(!Validators::contains(host, all));
}

QTEST_MAIN(TestValidators)
#include "tst_validators.moc"
