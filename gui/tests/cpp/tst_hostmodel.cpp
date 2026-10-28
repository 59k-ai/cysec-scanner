// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// HostModel, HostFilterProxy and HostTableAdapter: IP-keyed upserts that
// survive the ip: -> mac: re-key, the merge rule, 100 ms coalescing, payload
// reconciliation (D-02), numeric IP sort, text filter, configurable columns.

#include "hostfilterproxy.h"
#include "hostmodel.h"
#include "hosttableadapter.h"

#include <QFile>
#include <QSignalSpy>
#include <QtTest>

namespace {

HostFact fact(const QString &ip, const QString &externalId = QString(),
              const QString &hostname = QString())
{
    HostFact f;
    f.ip = ip;
    f.externalId = externalId.isEmpty() ? QStringLiteral("ip:") + ip : externalId;
    f.hostname = hostname;
    return f;
}

ServiceFact svc(int port, const QString &name = QString())
{
    ServiceFact s;
    s.port = port;
    s.protocol = QStringLiteral("tcp");
    s.serviceName = name;
    return s;
}

QByteArray readFixture(const char *name)
{
    QFile f(QStringLiteral(CYSEC_GUI_FIXTURES_DIR "/") + QLatin1StringView(name));
    if (!f.open(QIODevice::ReadOnly))
        return {};
    return f.readAll();
}

int rowOfIp(const QAbstractItemModel &m, const QString &ip)
{
    for (int r = 0; r < m.rowCount(); ++r) {
        if (m.index(r, 0).data(HostModel::IpRole).toString() == ip)
            return r;
    }
    return -1;
}

} // namespace

class TestHostModel : public QObject
{
    Q_OBJECT

private slots:
    void rekeyUpdatesSameRow();
    void laterEventNeverBlanksField();
    void servicesReplaceOnlyWhenKnown();
    void burstIsBatched();
    void timerFlushesWithoutFlushNow();
    void portsRoles();
    void roleNamesExposed();
    void reconcileAddsUpdatesRemoves();
    void reconcileKeepsAssetWithoutIp();
    void reconcileRejectsGarbage();
    void clearResets();
    void hostAtMap();
    void proxySortsIpNumerically();
    void proxyFilters();
    void proxyHostAt();
    void adapterColumns();
    void adapterFollowsSource();
};

void TestHostModel::rekeyUpdatesSameRow()
{
    HostModel m;
    m.upsert(fact(QStringLiteral("192.0.2.10")));
    m.flushNow();
    QCOMPARE(m.count(), 1);
    m.upsert(fact(QStringLiteral("192.0.2.10"), QStringLiteral("mac:aa:bb:cc:dd:ee:ff"),
                  QStringLiteral("nas")));
    m.flushNow();
    QCOMPARE(m.count(), 1);
    const QModelIndex i = m.index(0, 0);
    QCOMPARE(i.data(HostModel::ExternalIdRole).toString(), QStringLiteral("mac:aa:bb:cc:dd:ee:ff"));
    QCOMPARE(i.data(HostModel::HostnameRole).toString(), QStringLiteral("nas"));
}

void TestHostModel::laterEventNeverBlanksField()
{
    HostModel m;
    HostFact full = fact(QStringLiteral("192.0.2.10"), QString(), QStringLiteral("nas"));
    full.mac = QStringLiteral("aa:bb:cc:dd:ee:ff");
    full.macVendor = QStringLiteral("Vendor");
    m.upsert(full);
    m.flushNow();

    HostFact sweep;
    sweep.ip = QStringLiteral("192.0.2.10");
    m.upsert(sweep);
    m.flushNow();
    QCOMPARE(m.count(), 1);
    const QModelIndex i = m.index(0, 0);
    QCOMPARE(i.data(HostModel::HostnameRole).toString(), QStringLiteral("nas"));
    QCOMPARE(i.data(HostModel::MacRole).toString(), QStringLiteral("aa:bb:cc:dd:ee:ff"));
    QCOMPARE(i.data(HostModel::VendorRole).toString(), QStringLiteral("Vendor"));
    QCOMPARE(i.data(HostModel::ExternalIdRole).toString(), QStringLiteral("ip:192.0.2.10"));

    // Pending merge (no flush in between) follows the same rule.
    HostFact a = fact(QStringLiteral("192.0.2.11"), QString(), QStringLiteral("box"));
    HostFact b;
    b.ip = QStringLiteral("192.0.2.11");
    b.osGuess = QStringLiteral("Linux");
    m.upsert(a);
    m.upsert(b);
    m.flushNow();
    const int r = rowOfIp(m, QStringLiteral("192.0.2.11"));
    QVERIFY(r >= 0);
    QCOMPARE(m.index(r, 0).data(HostModel::HostnameRole).toString(), QStringLiteral("box"));
    QCOMPARE(m.index(r, 0).data(HostModel::OsGuessRole).toString(), QStringLiteral("Linux"));
}

void TestHostModel::servicesReplaceOnlyWhenKnown()
{
    HostModel m;
    HostFact f = fact(QStringLiteral("192.0.2.10"));
    f.services = {svc(22, QStringLiteral("ssh"))};
    f.servicesKnown = true;
    m.upsert(f);
    m.flushNow();

    HostFact unknown = fact(QStringLiteral("192.0.2.10"));
    m.upsert(unknown);
    m.flushNow();
    QCOMPARE(m.index(0, 0).data(HostModel::PortsListRole).toString(), QStringLiteral("22/tcp"));

    HostFact known = fact(QStringLiteral("192.0.2.10"));
    known.services = {svc(80), svc(443)};
    known.servicesKnown = true;
    m.upsert(known);
    m.flushNow();
    QCOMPARE(m.index(0, 0).data(HostModel::PortsListRole).toString(),
             QStringLiteral("80/tcp 443/tcp"));
}

void TestHostModel::burstIsBatched()
{
    HostModel m;
    QSignalSpy inserted(&m, &QAbstractItemModel::rowsInserted);
    QSignalSpy countSpy(&m, &HostModel::countChanged);
    for (int i = 0; i < 1000; ++i)
        m.upsert(fact(QStringLiteral("10.0.%1.%2").arg(i / 250).arg(i % 250 + 1)));
    QCOMPARE(m.count(), 0); // nothing visible before a flush
    m.flushNow();
    QCOMPARE(m.count(), 1000);
    QVERIFY2(inserted.count() >= 1 && inserted.count() <= 10,
             qPrintable(QStringLiteral("rowsInserted fired %1 times").arg(inserted.count())));
    QVERIFY(countSpy.count() >= 1 && countSpy.count() <= 10);

    // Updates to existing rows are a dataChanged, not inserts.
    QSignalSpy changed(&m, &QAbstractItemModel::dataChanged);
    for (int i = 0; i < 100; ++i) {
        HostFact f = fact(QStringLiteral("10.0.0.%1").arg(i + 1), QString(), QStringLiteral("h"));
        m.upsert(f);
    }
    inserted.clear();
    m.flushNow();
    QCOMPARE(inserted.count(), 0);
    QVERIFY(changed.count() >= 1 && changed.count() <= 10);
    QCOMPARE(m.count(), 1000);
}

void TestHostModel::timerFlushesWithoutFlushNow()
{
    HostModel m;
    for (int i = 0; i < 50; ++i)
        m.upsert(fact(QStringLiteral("192.0.2.%1").arg(i + 1)));
    QTRY_COMPARE_WITH_TIMEOUT(m.count(), 50, 150);
}

void TestHostModel::portsRoles()
{
    HostModel m;
    HostFact f = fact(QStringLiteral("192.0.2.10"));
    // Deliberately unsorted input.
    f.services = {svc(8443), svc(80), svc(22), svc(8080), svc(443)};
    f.servicesKnown = true;
    m.upsert(f);
    m.flushNow();
    const QModelIndex i = m.index(0, 0);
    QCOMPARE(i.data(HostModel::PortsRole).toString(), QStringLiteral("22, 80, 443 +2"));
    QCOMPARE(i.data(HostModel::PortsListRole).toString(),
             QStringLiteral("22/tcp 80/tcp 443/tcp 8080/tcp 8443/tcp"));

    HostFact few = fact(QStringLiteral("192.0.2.11"));
    few.services = {svc(443), svc(22)};
    few.servicesKnown = true;
    m.upsert(few);
    m.flushNow();
    QCOMPARE(m.index(rowOfIp(m, QStringLiteral("192.0.2.11")), 0).data(HostModel::PortsRole).toString(),
             QStringLiteral("22, 443"));
    QCOMPARE(i.data(HostModel::SortKeyRole).toUInt(), (192u << 24) | (2u << 8) | 10u);
}

void TestHostModel::roleNamesExposed()
{
    HostModel m;
    const QList<QByteArray> names = m.roleNames().values();
    for (const char *n : {"ip", "hostname", "vendor", "mac", "ports", "portsList", "osGuess",
                          "externalId", "services", "sortKey", "host"}) {
        QVERIFY2(names.contains(QByteArray(n)), n);
    }
}

void TestHostModel::reconcileAddsUpdatesRemoves()
{
    HostModel m;
    HostFact a = fact(QStringLiteral("192.0.2.10"));
    a.osGuess = QStringLiteral("old guess");
    m.upsert(a);
    m.upsert(fact(QStringLiteral("192.0.2.20"))); // absent from the payload
    m.flushNow();
    QCOMPARE(m.count(), 2);

    const QByteArray payload = readFixture("payload-reconcile.json");
    QVERIFY(!payload.isEmpty());
    QSignalSpy countSpy(&m, &HostModel::countChanged);
    QVERIFY(m.reconcileFromPayload(payload));
    QVERIFY(countSpy.count() >= 1);

    QCOMPARE(m.count(), 3);
    QCOMPARE(rowOfIp(m, QStringLiteral("192.0.2.20")), -1);
    const int r10 = rowOfIp(m, QStringLiteral("192.0.2.10"));
    const int r30 = rowOfIp(m, QStringLiteral("192.0.2.30"));
    QVERIFY(r10 >= 0);
    QVERIFY(r30 >= 0);
    const QModelIndex i10 = m.index(r10, 0);
    QCOMPARE(i10.data(HostModel::OsGuessRole).toString(), QStringLiteral("Linux 6.x"));
    QCOMPARE(i10.data(HostModel::HostnameRole).toString(), QStringLiteral("nas"));
    QCOMPARE(i10.data(HostModel::VendorRole).toString(), QStringLiteral("Example Storage Inc."));
    QCOMPARE(i10.data(HostModel::ExternalIdRole).toString(), QStringLiteral("mac:02:00:5e:10:00:10"));
    QCOMPARE(i10.data(HostModel::PortsListRole).toString(), QStringLiteral("22/tcp 445/tcp"));
    QCOMPARE(m.index(r30, 0).data(HostModel::OsGuessRole).toString(), QString());

    // Same payload again: nothing changes.
    QVERIFY(!m.reconcileFromPayload(payload));
    QCOMPARE(m.count(), 3);
}

void TestHostModel::reconcileKeepsAssetWithoutIp()
{
    HostModel m;
    QVERIFY(m.reconcileFromPayload(readFixture("payload-reconcile.json")));
    bool found = false;
    for (int r = 0; r < m.rowCount(); ++r) {
        const QModelIndex i = m.index(r, 0);
        if (i.data(HostModel::ExternalIdRole).toString() == QStringLiteral("mac:02:00:5e:10:00:99")) {
            found = true;
            QCOMPARE(i.data(HostModel::IpRole).toString(), QString());
            QCOMPARE(i.data(HostModel::SortKeyRole).toUInt(), 0u);
            QCOMPARE(i.data(HostModel::MacRole).toString(), QStringLiteral("02:00:5e:10:00:99"));
        }
    }
    QVERIFY(found);
}

void TestHostModel::reconcileRejectsGarbage()
{
    HostModel m;
    m.upsert(fact(QStringLiteral("192.0.2.10")));
    m.flushNow();
    QVERIFY(!m.reconcileFromPayload(QByteArrayLiteral("not json")));
    QVERIFY(!m.reconcileFromPayload(QByteArrayLiteral("[1,2]")));
    QCOMPARE(m.count(), 1); // a broken payload never wipes the live table
}

void TestHostModel::clearResets()
{
    HostModel m;
    m.upsert(fact(QStringLiteral("192.0.2.10")));
    m.flushNow();
    m.upsert(fact(QStringLiteral("192.0.2.11"))); // pending, not yet flushed
    QSignalSpy reset(&m, &QAbstractItemModel::modelReset);
    m.clear();
    QCOMPARE(reset.count(), 1);
    QCOMPARE(m.count(), 0);
    m.flushNow();
    QCOMPARE(m.count(), 0); // pending work was discarded too
}

void TestHostModel::hostAtMap()
{
    HostModel m;
    HostFact f = fact(QStringLiteral("192.0.2.10"), QString(), QStringLiteral("nas"));
    f.mac = QStringLiteral("aa:bb:cc:dd:ee:ff");
    f.macVendor = QStringLiteral("Vendor");
    f.osGuess = QStringLiteral("Linux");
    ServiceFact s = svc(22, QStringLiteral("ssh"));
    s.product = QStringLiteral("OpenSSH");
    s.version = QStringLiteral("9.6");
    f.services = {s};
    f.servicesKnown = true;
    m.upsert(f);
    m.flushNow();

    const QVariantMap h = m.hostAt(0);
    for (const char *k : {"ip", "hostname", "mac", "vendor", "osGuess", "services"})
        QVERIFY2(h.contains(QLatin1StringView(k)), k);
    QCOMPARE(h.value(QStringLiteral("ip")).toString(), QStringLiteral("192.0.2.10"));
    const QVariantList services = h.value(QStringLiteral("services")).toList();
    QCOMPARE(services.size(), 1);
    const QVariantMap s0 = services.first().toMap();
    QCOMPARE(s0.value(QStringLiteral("port")).toInt(), 22);
    QCOMPARE(s0.value(QStringLiteral("serviceName")).toString(), QStringLiteral("ssh"));
    QCOMPARE(s0.value(QStringLiteral("product")).toString(), QStringLiteral("OpenSSH"));
    QCOMPARE(s0.value(QStringLiteral("version")).toString(), QStringLiteral("9.6"));
    QVERIFY(m.hostAt(5).isEmpty());
    QVERIFY(m.hostAt(-1).isEmpty());
    QCOMPARE(m.hosts().size(), 1);
}

void TestHostModel::proxySortsIpNumerically()
{
    HostModel m;
    m.upsert(fact(QStringLiteral("192.0.2.10")));
    m.upsert(fact(QStringLiteral("192.0.2.9")));
    m.upsert(fact(QStringLiteral("192.0.2.100")));
    m.flushNow();
    HostFilterProxy p;
    p.setSourceModel(&m);
    p.sortByRole(QStringLiteral("ip"), Qt::AscendingOrder);
    QCOMPARE(p.index(0, 0).data(HostModel::IpRole).toString(), QStringLiteral("192.0.2.9"));
    QCOMPARE(p.index(1, 0).data(HostModel::IpRole).toString(), QStringLiteral("192.0.2.10"));
    QCOMPARE(p.index(2, 0).data(HostModel::IpRole).toString(), QStringLiteral("192.0.2.100"));
    p.sortByRole(QStringLiteral("ip"), Qt::DescendingOrder);
    QCOMPARE(p.index(0, 0).data(HostModel::IpRole).toString(), QStringLiteral("192.0.2.100"));

    // Live inserts stay sorted.
    m.upsert(fact(QStringLiteral("192.0.2.200")));
    m.flushNow();
    QCOMPARE(p.index(0, 0).data(HostModel::IpRole).toString(), QStringLiteral("192.0.2.200"));
}

void TestHostModel::proxyFilters()
{
    HostModel m;
    HostFact nas = fact(QStringLiteral("192.0.2.10"), QString(), QStringLiteral("NAS"));
    nas.services = {svc(22, QStringLiteral("ssh"))};
    nas.servicesKnown = true;
    HostFact web = fact(QStringLiteral("192.0.2.20"), QString(), QStringLiteral("web"));
    web.services = {svc(8080, QStringLiteral("http-proxy"))};
    web.servicesKnown = true;
    web.macVendor = QStringLiteral("Acme Corp");
    m.upsert(nas);
    m.upsert(web);
    m.upsert(fact(QStringLiteral("192.0.2.30")));
    m.flushNow();

    HostFilterProxy p;
    p.setSourceModel(&m);
    QSignalSpy textSpy(&p, &HostFilterProxy::filterTextChanged);
    QCOMPARE(p.rowCount(), 3);

    p.setFilterText(QStringLiteral("ssh"));
    QCOMPARE(textSpy.count(), 1);
    QCOMPARE(p.rowCount(), 1);
    QCOMPARE(p.index(0, 0).data(HostModel::IpRole).toString(), QStringLiteral("192.0.2.10"));

    p.setFilterText(QStringLiteral("nas"));
    QCOMPARE(p.rowCount(), 1);
    QCOMPARE(p.index(0, 0).data(HostModel::IpRole).toString(), QStringLiteral("192.0.2.10"));

    p.setFilterText(QStringLiteral("8080"));
    QCOMPARE(p.rowCount(), 1);
    QCOMPARE(p.index(0, 0).data(HostModel::IpRole).toString(), QStringLiteral("192.0.2.20"));

    p.setFilterText(QStringLiteral("acme"));
    QCOMPARE(p.rowCount(), 1);

    p.setFilterText(QStringLiteral("192.0.2.3"));
    QCOMPARE(p.rowCount(), 1);

    p.setFilterText(QStringLiteral("  "));
    QCOMPARE(p.rowCount(), 3);
    p.setFilterText(QString());
    QCOMPARE(p.rowCount(), 3);
}

void TestHostModel::proxyHostAt()
{
    HostModel m;
    m.upsert(fact(QStringLiteral("192.0.2.10"), QString(), QStringLiteral("b")));
    m.upsert(fact(QStringLiteral("192.0.2.9"), QString(), QStringLiteral("a")));
    m.flushNow();
    HostFilterProxy p;
    p.setSourceModel(&m);
    p.sortByRole(QStringLiteral("ip"), Qt::AscendingOrder);
    QCOMPARE(p.hostAt(0).value(QStringLiteral("hostname")).toString(), QStringLiteral("a"));
    QVERIFY(p.hostAt(9).isEmpty());
    p.sortByRole(QStringLiteral("hostname"), Qt::DescendingOrder);
    QCOMPARE(p.hostAt(0).value(QStringLiteral("hostname")).toString(), QStringLiteral("b"));
}

void TestHostModel::adapterColumns()
{
    HostModel m;
    m.upsert(fact(QStringLiteral("192.0.2.10"), QString(), QStringLiteral("nas")));
    m.flushNow();
    HostFilterProxy p;
    p.setSourceModel(&m);
    HostTableAdapter t;
    QSignalSpy sourceSpy(&t, &HostTableAdapter::sourceModelChanged);
    t.setSourceModel(&p);
    QCOMPARE(sourceSpy.count(), 1);
    t.setColumnRoles({QStringLiteral("ip"), QStringLiteral("hostname"), QStringLiteral("vendor"),
                      QStringLiteral("ports"), QStringLiteral("osGuess")});
    QCOMPARE(t.columnCount(), 5);
    QCOMPARE(t.rowCount(), 1);
    QCOMPARE(t.data(t.index(0, 1)).toString(), QStringLiteral("nas"));
    QCOMPARE(t.data(t.index(0, 0)).toString(), QStringLiteral("192.0.2.10"));
    QVERIFY(!t.data(t.index(0, 7)).isValid());

    QSignalSpy reset(&t, &QAbstractItemModel::modelReset);
    QSignalSpy rolesSpy(&t, &HostTableAdapter::columnRolesChanged);
    t.setColumnRoles({QStringLiteral("ip"), QStringLiteral("hostname"), QStringLiteral("ports")});
    QCOMPARE(reset.count(), 1);
    QCOMPARE(rolesSpy.count(), 1);
    QCOMPARE(t.columnCount(), 3);
    QCOMPARE(t.rowData(0).value(QStringLiteral("hostname")).toString(), QStringLiteral("nas"));
    QVERIFY(t.rowData(4).isEmpty());

    // An unknown role name yields an empty cell rather than a crash.
    t.setColumnRoles({QStringLiteral("nope")});
    QVERIFY(!t.data(t.index(0, 0)).isValid());
}

void TestHostModel::adapterFollowsSource()
{
    HostModel m;
    HostFilterProxy p;
    p.setSourceModel(&m);
    HostTableAdapter t;
    t.setColumnRoles({QStringLiteral("ip"), QStringLiteral("hostname")});
    t.setSourceModel(&p);
    QCOMPARE(t.rowCount(), 0);

    m.upsert(fact(QStringLiteral("192.0.2.10")));
    m.upsert(fact(QStringLiteral("192.0.2.11")));
    m.flushNow();
    QCOMPARE(t.rowCount(), 2);

    QSignalSpy changed(&t, &QAbstractItemModel::dataChanged);
    m.upsert(fact(QStringLiteral("192.0.2.10"), QString(), QStringLiteral("renamed")));
    m.flushNow();
    QVERIFY(changed.count() >= 1);

    p.setFilterText(QStringLiteral("renamed"));
    QCOMPARE(t.rowCount(), 1);
    QCOMPARE(t.data(t.index(0, 1)).toString(), QStringLiteral("renamed"));
    p.setFilterText(QString());
    QCOMPARE(t.rowCount(), 2);

    m.clear();
    QCOMPARE(t.rowCount(), 0);

    t.setSourceModel(nullptr);
    QCOMPARE(t.rowCount(), 0);
    QVERIFY(t.rowData(0).isEmpty());
}

QTEST_MAIN(TestHostModel)
#include "tst_hostmodel.moc"
