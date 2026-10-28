// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "hostmodel.h"
#include "logmodel.h"

#include <QDateTime>
#include <QObject>
#include <QQmlContext>
#include <QQmlEngine>
#include <QVariantList>
#include <QVariantMap>
#include <QtQuickTest>
#include <QtQml/qqmlextensionplugin.h>

Q_IMPORT_QML_PLUGIN(Cysec_Scanner_UiPlugin)

// QML tests need real HostModel / LogModel instances (the filter proxy and
// the table adapter read HostModel role ids), but their mutators are C++
// only. TestData is exposed as the context property "TestData" and builds
// populated models from plain JS objects. Models are parented to TestData
// so the JS garbage collector never frees one a component still uses.
class TestData : public QObject
{
    Q_OBJECT

public:
    using QObject::QObject;

    // hosts: [{ip, hostname, mac, vendor, osGuess, services: [{port, protocol,
    // serviceName, product, version}]}]
    Q_INVOKABLE QObject *hostModel(const QVariantList &hosts)
    {
        auto *model = new HostModel(this);
        for (const QVariant &v : hosts)
            model->upsert(toFact(v.toMap()));
        model->flushNow();
        return model;
    }

    Q_INVOKABLE void upsertHost(QObject *model, const QVariantMap &host)
    {
        if (auto *m = qobject_cast<HostModel *>(model)) {
            m->upsert(toFact(host));
            m->flushNow();
        }
    }

    // lines: [{level, text}] with fixed, increasing timestamps.
    Q_INVOKABLE QObject *logModel(const QVariantList &lines)
    {
        auto *model = new LogModel(this);
        m_logClock = QDateTime();
        for (const QVariant &v : lines)
            appendLog(model, v.toMap().value(QStringLiteral("level")).toString(),
                      v.toMap().value(QStringLiteral("text")).toString());
        return model;
    }

    Q_INVOKABLE void appendLog(QObject *model, const QString &level, const QString &text)
    {
        if (auto *m = qobject_cast<LogModel *>(model)) {
            m_logClock = m_logClock.isValid() ? m_logClock.addSecs(1)
                                              : QDateTime(QDate(2026, 10, 28), QTime(14, 5, 0));
            m->append(level, text, m_logClock);
        }
    }

    Q_INVOKABLE QDateTime logTimeAt(int index) const
    {
        return QDateTime(QDate(2026, 10, 28), QTime(14, 5, 0)).addSecs(index);
    }

private:
    static HostFact toFact(const QVariantMap &m)
    {
        HostFact f;
        f.ip = m.value(QStringLiteral("ip")).toString();
        f.externalId = m.value(QStringLiteral("externalId"), QStringLiteral("ip:") + f.ip).toString();
        f.hostname = m.value(QStringLiteral("hostname")).toString();
        f.mac = m.value(QStringLiteral("mac")).toString();
        f.macVendor = m.value(QStringLiteral("vendor")).toString();
        f.osGuess = m.value(QStringLiteral("osGuess")).toString();
        const QVariantList services = m.value(QStringLiteral("services")).toList();
        f.servicesKnown = m.contains(QStringLiteral("services"));
        for (const QVariant &sv : services) {
            const QVariantMap s = sv.toMap();
            ServiceFact fact;
            fact.port = s.value(QStringLiteral("port")).toInt();
            fact.protocol = s.value(QStringLiteral("protocol"), QStringLiteral("tcp")).toString();
            fact.serviceName = s.value(QStringLiteral("serviceName")).toString();
            fact.product = s.value(QStringLiteral("product")).toString();
            fact.version = s.value(QStringLiteral("version")).toString();
            f.services.append(fact);
        }
        return f;
    }

    QDateTime m_logClock;
};

class Setup : public QObject
{
    Q_OBJECT

public slots:
    void qmlEngineAvailable(QQmlEngine *engine)
    {
        engine->rootContext()->setContextProperty(QStringLiteral("TestData"),
                                                  new TestData(engine));
    }
};

QUICK_TEST_MAIN_WITH_SETUP(ui, Setup)

#include "tst_main.moc"
