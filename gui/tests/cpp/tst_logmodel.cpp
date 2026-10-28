// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// LogModel: 5000-line cap with oldest dropped (T-13-35), cumulative
// warning/error counters that survive the drop, level normalisation and
// control-character stripping.

#include "logmodel.h"

#include <QSignalSpy>
#include <QtTest>

class TestLogModel : public QObject
{
    Q_OBJECT

private slots:
    void appendAndCounters();
    void roles();
    void capDropsOldestKeepsCounters();
    void infoAndUnknownLevels();
    void clearResetsEverything();
    void stripsControlCharacters();
};

void TestLogModel::appendAndCounters()
{
    LogModel m;
    QSignalSpy warnSpy(&m, &LogModel::warningCountChanged);
    QSignalSpy errSpy(&m, &LogModel::errorCountChanged);
    QSignalSpy countSpy(&m, &LogModel::countChanged);
    m.append(QStringLiteral("warn"), QStringLiteral("a"));
    m.append(QStringLiteral("error"), QStringLiteral("b"));
    QCOMPARE(m.count(), 2);
    QCOMPARE(m.rowCount(), 2);
    QCOMPARE(m.warningCount(), 1);
    QCOMPARE(m.errorCount(), 1);
    QCOMPARE(warnSpy.count(), 1);
    QCOMPARE(errSpy.count(), 1);
    QCOMPARE(countSpy.count(), 2);
}

void TestLogModel::roles()
{
    LogModel m;
    const QDateTime when = QDateTime::fromSecsSinceEpoch(1'800'000'000);
    m.append(QStringLiteral("warn"), QStringLiteral("hello"), when);
    const QModelIndex i = m.index(0, 0);
    QCOMPARE(i.data(LogModel::TimeRole).toDateTime(), when);
    QCOMPARE(i.data(LogModel::LevelRole).toString(), QStringLiteral("warn"));
    QCOMPARE(i.data(LogModel::TextRole).toString(), QStringLiteral("hello"));
    QVERIFY(!m.index(1, 0).data(LogModel::TextRole).isValid());

    const QList<QByteArray> names = m.roleNames().values();
    QVERIFY(names.contains(QByteArrayLiteral("time")));
    QVERIFY(names.contains(QByteArrayLiteral("level")));
    QVERIFY(names.contains(QByteArrayLiteral("text")));
}

void TestLogModel::capDropsOldestKeepsCounters()
{
    LogModel m;
    for (int i = 0; i < 5003; ++i)
        m.append(QStringLiteral("warn"), QString::number(i));
    QCOMPARE(m.count(), LogModel::kCap);
    QCOMPARE(m.count(), 5000);
    QCOMPARE(m.index(0, 0).data(LogModel::TextRole).toString(), QStringLiteral("3"));
    QCOMPARE(m.index(4999, 0).data(LogModel::TextRole).toString(), QStringLiteral("5002"));
    QCOMPARE(m.warningCount(), 5003);

    QSignalSpy removed(&m, &QAbstractItemModel::rowsRemoved);
    QSignalSpy inserted(&m, &QAbstractItemModel::rowsInserted);
    m.append(QStringLiteral("info"), QStringLiteral("x"));
    QCOMPARE(removed.count(), 1);
    QCOMPARE(inserted.count(), 1);
    QCOMPARE(m.count(), 5000);
}

void TestLogModel::infoAndUnknownLevels()
{
    LogModel m;
    m.append(QStringLiteral("info"), QStringLiteral("i"));
    m.append(QStringLiteral("bogus"), QStringLiteral("u"));
    m.append(QStringLiteral("WARNING"), QStringLiteral("w"));
    m.append(QStringLiteral("Error"), QStringLiteral("e"));
    QCOMPARE(m.index(0, 0).data(LogModel::LevelRole).toString(), QStringLiteral("info"));
    QCOMPARE(m.index(1, 0).data(LogModel::LevelRole).toString(), QStringLiteral("info"));
    QCOMPARE(m.index(2, 0).data(LogModel::LevelRole).toString(), QStringLiteral("warn"));
    QCOMPARE(m.index(3, 0).data(LogModel::LevelRole).toString(), QStringLiteral("error"));
    QCOMPARE(m.warningCount(), 1);
    QCOMPARE(m.errorCount(), 1);
}

void TestLogModel::clearResetsEverything()
{
    LogModel m;
    m.append(QStringLiteral("warn"), QStringLiteral("a"));
    m.append(QStringLiteral("error"), QStringLiteral("b"));
    QSignalSpy warnSpy(&m, &LogModel::warningCountChanged);
    QSignalSpy errSpy(&m, &LogModel::errorCountChanged);
    QSignalSpy reset(&m, &QAbstractItemModel::modelReset);
    m.clear();
    QCOMPARE(m.count(), 0);
    QCOMPARE(m.warningCount(), 0);
    QCOMPARE(m.errorCount(), 0);
    QCOMPARE(warnSpy.count(), 1);
    QCOMPARE(errSpy.count(), 1);
    QCOMPARE(reset.count(), 1);
}

void TestLogModel::stripsControlCharacters()
{
    LogModel m;
    QString hostile = QStringLiteral("a");
    hostile += QChar(0x1b);
    hostile += QStringLiteral("[31mb");
    hostile += QChar(0x07);
    hostile += QChar(u'\n');
    hostile += QChar(u'\t');
    hostile += QChar(0x7f);
    hostile += QStringLiteral("c");
    m.append(QStringLiteral("info"), hostile);
    QCOMPARE(m.index(0, 0).data(LogModel::TextRole).toString(), QStringLiteral("a[31mb\tc"));

    m.append(QStringLiteral("info"), QStringLiteral("<b>x</b>"));
    QCOMPARE(m.index(1, 0).data(LogModel::TextRole).toString(), QStringLiteral("<b>x</b>"));
}

QTEST_MAIN(TestLogModel)
#include "tst_logmodel.moc"
