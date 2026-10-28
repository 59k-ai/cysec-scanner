// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Formatter: counts, percentages and log times follow the default QLocale
// (LanguageController sets it on a language switch); elapsed time is ASCII
// mm:ss / h:mm:ss in every language; the revision argument never changes the
// output.

#include "formatter.h"

#include <QDateTime>
#include <QLocale>
#include <QtTest>

class TestFormatter : public QObject
{
    Q_OBJECT

private slots:
    void init();
    void cleanup();

    void countIsLocaleGrouped_data();
    void countIsLocaleGrouped();
    void percentFollowsLocale_data();
    void percentFollowsLocale();
    void percentClamps();
    void elapsedIsAscii_data();
    void elapsedIsAscii();
    void elapsedNegativeIsZero();
    void logTimeIsLocaleShortTime_data();
    void logTimeIsLocaleShortTime();
    void logTimeInvalidIsEmpty();
    void revisionDoesNotChangeOutput();

private:
    QLocale m_saved;
    Formatter m_fmt;
};

void TestFormatter::init()
{
    m_saved = QLocale();
}

void TestFormatter::cleanup()
{
    QLocale::setDefault(m_saved);
}

void TestFormatter::countIsLocaleGrouped_data()
{
    QTest::addColumn<QString>("locale");
    QTest::addColumn<QString>("expected");
    QTest::newRow("en") << QStringLiteral("en") << QStringLiteral("12,345");
    QTest::newRow("de") << QStringLiteral("de") << QStringLiteral("12.345");
}

void TestFormatter::countIsLocaleGrouped()
{
    QFETCH(QString, locale);
    QFETCH(QString, expected);
    QLocale::setDefault(QLocale(locale));
    QCOMPARE(m_fmt.count(12345, 0), expected);
    QCOMPARE(m_fmt.count(0, 0), QStringLiteral("0"));
}

void TestFormatter::percentFollowsLocale_data()
{
    QTest::addColumn<QString>("locale");
    QTest::addColumn<bool>("spaced");
    QTest::newRow("en") << QStringLiteral("en") << false;
    QTest::newRow("de") << QStringLiteral("de") << true;
}

void TestFormatter::percentFollowsLocale()
{
    QFETCH(QString, locale);
    QFETCH(bool, spaced);
    QLocale::setDefault(QLocale(locale));
    const QLocale loc;
    const QString number = loc.toString(qRound(0.127 * 100));
    // German (DIN 5008) separates the sign with a no-break space; English
    // does not. The digits and the sign itself come from QLocale.
    const QString expected = number + (spaced ? QString(QChar(0x00A0)) : QString()) + loc.percent();
    QCOMPARE(m_fmt.percent(0.127, 0), expected);
    QVERIFY(m_fmt.percent(0.127, 0).startsWith(QStringLiteral("13")));
}

void TestFormatter::percentClamps()
{
    QLocale::setDefault(QLocale(QStringLiteral("en")));
    QCOMPARE(m_fmt.percent(-0.5, 0), QStringLiteral("0%"));
    QCOMPARE(m_fmt.percent(1.7, 0), QStringLiteral("100%"));
    QCOMPARE(m_fmt.percent(1.0, 0), QStringLiteral("100%"));
    QCOMPARE(m_fmt.percent(qQNaN(), 0), QStringLiteral("0%"));
}

void TestFormatter::elapsedIsAscii_data()
{
    QTest::addColumn<QString>("locale");
    QTest::addColumn<int>("seconds");
    QTest::addColumn<QString>("expected");
    for (const char *loc : {"en", "de", "ar"}) {
        const QString l = QLatin1StringView(loc);
        QTest::addRow("%s-0", loc) << l << 0 << QStringLiteral("00:00");
        QTest::addRow("%s-75", loc) << l << 75 << QStringLiteral("01:15");
        QTest::addRow("%s-3599", loc) << l << 3599 << QStringLiteral("59:59");
        QTest::addRow("%s-3600", loc) << l << 3600 << QStringLiteral("1:00:00");
        QTest::addRow("%s-3725", loc) << l << 3725 << QStringLiteral("1:02:05");
        QTest::addRow("%s-36000", loc) << l << 36000 << QStringLiteral("10:00:00");
    }
}

void TestFormatter::elapsedIsAscii()
{
    QFETCH(QString, locale);
    QFETCH(int, seconds);
    QFETCH(QString, expected);
    QLocale::setDefault(QLocale(locale));
    QCOMPARE(m_fmt.elapsed(seconds), expected);
}

void TestFormatter::elapsedNegativeIsZero()
{
    QCOMPARE(m_fmt.elapsed(-1), QStringLiteral("00:00"));
    QCOMPARE(m_fmt.elapsed(-3725), QStringLiteral("00:00"));
}

void TestFormatter::logTimeIsLocaleShortTime_data()
{
    QTest::addColumn<QString>("locale");
    QTest::newRow("en") << QStringLiteral("en");
    QTest::newRow("de") << QStringLiteral("de");
}

void TestFormatter::logTimeIsLocaleShortTime()
{
    QFETCH(QString, locale);
    QLocale::setDefault(QLocale(locale));
    const QDateTime t(QDate(2026, 10, 28), QTime(14, 5, 9));
    const QString expected = QLocale().toString(t.time(), QLocale::ShortFormat);
    QVERIFY(!expected.isEmpty());
    QCOMPARE(m_fmt.logTime(t, 0), expected);
}

void TestFormatter::logTimeInvalidIsEmpty()
{
    QCOMPARE(m_fmt.logTime(QDateTime(), 0), QString());
}

void TestFormatter::revisionDoesNotChangeOutput()
{
    QLocale::setDefault(QLocale(QStringLiteral("de")));
    const QDateTime t(QDate(2026, 10, 28), QTime(9, 30));
    for (int rev : {1, 7, 42}) {
        QCOMPARE(m_fmt.count(12345, rev), m_fmt.count(12345, 0));
        QCOMPARE(m_fmt.percent(0.5, rev), m_fmt.percent(0.5, 0));
        QCOMPARE(m_fmt.logTime(t, rev), m_fmt.logTime(t, 0));
    }
}

QTEST_MAIN(TestFormatter)
#include "tst_formatter.moc"
