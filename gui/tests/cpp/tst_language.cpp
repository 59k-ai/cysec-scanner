// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "formatter.h"
#include "languagecontroller.h"

#include <QCoreApplication>
#include <QFile>
#include <QLocale>
#include <QProcess>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QSettings>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QVariantMap>

#include <memory>

// Covers the runtime language switch (I18N-01, D-28): the system-locale
// default, QSettings persistence, the translator swap with
// QQmlEngine::retranslate, and the default QLocale that Formatter reads.
// The shipped catalogues are still empty (13-17 fills them), so the
// translator case builds its own one-string catalogue with lrelease.
class TestLanguage : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_settingsDir;

    static std::unique_ptr<LanguageController> make(QQmlEngine *engine)
    {
        return std::unique_ptr<LanguageController>(LanguageController::create(engine, engine));
    }

    // Writes cysec_scanner_ui_de.qm ("Hello" -> "Hallo" in context "Test")
    // into dir. Returns false when lrelease is unavailable.
    static bool buildTestCatalogue(const QString &dir)
    {
#ifdef CYSEC_LRELEASE_PATH
        const QString ts = dir + QStringLiteral("/cysec_scanner_ui_de.ts");
        QFile f(ts);
        if (!f.open(QIODevice::WriteOnly))
            return false;
        f.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                "<!DOCTYPE TS>\n"
                "<TS version=\"2.1\" language=\"de_DE\" sourcelanguage=\"en\">\n"
                "<context><name>Test</name>\n"
                "<message><source>Hello</source><translation>Hallo</translation></message>\n"
                "</context>\n"
                "</TS>\n");
        f.close();
        const int rc = QProcess::execute(QStringLiteral(CYSEC_LRELEASE_PATH),
                                         {QStringLiteral("-silent"), ts, QStringLiteral("-qm"),
                                          dir + QStringLiteral("/cysec_scanner_ui_de.qm")});
        return rc == 0 && QFile::exists(dir + QStringLiteral("/cysec_scanner_ui_de.qm"));
#else
        Q_UNUSED(dir);
        return false;
#endif
    }

private slots:
    void initTestCase()
    {
        QVERIFY(m_settingsDir.isValid());
        // Keep the user's real preferences untouched.
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_settingsDir.path());
        QCoreApplication::setOrganizationName(QStringLiteral("cysec-test"));
        QCoreApplication::setApplicationName(QStringLiteral("tst_language"));
    }

    void init()
    {
        QSettings().clear();
        QLocale::setDefault(QLocale(QStringLiteral("en_US")));
    }

    void cleanup()
    {
        QSettings().clear();
        QLocale::setDefault(QLocale(QStringLiteral("en_US")));
    }

    void defaultsFromGermanSystemLocale()
    {
        QLocale::setDefault(QLocale(QStringLiteral("de_AT")));
        QQmlEngine engine;
        auto c = make(&engine);
        QCOMPARE(c->language(), QStringLiteral("de"));
    }

    void defaultsToEnglishForOtherLocales()
    {
        QLocale::setDefault(QLocale(QStringLiteral("fr_FR")));
        QQmlEngine engine;
        auto c = make(&engine);
        QCOMPARE(c->language(), QStringLiteral("en"));
    }

    void persistedChoiceWinsOverSystemLocale()
    {
        QSettings().setValue(QStringLiteral("ui/language"), QStringLiteral("de"));
        QLocale::setDefault(QLocale(QStringLiteral("fr_FR")));
        QQmlEngine engine;
        auto c = make(&engine);
        QCOMPARE(c->language(), QStringLiteral("de"));

        c->setLanguage(QStringLiteral("en"));
        QCOMPARE(QSettings().value(QStringLiteral("ui/language")).toString(), QStringLiteral("en"));
    }

    void invalidPersistedValueFallsBackToLocale()
    {
        QSettings().setValue(QStringLiteral("ui/language"), QStringLiteral("xx"));
        QLocale::setDefault(QLocale(QStringLiteral("de_DE")));
        QQmlEngine engine;
        auto c = make(&engine);
        QCOMPARE(c->language(), QStringLiteral("de"));
    }

    void switchEmitsOnceAndBumpsRevision()
    {
        QQmlEngine engine;
        auto c = make(&engine);
        QCOMPARE(c->language(), QStringLiteral("en"));
        const int before = c->revision();
        QSignalSpy spy(c.get(), &LanguageController::languageChanged);

        c->setLanguage(QStringLiteral("de"));
        QCOMPARE(spy.count(), 1);
        QCOMPARE(c->language(), QStringLiteral("de"));
        QCOMPARE(c->revision(), before + 1);
        QCOMPARE(QSettings().value(QStringLiteral("ui/language")).toString(), QStringLiteral("de"));

        // Same value: no-op.
        c->setLanguage(QStringLiteral("de"));
        QCOMPARE(spy.count(), 1);
        QCOMPARE(c->revision(), before + 1);

        // Unsupported codes are ignored.
        c->setLanguage(QStringLiteral("fr"));
        c->setLanguage(QString());
        QCOMPARE(spy.count(), 1);
        QCOMPARE(c->language(), QStringLiteral("de"));
    }

    void translatorSwitchRetranslatesQml()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        if (!buildTestCatalogue(dir.path()))
            QSKIP("lrelease unavailable; translator mechanics not exercised");

        QQmlEngine engine;
        auto c = make(&engine);
        c->setTranslationDirectory(dir.path());

        QQmlComponent component(&engine);
        component.setData("import QtQml\nQtObject { property string t: qsTr(\"Hello\") }\n",
                          QUrl::fromLocalFile(dir.path() + QStringLiteral("/Test.qml")));
        std::unique_ptr<QObject> obj(component.create());
        QVERIFY2(obj, qPrintable(component.errorString()));
        QCOMPARE(obj->property("t").toString(), QStringLiteral("Hello"));
        QSignalSpy textSpy(obj.get(), SIGNAL(tChanged()));

        c->setLanguage(QStringLiteral("de"));
        QCOMPARE(obj->property("t").toString(), QStringLiteral("Hallo"));
        QVERIFY(textSpy.count() >= 1);

        c->setLanguage(QStringLiteral("en"));
        QCOMPARE(obj->property("t").toString(), QStringLiteral("Hello"));
    }

    void shippedCataloguesAreEmbedded()
    {
        // qt_add_translations embeds the .qm files under :/i18n; the EN file
        // carries the plural forms of the English source strings.
        QVERIFY(QFile::exists(QStringLiteral(":/i18n/cysec_scanner_ui_en.qm")));
        QVERIFY(QFile::exists(QStringLiteral(":/i18n/cysec_scanner_ui_de.qm")));
    }

    void availableLanguagesContract()
    {
        LanguageController c;
        const QVariantList langs = c.availableLanguages();
        QCOMPARE(langs.size(), 2);
        QCOMPARE(langs.at(0).toMap().value(QStringLiteral("code")).toString(), QStringLiteral("en"));
        QCOMPARE(langs.at(0).toMap().value(QStringLiteral("name")).toString(),
                 QStringLiteral("English"));
        QCOMPARE(langs.at(1).toMap().value(QStringLiteral("code")).toString(), QStringLiteral("de"));
        QCOMPARE(langs.at(1).toMap().value(QStringLiteral("name")).toString(),
                 QStringLiteral("Deutsch"));
    }

    void formatterFollowsLanguage()
    {
        QQmlEngine engine;
        auto c = make(&engine);
        Formatter fmt;

        c->setLanguage(QStringLiteral("de"));
        QCOMPARE(fmt.count(12345, c->revision()), QStringLiteral("12.345"));

        c->setLanguage(QStringLiteral("en"));
        QCOMPARE(fmt.count(12345, c->revision()), QStringLiteral("12,345"));
    }

    void codesAreNeverLocalised()
    {
        // The controller exposes codes only; the persisted value and the
        // language property stay ASCII codes whatever the UI language is.
        QQmlEngine engine;
        auto c = make(&engine);
        c->setLanguage(QStringLiteral("de"));
        QCOMPARE(c->language(), QStringLiteral("de"));
        QCOMPARE(QSettings().value(QStringLiteral("ui/language")).toString(), QStringLiteral("de"));
    }
};

QTEST_MAIN(TestLanguage)

#include "tst_language.moc"
