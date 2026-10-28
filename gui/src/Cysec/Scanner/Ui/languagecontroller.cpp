// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "languagecontroller.h"

#include <QCoreApplication>
#include <QLocale>
#include <QQmlEngine>
#include <QSettings>
#include <QTranslator>
#include <QVariantMap>

// One translator per language, loaded from cysec_scanner_ui_<code>.qm. The
// "en" catalogue is the plurals-only file qt_add_translations generates for
// the source language (I18N_SOURCE_LANGUAGE en), so "%n host(s) found"
// resolves to proper English plurals once 13-17 fills it. Phase 14 installs
// its own translator alongside this one; nothing here removes foreign
// translators.
//
// The controller deals in language codes only; it never translates text in
// C++, and exports and file names are never localised.

namespace {

const QString kSettingsKey = QStringLiteral("ui/language");
const QString kCatalogueBase = QStringLiteral("cysec_scanner_ui");

} // namespace

LanguageController::LanguageController(QObject *parent)
    : QObject(parent)
{
}

LanguageController *LanguageController::create(QQmlEngine *qml, QJSEngine *js)
{
    Q_UNUSED(js);
    auto *controller = new LanguageController;
    controller->m_engine = qml;

    // Persisted choice first (D-28), else the system locale: any German
    // variant selects German, everything else English.
    QString code = QSettings().value(kSettingsKey).toString();
    if (!controller->isSupported(code))
        code = QLocale().name().startsWith(QLatin1String("de")) ? QStringLiteral("de")
                                                                : QStringLiteral("en");
    // Not persisted: a system-derived default keeps following the system
    // until the user picks a language.
    controller->apply(code, false);
    return controller;
}

QString LanguageController::language() const
{
    return m_language;
}

int LanguageController::revision() const
{
    return m_revision;
}

QVariantList LanguageController::availableLanguages() const
{
    return {
        QVariantMap{{QStringLiteral("code"), QStringLiteral("en")},
                    {QStringLiteral("name"), QStringLiteral("English")}},
        QVariantMap{{QStringLiteral("code"), QStringLiteral("de")},
                    {QStringLiteral("name"), QStringLiteral("Deutsch")}},
    };
}

bool LanguageController::isSupported(const QString &code) const
{
    const QVariantList langs = availableLanguages();
    for (const QVariant &v : langs) {
        if (v.toMap().value(QStringLiteral("code")).toString() == code)
            return true;
    }
    return false;
}

void LanguageController::setLanguage(const QString &code)
{
    if (code == m_language || !isSupported(code))
        return;
    apply(code, true);
}

void LanguageController::setTranslationDirectory(const QString &dir)
{
    m_translationDir = dir;
}

void LanguageController::apply(const QString &code, bool persist)
{
    if (m_translator) {
        QCoreApplication::removeTranslator(m_translator);
        delete m_translator;
        m_translator = nullptr;
    }

    auto *translator = new QTranslator(this);
    if (translator->load(QLocale(code), kCatalogueBase, QStringLiteral("_"), m_translationDir)
        && QCoreApplication::installTranslator(translator)) {
        m_translator = translator;
    } else {
        // Missing or empty catalogue: the English source strings show.
        delete translator;
    }

    // Formatter reads the default QLocale, so it must change before
    // revision does; bindings passing revision then re-run with the new
    // locale.
    QLocale::setDefault(QLocale(code));
    m_language = code;
    if (m_engine)
        m_engine->retranslate();
    ++m_revision;
    if (persist)
        QSettings().setValue(kSettingsKey, code);
    emit languageChanged();
}
