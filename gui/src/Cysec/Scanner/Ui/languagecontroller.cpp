// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "languagecontroller.h"

#include <QQmlEngine>
#include <QVariantMap>

// Skeleton; plan 13-13 implements translator installation and switching.
// availableLanguages is already final because it is a contract constant.

LanguageController::LanguageController(QObject *parent)
    : QObject(parent)
{
}

LanguageController *LanguageController::create(QQmlEngine *qml, QJSEngine *js)
{
    Q_UNUSED(js);
    auto *controller = new LanguageController;
    controller->m_engine = qml;
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

void LanguageController::setLanguage(const QString &code)
{
    Q_UNUSED(code);
}
