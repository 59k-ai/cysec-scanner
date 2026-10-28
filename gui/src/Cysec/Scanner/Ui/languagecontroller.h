// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QObject>
#include <QPointer>
#include <QString>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

class QJSEngine;
class QQmlEngine;
class QTranslator;

// LanguageController switches the UI language at runtime (English, German).
// It installs the translator and retranslates the QML engine; revision
// changes with every switch so locale-formatted bindings (counts, times)
// re-evaluate even where no qsTr string is involved.
//
// Contract fixed by plan 13-07; implemented in plan 13-13.
class LanguageController : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

    Q_PROPERTY(QString language READ language NOTIFY languageChanged FINAL)
    Q_PROPERTY(int revision READ revision NOTIFY languageChanged FINAL)
    // [{code:"en",name:"English"},{code:"de",name:"Deutsch"}]
    Q_PROPERTY(QVariantList availableLanguages READ availableLanguages CONSTANT FINAL)

public:
    explicit LanguageController(QObject *parent = nullptr);

    static LanguageController *create(QQmlEngine *qml, QJSEngine *js);

    QString language() const;
    int revision() const;
    QVariantList availableLanguages() const;

    Q_INVOKABLE void setLanguage(const QString &code);

    // Directory the cysec_scanner_ui_<lang>.qm catalogues load from
    // (":/i18n" by default). Added by plan 13-13 as a test hook; takes effect
    // on the next language switch.
    void setTranslationDirectory(const QString &dir);

signals:
    void languageChanged();

private:
    void apply(const QString &code);
    bool isSupported(const QString &code) const;

    QPointer<QQmlEngine> m_engine;
    QTranslator *m_translator = nullptr;
    QString m_translationDir = QStringLiteral(":/i18n");
    QString m_language = QStringLiteral("en");
    int m_revision = 0;
};
