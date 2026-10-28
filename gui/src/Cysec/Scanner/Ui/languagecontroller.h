// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

class QJSEngine;
class QQmlEngine;

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

signals:
    void languageChanged();

private:
    QQmlEngine *m_engine = nullptr;
    QString m_language = QStringLiteral("en");
    int m_revision = 0;
};
