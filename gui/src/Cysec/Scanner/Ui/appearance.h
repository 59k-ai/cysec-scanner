// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QObject>
#include <QtQml/qqmlregistration.h>

// Appearance is the single source of OS appearance facts for QML: light or
// dark, reduced motion, and text scaling. Theme binds to it instead of reading
// Qt.styleHints directly, which qmllint cannot type-check.
class Appearance : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

    Q_PROPERTY(bool dark READ dark NOTIFY darkChanged FINAL)
    Q_PROPERTY(Scheme forcedScheme READ forcedScheme WRITE setForcedScheme NOTIFY forcedSchemeChanged FINAL)
    Q_PROPERTY(bool reducedMotion READ reducedMotion WRITE setReducedMotion NOTIFY reducedMotionChanged FINAL)
    Q_PROPERTY(qreal fontScale READ fontScale WRITE setFontScale NOTIFY fontScaleChanged FINAL)

public:
    enum Scheme { Auto, Light, Dark };
    Q_ENUM(Scheme)

    explicit Appearance(QObject *parent = nullptr);

    bool dark() const;

    Scheme forcedScheme() const { return m_forcedScheme; }
    void setForcedScheme(Scheme scheme);

    bool reducedMotion() const { return m_reducedMotion; }
    void setReducedMotion(bool reduced);

    qreal fontScale() const { return m_fontScale; }
    void setFontScale(qreal scale);

    // Parses a CYSEC_SCANNER_FONT_SCALE value; anything unparsable is 1.0,
    // and the result is clamped to 1.0..2.0 so layouts stay usable.
    static qreal parseFontScale(const QByteArray &raw);

signals:
    void darkChanged();
    void forcedSchemeChanged();
    void reducedMotionChanged();
    void fontScaleChanged();

private:
    void refreshDark();

    Scheme m_forcedScheme = Auto;
    bool m_dark = false;
    bool m_reducedMotion = false;
    qreal m_fontScale = 1.0;
};
