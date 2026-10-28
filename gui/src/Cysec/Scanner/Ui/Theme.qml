// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

pragma Singleton

import QtQuick

// Design values for every Cysec.Scanner.Ui component. Components never use
// colour literals; they read these properties. Light or dark follows the OS
// through the Appearance singleton. Consumers extend the set with their own
// singleton instead of editing this one.
QtObject {
    id: theme

    // ---- Appearance -------------------------------------------------------
    readonly property bool dark: Appearance.dark
    readonly property bool reducedMotion: Appearance.reducedMotion
    readonly property real fontScale: Appearance.fontScale

    // ---- Colour -----------------------------------------------------------
    readonly property color surface:      dark ? "#0f172a" : "#ffffff"
    readonly property color surfaceMuted: dark ? "#1e293b" : "#f8fafc"
    readonly property color zebra:        dark ? "#172033" : "#fafafa"
    readonly property color neutralFill:  dark ? "#263449" : "#f1f5f9"
    readonly property color hairline:     dark ? "#334155" : "#e2e8f0"
    // Input borders are non-text UI and must reach 3:1 on every surface.
    readonly property color borderStrong: dark ? "#748499" : "#7c8aa0"

    readonly property color ink:    dark ? "#f1f5f9" : "#0f172a"
    readonly property color muted:  dark ? "#cbd5e1" : "#475569"
    readonly property color subtle: dark ? "#94a3b8" : "#64748b"

    // Accent is reserved: primary button fill, progress fill, selection
    // edge, focus ring, About links, checked checkboxes. Nothing else.
    readonly property color accent:     dark ? "#34d399" : "#047857"
    readonly property color accentTint: dark ? "#0b3b2e" : "#ecfdf5"
    readonly property color onAccent:   dark ? "#0f172a" : "#ffffff"

    readonly property color warningFill: dark ? "#3b2a0a" : "#fef3c7"
    readonly property color warningText: dark ? "#fcd34d" : "#92400e"
    readonly property color warningEdge: dark ? "#f59e0b" : "#b45309"

    readonly property color errorFill: dark ? "#3b0f1a" : "#ffe4e6"
    readonly property color errorText: dark ? "#fda4af" : "#9f1239"
    readonly property color errorEdge: dark ? "#fb7185" : "#9f1239"
    // Text on a filled errorEdge background (destructive button).
    readonly property color onError:   dark ? "#0f172a" : "#ffffff"

    readonly property color infoFill: dark ? "#0c2a40" : "#e0f2fe"
    readonly property color infoText: dark ? "#7dd3fc" : "#075985"
    readonly property color infoEdge: dark ? "#38bdf8" : "#0369a1"

    // ---- Spacing and sizes (device-independent px) ------------------------
    readonly property int spaceXs: 4
    readonly property int spaceSm: 8
    readonly property int spaceMd: 16
    readonly property int spaceLg: 24
    readonly property int spaceXl: 32
    readonly property int space2xl: 48
    readonly property int space3xl: 64

    readonly property int rowHeight: 32
    readonly property int controlHeight: 36
    readonly property int buttonMinWidth: 96
    readonly property int barHeight: 8
    readonly property int focusRingWidth: 2
    readonly property int radiusSm: 4
    readonly property int radiusMd: 8

    // ---- Typography -------------------------------------------------------
    readonly property int fontSizeLabel:   Math.round(12 * fontScale)
    readonly property int fontSizeBody:    Math.round(14 * fontScale)
    readonly property int fontSizeHeading: Math.round(18 * fontScale)
    readonly property int fontSizeDisplay: Math.round(24 * fontScale)

    readonly property int weightRegular: Font.Normal
    readonly property int weightSemiBold: Font.DemiBold

    readonly property FontLoader sansRegular:  FontLoader { source: "fonts/IBMPlexSans-Regular.ttf" }
    readonly property FontLoader sansSemiBold: FontLoader { source: "fonts/IBMPlexSans-SemiBold.ttf" }
    readonly property FontLoader monoRegular:  FontLoader { source: "fonts/IBMPlexMono-Regular.ttf" }
    readonly property FontLoader monoSemiBold: FontLoader { source: "fonts/IBMPlexMono-SemiBold.ttf" }

    readonly property string sansFamily: sansRegular.name
    readonly property string monoFamily: monoRegular.name

    // ---- Motion -----------------------------------------------------------
    readonly property int durationFast: reducedMotion ? 0 : 150
    readonly property int durationBar:  reducedMotion ? 0 : 100

    // ---- Icons (monochrome SVG, recoloured by the consumer) ---------------
    readonly property url iconChevron: Qt.resolvedUrl("icons/chevron.svg")
    readonly property url iconWarning: Qt.resolvedUrl("icons/warning.svg")
    readonly property url iconError:   Qt.resolvedUrl("icons/error.svg")
    readonly property url iconInfo:    Qt.resolvedUrl("icons/info.svg")

    function icon(name: string): url {
        return Qt.resolvedUrl("icons/" + name + ".svg")
    }
}
