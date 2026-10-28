// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtTest
import Cysec.Scanner.Ui

TestCase {
    id: testCase
    name: "Theme"
    when: windowShown
    // TestCase is invisible by default; children must be visible to take
    // Tab focus and to report visible icons.
    visible: true
    width: 400
    height: 300

    // WCAG 2.x relative luminance of a QML color (sRGB channels 0..1).
    function channel(c) {
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
    }
    function luminance(col) {
        return 0.2126 * channel(col.r) + 0.7152 * channel(col.g) + 0.0722 * channel(col.b)
    }
    function contrast(a, b) {
        const la = luminance(a)
        const lb = luminance(b)
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
    }

    readonly property var textPairs: [
        ["ink", "surface"], ["ink", "surfaceMuted"], ["ink", "zebra"],
        ["muted", "surface"], ["muted", "surfaceMuted"],
        ["subtle", "surface"], ["subtle", "surfaceMuted"],
        ["textOnAccent", "accent"], ["accent", "surface"],
        ["warningText", "warningFill"], ["errorText", "errorFill"], ["infoText", "infoFill"],
        ["ink", "accentTint"], ["textOnError", "errorEdge"]
    ]
    readonly property var nonTextPairs: [
        ["borderStrong", "surface"], ["borderStrong", "surfaceMuted"],
        ["accent", "neutralFill"], ["accent", "surfaceMuted"]
    ]

    function cleanup() {
        Appearance.forcedScheme = Appearance.Auto
    }

    function test_contrast_data() {
        return [
            { tag: "light", scheme: Appearance.Light },
            { tag: "dark", scheme: Appearance.Dark }
        ]
    }

    function test_contrast(data) {
        Appearance.forcedScheme = data.scheme
        compare(Theme.dark, data.scheme === Appearance.Dark)
        const failures = []
        for (const p of textPairs) {
            const r = contrast(Theme[p[0]], Theme[p[1]])
            if (r < 4.5)
                failures.push(p[0] + "/" + p[1] + " = " + r.toFixed(2) + " (< 4.5)")
        }
        for (const p of nonTextPairs) {
            const r = contrast(Theme[p[0]], Theme[p[1]])
            if (r < 3.0)
                failures.push(p[0] + "/" + p[1] + " = " + r.toFixed(2) + " (< 3.0)")
        }
        verify(failures.length === 0, data.tag + ": " + failures.join("; "))
    }

    function test_fonts() {
        for (const name of ["sansRegular", "sansSemiBold", "monoRegular", "monoSemiBold"]) {
            tryVerify(function() { return Theme[name].status === FontLoader.Ready }, 2000,
                      name + " did not reach FontLoader.Ready")
        }
        verify(Theme.sansFamily.length > 0)
        verify(Theme.monoFamily.length > 0)
        verify(Theme.sansFamily !== Theme.monoFamily)
    }

    function test_darkFollowsAppearance() {
        Appearance.forcedScheme = Appearance.Dark
        verify(Theme.dark)
        verify(Qt.colorEqual(Theme.surface, "#0f172a"), "dark surface is " + Theme.surface)
        Appearance.forcedScheme = Appearance.Light
        verify(!Theme.dark)
        verify(Qt.colorEqual(Theme.surface, "#ffffff"), "light surface is " + Theme.surface)
    }

    // Host data is shown in neutral greys only: the text colours must stay
    // low-chroma (max - min RGB channel) and never coincide with an accent or
    // status colour.
    function chroma(col) {
        return Math.max(col.r, col.g, col.b) - Math.min(col.r, col.g, col.b)
    }
    function test_neutralTextColours_data() {
        return [
            { tag: "light", scheme: Appearance.Light },
            { tag: "dark", scheme: Appearance.Dark }
        ]
    }

    function test_neutralTextColours(data) {
        Appearance.forcedScheme = data.scheme
        const signal = ["accent", "warningText", "warningEdge", "errorText", "errorEdge",
                        "infoText", "infoEdge"]
        for (const n of ["ink", "muted", "subtle"]) {
            verify(chroma(Theme[n]) < 0.2, n + " chroma " + chroma(Theme[n]).toFixed(2))
            for (const s of signal)
                verify(!Qt.colorEqual(Theme[n], Theme[s]), n + " equals " + s)
        }
    }

    Component {
        id: plainLabelComponent
        PlainLabel {}
    }

    function test_plainLabel() {
        const hostile = "<b>x</b><img src=\"http://192.0.2.1/\">"
        const label = createTemporaryObject(plainLabelComponent, testCase, { text: hostile })
        verify(label !== null)
        compare(label.textFormat, Text.PlainText)
        compare(label.text, hostile)
    }

    Component {
        id: buttonRow
        Row {
            property alias primary: primary
            property alias secondary: secondary
            property alias destructive: destructive
            PrimaryButton { id: primary; text: "X" }
            SecondaryButton { id: secondary; text: "X" }
            DestructiveButton { id: destructive; text: "X" }
        }
    }

    function test_buttonsAccessible() {
        const row = createTemporaryObject(buttonRow, testCase)
        verify(row !== null)
        for (const b of [row.primary, row.secondary, row.destructive]) {
            compare(b.Accessible.name, "X")
            verify(b.implicitHeight >= 36, "implicitHeight " + b.implicitHeight)
            verify(b.implicitWidth >= 96, "implicitWidth " + b.implicitWidth)
            verify(b.activeFocusOnTab)
        }
        row.primary.forceActiveFocus()
        verify(row.primary.activeFocus)
        keyClick(Qt.Key_Tab)
        verify(row.secondary.activeFocus, "Tab did not move focus to SecondaryButton")
        keyClick(Qt.Key_Tab)
        verify(row.destructive.activeFocus, "Tab did not move focus to DestructiveButton")
    }

    Component {
        id: badgeComponent
        StatusBadge {}
    }

    function test_statusBadge() {
        const badge = createTemporaryObject(badgeComponent, testCase,
                                            { kind: "partial", text: "Partial" })
        verify(badge !== null)
        const icon = findChild(badge, "statusBadgeIcon")
        const label = findChild(badge, "statusBadgeText")
        verify(icon !== null, "no icon")
        verify(label !== null, "no text")
        verify(icon.visible)
        verify(label.visible)
        verify(String(icon.source).length > 0)
        compare(label.text, "Partial")
        compare(badge.Accessible.name, "Partial")
    }
}
