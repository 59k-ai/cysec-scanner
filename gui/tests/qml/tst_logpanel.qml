// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtTest
import Cysec.Scanner.Ui

TestCase {
    id: testCase
    name: "LogPanel"
    when: windowShown
    visible: true
    width: 800
    height: 400

    Component {
        id: panelComponent
        LogPanel {
            width: 760
        }
    }

    function cleanup() {
        Appearance.reducedMotion = false
    }

    function sampleLines() {
        return [
            { level: "info", text: "scan started" },
            { level: "warn", text: "ICMP unavailable" },
            { level: "error", text: "<b>x</b>" },
            { level: "warn", text: "host timeout" }
        ]
    }

    function makePanel(lines, props) {
        const model = TestData.logModel(lines)
        const base = { model: model }
        for (const k in props)
            base[k] = props[k]
        const panel = createTemporaryObject(panelComponent, testCase, base)
        verify(panel)
        panel.warningCount = Qt.binding(() => model.warningCount)
        panel.errorCount = Qt.binding(() => model.errorCount)
        return panel
    }

    function test_collapsedShowsBadges() {
        const panel = makePanel(sampleLines(), {})
        verify(!panel.expanded)
        const warn = findChild(panel, "warningBadge")
        const err = findChild(panel, "errorBadge")
        verify(warn.visible)
        verify(err.visible)
        compare(warn.text, qsTr("%n warning(s)", "", 2))
        compare(err.text, qsTr("%n error(s)", "", 1))
        verify(warn.text.indexOf("2") === 0)
        verify(err.text.indexOf("1") === 0)
        verify(!findChild(panel, "logList").visible)
        compare(panel.implicitHeight, panel.headerHeight)
    }

    function test_badgesHiddenWhenZero() {
        const panel = makePanel([{ level: "info", text: "ok" }], {})
        verify(!findChild(panel, "warningBadge").visible)
        verify(!findChild(panel, "errorBadge").visible)
    }

    function test_toggleShowsLines() {
        const panel = makePanel(sampleLines(), {})
        const toggle = findChild(panel, "logToggle")
        compare(toggle.Accessible.name, "Show log")
        mouseClick(toggle)
        verify(panel.expanded)
        compare(toggle.Accessible.name, "Hide log")
        const list = findChild(panel, "logList")
        verify(list.visible)
        tryCompare(list, "count", 4)
        waitForRendering(panel)

        // Level icon plus level word, never colour alone.
        compare(findChild(panel, "logLevel0").text, "Info")
        compare(findChild(panel, "logLevel1").text, "Warning")
        compare(findChild(panel, "logLevel2").text, "Error")
        verify(findChild(panel, "logIcon2").visible)
        compare(String(findChild(panel, "logIcon2").source), String(Theme.iconError))
        compare(String(findChild(panel, "logIcon1").source), String(Theme.iconWarning))

        compare(findChild(panel, "logTime0").text,
                Formatter.logTime(TestData.logTimeAt(0), LanguageController.revision))
    }

    function test_hostileMessageVerbatim() {
        const panel = makePanel(sampleLines(), { expanded: true })
        tryCompare(findChild(panel, "logList"), "count", 4)
        waitForRendering(panel)
        const msg = findChild(panel, "logText2")
        verify(msg)
        compare(msg.text, "<b>x</b>")
        compare(msg.textFormat, Text.PlainText)
    }

    function test_emptyState() {
        const panel = makePanel([], { expanded: true })
        const empty = findChild(panel, "logEmpty")
        verify(empty.visible)
        compare(empty.text, "No warnings or errors.")
    }

    function test_noClearControl() {
        const panel = makePanel(sampleLines(), { expanded: true })
        const walk = function(item) {
            if (item.text !== undefined && typeof item.text === "string")
                verify(!/clear/i.test(item.text), item.text)
            if (item.Accessible && item.Accessible.name)
                verify(!/clear/i.test(item.Accessible.name), item.Accessible.name)
            for (let i = 0; i < item.children.length; ++i)
                walk(item.children[i])
        }
        walk(panel)
    }

    function test_autoScrollFollowsNewest() {
        const lines = []
        for (let i = 0; i < 60; ++i)
            lines.push({ level: "info", text: "line " + i })
        const panel = makePanel(lines, { expanded: true })
        const list = findChild(panel, "logList")
        tryCompare(list, "count", 60)
        tryVerify(() => list.atYEnd)
        TestData.appendLog(panel.model, "info", "newest")
        tryCompare(list, "count", 61)
        tryVerify(() => list.atYEnd)
    }

    function test_noAutoScrollWhenUserScrolledUp() {
        const lines = []
        for (let i = 0; i < 60; ++i)
            lines.push({ level: "info", text: "line " + i })
        const panel = makePanel(lines, { expanded: true })
        const list = findChild(panel, "logList")
        tryVerify(() => list.atYEnd)
        // The user scrolls to the top.
        mouseWheel(list, list.width / 2, list.height / 2, 0, 2400)
        tryVerify(() => list.atYBeginning)
        wait(50)
        TestData.appendLog(panel.model, "warn", "newer")
        tryCompare(list, "count", 61)
        wait(50)
        verify(list.atYBeginning)
        verify(!list.atYEnd)
    }

    function test_errorPulse() {
        const panel = makePanel(sampleLines(), {})
        const pulse = findChild(panel, "errorPulse")
        verify(pulse)
        TestData.appendLog(panel.model, "error", "boom")
        compare(panel.errorCount, 2)
        verify(pulse.running)
    }

    function test_errorPulseReducedMotion() {
        Appearance.reducedMotion = true
        const panel = makePanel(sampleLines(), {})
        TestData.appendLog(panel.model, "error", "boom")
        compare(panel.errorCount, 2)
        verify(!findChild(panel, "errorPulse").running)
    }
}
