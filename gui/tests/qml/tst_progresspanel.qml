// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtTest
import Cysec.Scanner.Ui

TestCase {
    id: testCase
    name: "ProgressPanel"
    when: windowShown
    visible: true
    width: 900
    height: 400

    Component {
        id: panelComponent
        ProgressPanel {
            width: 860
            stages: ["Discovery", "Ports", "Fingerprint"]
        }
    }

    Component {
        id: bannerComponent
        CapabilityBanner {
            width: 860
        }
    }

    function cleanup() {
        Appearance.reducedMotion = false
    }

    // Every PlainLabel/Text under item, depth first.
    function texts(item, out) {
        if (!out)
            out = []
        if (item.text !== undefined && typeof item.text === "string" && item.visible)
            out.push(item.text)
        const kids = item.children
        for (let i = 0; i < kids.length; ++i)
            texts(kids[i], out)
        return out
    }

    function running(props) {
        const base = { scanState: 1, currentStage: 1, stageDone: 1200, stageTotal: 9472,
                       elapsedSeconds: 75, hostsFound: 3, title: "Scan progress" }
        for (const k in props)
            base[k] = props[k]
        return createTemporaryObject(panelComponent, testCase, base)
    }

    function test_percentageUsesFormatter() {
        const panel = running({})
        verify(panel)
        const pct = findChild(panel, "percentText")
        verify(pct)
        compare(pct.text, Formatter.percent(1200 / 9472, LanguageController.revision))
        compare(pct.textFormat, Text.PlainText)
    }

    function test_statusLine() {
        const panel = running({})
        const status = findChild(panel, "statusText")
        verify(status)
        verify(status.text.indexOf("Stage 2 of 3") === 0, status.text)
        compare(status.text, "Stage 2 of 3: Ports (" + Formatter.count(1200, 0) + " of "
                + Formatter.count(9472, 0) + " done)")
    }

    function test_statusTextOverrides() {
        const panel = running({ statusText: "Custom status" })
        compare(findChild(panel, "statusText").text, "Custom status")
    }

    function test_elapsed() {
        const panel = running({})
        const el = findChild(panel, "elapsedText")
        verify(el)
        verify(el.text.indexOf("01:15") >= 0, el.text)
        compare(el.text, "Elapsed 01:15")
        panel.elapsedSeconds = 3725
        compare(el.text, "Elapsed 1:02:05")
    }

    function test_hostsCounter() {
        const panel = running({})
        compare(findChild(panel, "hostsText").text, "3 hosts found")
        panel.hostsFound = 1
        compare(findChild(panel, "hostsText").text, "1 host found")
    }

    function test_noEta() {
        const panel = running({})
        const all = texts(panel)
        verify(all.length > 0)
        for (const t of all)
            verify(!/ETA|remaining/i.test(t), t)
    }

    function test_stageSegments() {
        const panel = running({})
        const segs = []
        for (let i = 0; i < 3; ++i) {
            const s = findChild(panel, "stageSegment" + i)
            verify(s, "segment " + i)
            segs.push(s)
        }
        compare(segs[0].color, Theme.accent)
        compare(segs[1].color, Theme.accent)
        compare(segs[2].color, Theme.neutralFill)
        compare(findChild(panel, "stageName1").text, "Ports")
    }

    function test_partialBadge() {
        const panel = running({ scanState: 4 })
        const badge = findChild(panel, "stateBadge")
        verify(badge)
        verify(badge.visible)
        compare(badge.text, "Partial")
        compare(badge.kind, "partial")
    }

    function test_runningBadge() {
        const panel = running({})
        const badge = findChild(panel, "stateBadge")
        verify(badge.visible)
        compare(badge.text, "Running")
    }

    function test_idleHasNoBadge() {
        const panel = running({ scanState: 0, currentStage: -1, stageDone: 0, stageTotal: 0 })
        verify(!findChild(panel, "stateBadge").visible)
        verify(!findChild(panel, "indeterminateSegment").visible)
    }

    function test_indeterminate() {
        const panel = running({ stageTotal: 0, stageDone: 0, currentStage: 0 })
        const seg = findChild(panel, "indeterminateSegment")
        verify(seg)
        verify(seg.visible)
        verify(findChild(panel, "indeterminateAnimation").running)
        verify(!findChild(panel, "stageFill").visible)
    }

    function test_indeterminateReducedMotion() {
        Appearance.reducedMotion = true
        const panel = running({ stageTotal: 0, stageDone: 0, currentStage: 0 })
        verify(findChild(panel, "indeterminateSegment").visible)
        verify(!findChild(panel, "indeterminateAnimation").running)
    }

    Component {
        id: panelWithExtra
        ProgressPanel {
            width: 860
            Rectangle {
                objectName: "extraRow"
                implicitWidth: 20
                implicitHeight: 40
            }
        }
    }

    function test_extraContentSlot() {
        const plain = createTemporaryObject(panelComponent, testCase)
        const panel = createTemporaryObject(panelWithExtra, testCase)
        const extra = findChild(panel, "extraRow")
        verify(extra)
        verify(extra.visible)
        verify(panel.implicitHeight >= plain.implicitHeight + 40)
    }

    function test_bannerText() {
        const banner = createTemporaryObject(bannerComponent, testCase,
                                             { text: "Limited discovery: test." })
        compare(findChild(banner, "bannerText").text, "Limited discovery: test.")
        compare(findChild(banner, "bannerText").textFormat, Text.PlainText)
    }

    function test_bannerDismiss() {
        const banner = createTemporaryObject(bannerComponent, testCase, { text: "x" })
        const spy = createTemporaryObject(spyComponent, testCase,
                                          { target: banner, signalName: "dismissed" })
        const btn = findChild(banner, "dismissButton")
        verify(btn)
        compare(btn.Accessible.name, "Dismiss")
        mouseClick(btn)
        compare(spy.count, 1)
    }

    function test_bannerNotDismissible() {
        const banner = createTemporaryObject(bannerComponent, testCase,
                                             { text: "x", dismissible: false })
        verify(!findChild(banner, "dismissButton").visible)
    }

    Component {
        id: spyComponent
        SignalSpy {}
    }
}
