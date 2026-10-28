// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import QtTest
import Cysec.Scanner.Ui

// SetupBar: subnet pre-fill and interface picker (D-08), the port preset
// and the fragile-probe option (no speed selector, D-12), and the
// authorisation gate for targets outside the local networks (D-11).
TestCase {
    id: testCase
    name: "AuthGate"
    when: windowShown
    visible: true
    width: 1100
    height: 400

    Component {
        id: barComponent
        SetupBar {
            width: testCase.width
        }
    }

    Component {
        id: spyComponent
        SignalSpy {}
    }

    function makeBar(fixture) {
        const info = TestData.engineInfo(fixture === undefined ? "describe-full.json" : fixture)
        const bar = createTemporaryObject(barComponent, testCase, { engineInfo: info })
        verify(bar)
        waitForRendering(bar)
        return bar
    }

    function child(bar, name) {
        const item = findChild(bar, name)
        verify(item, name)
        return item
    }

    function setTarget(bar, text) {
        const field = child(bar, "cidrField")
        field.forceActiveFocus()
        field.selectAll()
        // Typing goes through textEdited, like a user.
        if (text.length === 0)
            keyClick(Qt.Key_Backspace)
        else
            keySequence(text.split("").join(","))
        // keySequence is unreliable for punctuation; settle on the value.
        if (field.text !== text) {
            field.text = text
            field.textEdited()
        }
        compare(field.text, text)
    }

    function allItems(item, out) {
        if (!out)
            out = []
        out.push(item)
        for (let i = 0; i < item.children.length; ++i)
            allItems(item.children[i], out)
        return out
    }

    // ---- D-08 pre-fill and picker ------------------------------------------

    function test_prefilledFromFirstNetwork() {
        const bar = makeBar()
        compare(child(bar, "cidrField").text, "192.0.2.0/24")
        compare(child(bar, "cidrField").placeholderText, "192.0.2.0/24")
    }

    function test_prefillWaitsForDescribe() {
        // Never-loaded EngineInfo: nothing to pre-fill, and the field stays empty.
        const bar = makeBar("")
        compare(child(bar, "cidrField").text, "")
        verify(!child(bar, "startButton").enabled)
    }

    function test_interfacePickerListsNetworks() {
        const bar = makeBar()
        const picker = child(bar, "interfacePicker")
        compare(picker.count, 2)
        compare(picker.textAt(0), "eth0 — 192.0.2.0/24")
        compare(picker.textAt(1), "wlan0 — 198.51.100.0/24")
        compare(picker.currentIndex, -1)
        compare(picker.displayText, qsTr("Choose an interface"))
        picker.currentIndex = 1
        picker.activated(1)
        compare(child(bar, "cidrField").text, "198.51.100.0/24")
        // wlan0's network is local too: no gate.
        verify(!child(bar, "authRow").visible)
        verify(child(bar, "startButton").enabled)
    }

    // ---- D-11 authorisation gate -------------------------------------------

    function test_insideLocalNoGate() {
        const bar = makeBar()
        setTarget(bar, "192.0.2.0/25")
        verify(!child(bar, "authRow").visible)
        verify(child(bar, "startButton").enabled)
    }

    function test_outsideLocalNeedsTick() {
        const bar = makeBar()
        setTarget(bar, "203.0.113.0/24")
        const row = child(bar, "authRow")
        const check = child(bar, "authCheck")
        const start = child(bar, "startButton")
        verify(row.visible)
        compare(check.text, qsTr("I am authorised to scan this network"))
        compare(child(bar, "authHelper").text,
                qsTr("This range is outside your local subnet. Scan only networks you own or have written permission to test."))
        verify(child(bar, "authHelper").visible)
        verify(!start.enabled)

        mouseClick(check)
        verify(check.checked)
        verify(start.enabled)

        // Editing the scope resets the tick.
        setTarget(bar, "203.0.113.0/25")
        verify(!check.checked)
        verify(!start.enabled)

        // Back inside the local network: the row hides again.
        setTarget(bar, "192.0.2.0/24")
        verify(!row.visible)
        verify(start.enabled)
    }

    function test_noNetworksGatesEverything() {
        const bar = makeBar("describe-no-networks.json")
        setTarget(bar, "192.0.2.0/24")
        verify(child(bar, "authRow").visible)
        verify(!child(bar, "startButton").enabled)
    }

    function test_neverLoadedGatesEverything() {
        const bar = makeBar("")
        setTarget(bar, "192.0.2.0/24")
        verify(child(bar, "authRow").visible)
        verify(!child(bar, "startButton").enabled)
    }

    function test_authCheckAccessibleDescription() {
        const bar = makeBar()
        setTarget(bar, "203.0.113.0/24")
        const check = child(bar, "authCheck")
        compare(check.Accessible.name, qsTr("I am authorised to scan this network"))
        compare(check.Accessible.description, child(bar, "authHelper").text)
    }

    // ---- validation ----------------------------------------------------------

    function test_ipv6Rejected() {
        const bar = makeBar()
        setTarget(bar, "fe80::/64")
        const texts = allItems(bar).filter(i => i.visible && i.text === qsTr("Enter a network like 192.168.1.0/24."))
        verify(texts.length > 0, "inline CIDR error shown")
        verify(!child(bar, "startButton").enabled)
        verify(!child(bar, "authRow").visible)
    }

    function test_emptyDisablesStart() {
        const bar = makeBar()
        setTarget(bar, "")
        verify(!child(bar, "startButton").enabled)
        // A cleared field explains what is expected.
        const texts = allItems(bar).filter(i => i.visible && i.text === qsTr("Enter a network like 192.168.1.0/24."))
        verify(texts.length > 0)
    }

    function test_customPorts() {
        const bar = makeBar()
        const picker = child(bar, "portsPicker")
        const custom = child(bar, "customPortsField")
        compare(picker.count, 2)
        compare(picker.textAt(0), qsTr("Default ports"))
        compare(picker.textAt(1), qsTr("Custom..."))
        verify(!custom.visible)

        picker.currentIndex = 1
        verify(custom.visible)
        custom.text = "22,,80"
        const msg = qsTr("Use numbers 1-65535, separated by commas, ranges like 8000-8100 allowed.")
        verify(allItems(bar).some(i => i.visible && i.text === msg))
        verify(!child(bar, "startButton").enabled)

        custom.text = "22,80,8000-8100"
        verify(!allItems(bar).some(i => i.visible && i.text === msg))
        verify(child(bar, "startButton").enabled)
    }

    function test_noSpeedSelector() {
        const bar = makeBar()
        for (const item of allItems(bar)) {
            const t = typeof item.text === "string" ? item.text : ""
            const n = item.Accessible ? String(item.Accessible.name ?? "") : ""
            verify(!/timing/i.test(t), t)
            verify(!/timing/i.test(n), n)
        }
    }

    // ---- start / stop ----------------------------------------------------------

    function test_startDefaultPreset() {
        const bar = makeBar()
        const spy = createTemporaryObject(spyComponent, testCase,
                                          { target: bar, signalName: "startRequested" })
        mouseClick(child(bar, "startButton"))
        compare(spy.count, 1)
        compare(spy.signalArguments[0][0].length, 1)
        compare(spy.signalArguments[0][0][0], "192.0.2.0/24")
        compare(spy.signalArguments[0][1], "")
        compare(spy.signalArguments[0][2], false)
    }

    function test_startCustomPortsAndProbe() {
        const bar = makeBar()
        const spy = createTemporaryObject(spyComponent, testCase,
                                          { target: bar, signalName: "startRequested" })
        child(bar, "portsPicker").currentIndex = 1
        child(bar, "customPortsField").text = "22,80"
        mouseClick(child(bar, "probeCheck"))
        verify(child(bar, "probeCheck").checked)
        mouseClick(child(bar, "startButton"))
        compare(spy.count, 1)
        compare(spy.signalArguments[0][0][0], "192.0.2.0/24")
        compare(spy.signalArguments[0][1], "22,80")
        compare(spy.signalArguments[0][2], true)
    }

    function test_probeTooltipDescription() {
        const bar = makeBar()
        compare(child(bar, "probeCheck").Accessible.description,
                qsTr("Sends extra probes that some older printers, PLCs and embedded devices handle poorly. Leave off unless you know the network is safe to probe."))
    }

    function test_stopReplacesStart() {
        const bar = makeBar()
        const spy = createTemporaryObject(spyComponent, testCase,
                                          { target: bar, signalName: "stopRequested" })
        bar.running = true
        const start = child(bar, "startButton")
        const stop = child(bar, "stopButton")
        verify(!start.visible)
        verify(stop.visible)
        compare(stop.text, qsTr("Stop scan"))
        verify(stop.enabled)
        // Same slot: Stop sits where Start was.
        compare(stop.mapToItem(bar, 0, 0).x, start.mapToItem(bar, 0, 0).x)
        // Neutral outline, not destructive (partial results are kept).
        verify(String(stop).indexOf("SecondaryButton") === 0, String(stop))
        mouseClick(stop)
        compare(spy.count, 1)

        bar.stopping = true
        compare(stop.text, qsTr("Stopping..."))
        verify(!stop.enabled)

        bar.running = false
        bar.stopping = false
        verify(start.visible)
        verify(!stop.visible)
    }

    function test_everyControlNamed() {
        const bar = makeBar()
        child(bar, "portsPicker").currentIndex = 1
        setTarget(bar, "203.0.113.0/24")
        let checked = 0
        for (const item of allItems(bar)) {
            if (!item.visible || item.focusPolicy === undefined || item.focusPolicy === Qt.NoFocus)
                continue
            verify(String(item.Accessible.name ?? "").length > 0, String(item))
            ++checked
        }
        verify(checked >= 6, "checked " + checked)
    }
}
