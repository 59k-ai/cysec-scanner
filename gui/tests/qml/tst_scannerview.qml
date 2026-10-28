// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import QtTest
import Cysec.Scanner.Ui

// ScannerView composition over a stub session: the D-09 single-window
// layout, the D-21 banner, D-22/D-27 close handling, the discard prompt,
// export enablement and flow, failure copy, the reconcile note, shortcuts
// and an accessibility walk.
TestCase {
    id: testCase
    name: "ScannerView"
    when: windowShown
    visible: true
    width: 1280
    height: 800

    // Same QML-visible surface as ScanSession; records what the view calls.
    Component {
        id: sessionComponent
        QtObject {
            property int state: ScanSession.Idle
            property int currentStageIndex: -1
            property string currentStage: ""
            property int stageDone: 0
            property int stageTotal: 0
            property int elapsedSeconds: 0
            property int hostsFound: 0
            property bool capabilitiesKnown: false
            property bool unprivilegedIcmp: true
            property bool hasPayload: false
            property string payloadPath: ""
            property bool partial: false
            property int failure: ScanSession.NoFailure
            property int exitCode: 0
            property string failureDetail: ""
            property bool resultsExported: false
            property bool hasUnexportedResults: false
            property var hosts: null
            property var log: null
            property var scope: []
            property var calls: []
            property var lastStart: null

            signal reconciled(bool changed)

            function start(cidrs, portSpec, probeFragile) {
                calls = calls.concat(["start"])
                lastStart = [cidrs, portSpec, probeFragile]
                state = ScanSession.Running
            }
            function stop() {
                calls = calls.concat(["stop"])
                if (state === ScanSession.Running)
                    state = ScanSession.Stopping
            }
            function markExported() {
                calls = calls.concat(["markExported"])
                resultsExported = true
                hasUnexportedResults = false
            }
            function discardResults() {
                calls = calls.concat(["discardResults"])
                hasUnexportedResults = false
                state = ScanSession.Idle
            }
        }
    }

    Component {
        id: viewComponent
        ScannerView {
            width: testCase.width
            height: testCase.height
        }
    }

    Component {
        id: spyComponent
        SignalSpy {}
    }

    readonly property var sampleHosts: [
        { ip: "192.0.2.10", hostname: "printer.lan", vendor: "Acme",
          services: [{ port: 631, protocol: "tcp", serviceName: "ipp" }] },
        { ip: "192.0.2.20", hostname: "nas.lan", vendor: "Example" }
    ]

    function makeSession(props) {
        const s = createTemporaryObject(sessionComponent, testCase, props || {})
        s.hosts = TestData.hostModel([])
        s.log = TestData.logModel([])
        return s
    }

    function makeView(session, fixture) {
        const info = TestData.engineInfo(fixture === undefined ? "describe-full.json" : fixture)
        const view = createTemporaryObject(viewComponent, testCase,
                                           { session: session, engineInfo: info,
                                             noticesText: "NOTICES" })
        verify(view)
        waitForRendering(view)
        return view
    }

    function child(item, name) {
        const c = findChild(item, name)
        verify(c, name)
        return c
    }

    function spyOn(target, signalName) {
        return createTemporaryObject(spyComponent, testCase,
                                     { target: target, signalName: signalName })
    }

    function allItems(item, out) {
        if (!out)
            out = []
        out.push(item)
        for (let i = 0; i < item.children.length; ++i)
            allItems(item.children[i], out)
        return out
    }

    function closeEvent() {
        return { accepted: true }
    }

    function init() {
        // A file dialog round trip can leave the test window inactive, and
        // window shortcuts only fire in the active window.
        const w = testCase.Window.window
        w.requestActivate()
        tryVerify(() => w.active, 2000)
    }

    // ---- layout -----------------------------------------------------------

    function test_windowTitle() {
        const view = makeView(makeSession())
        compare(view.windowTitle, qsTr("Cysec Scanner"))
    }

    function test_singleWindowLayout() {
        const s = makeSession({ state: ScanSession.Running })
        const view = makeView(s)
        const setup = child(view, "setupBar")
        const progress = child(view, "progressPanel")
        const split = child(view, "mainSplit")
        const table = child(view, "resultsTable")
        const detail = child(view, "detailPanel")
        const log = child(view, "logPanel")
        const exportButton = child(view, "exportButton")
        child(view, "settingsMenu")

        // Top to bottom: setup, progress, split (table | detail), log, footer.
        const y = item => item.mapToItem(view, 0, 0).y
        verify(y(setup) < y(progress))
        verify(y(progress) < y(split))
        verify(y(split) < y(log))
        verify(y(log) < y(exportButton))
        verify(table.mapToItem(view, 0, 0).x < detail.mapToItem(view, 0, 0).x)
        tryVerify(() => Math.abs(detail.width - 360) <= 1, 2000, "detail width " + detail.width)
        compare(detail.SplitView.minimumWidth, 280)
        compare(detail.SplitView.maximumWidth, 560)
        verify(!log.expanded)
        verify(child(view, "filterField").mapToItem(view, 0, 0).y < table.mapToItem(view, 0, 0).y)
    }

    function test_progressBindsSession() {
        const s = makeSession({ state: ScanSession.Running, currentStageIndex: 1,
                                stageDone: 3, stageTotal: 10, elapsedSeconds: 65,
                                hostsFound: 2 })
        const view = makeView(s)
        const progress = child(view, "progressPanel")
        compare(progress.scanState, ScanSession.Running)
        compare(progress.currentStage, 1)
        compare(progress.stageDone, 3)
        compare(progress.stageTotal, 10)
        compare(progress.elapsedSeconds, 65)
        compare(progress.hostsFound, 2)
        compare(progress.stages.length, 3)
        // Running leaves statusText empty so the stage line shows.
        compare(progress.statusText, "")

        s.state = ScanSession.Completed
        compare(progress.statusText, "Scan complete: 2 hosts found.")
        s.state = ScanSession.Partial
        compare(progress.statusText, qsTr("Partial results: scan stopped before finishing."))
    }

    function test_idleHidesProgressAndShowsEmptyState() {
        const view = makeView(makeSession())
        verify(!child(view, "progressPanel").visible)
        const table = child(view, "resultsTable")
        compare(table.emptyTitle, qsTr("No scan yet"))
        compare(table.emptyBody, qsTr("Check the target network above, then choose Start scan. Hosts appear here as they are found."))
    }

    function test_nothingFoundEmptyState() {
        const s = makeSession({ state: ScanSession.Completed, scope: ["192.0.2.0/24"] })
        const view = makeView(s)
        const table = child(view, "resultsTable")
        compare(table.emptyTitle, qsTr("No hosts found"))
        compare(table.emptyBody,
                qsTr("Nothing responded on %1. Check the network range, or see the log for warnings.")
                    .arg("192.0.2.0/24"))
    }

    function test_detailFollowsSelection() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 2 })
        s.hosts = TestData.hostModel(sampleHosts)
        const view = makeView(s)
        const table = child(view, "resultsTable")
        table.selectRow(0)
        compare(child(view, "detailPanel").host.ip, "192.0.2.10")
    }

    // ---- D-21 banner ----------------------------------------------------------

    function test_bannerFromEngineInfo() {
        const view = makeView(makeSession(), "describe-no-icmp.json")
        const banner = child(view, "capabilityBanner")
        verify(banner.visible)
        compare(banner.text, qsTr("Limited discovery: this computer cannot send ICMP pings without extra privileges, so host discovery uses ARP and TCP only. Some hosts may be missing from the results."))
        mouseClick(child(banner, "dismissButton"))
        verify(!banner.visible)
    }

    function test_bannerHiddenWithIcmp() {
        const s = makeSession()
        const view = makeView(s)
        const banner = child(view, "capabilityBanner")
        verify(!banner.visible)
        // scan_start reports the capability for this run.
        s.capabilitiesKnown = true
        s.unprivilegedIcmp = false
        verify(banner.visible)
    }

    function test_noElevationControl() {
        const view = makeView(makeSession(), "describe-no-icmp.json")
        for (const item of allItems(view)) {
            const t = typeof item.text === "string" ? item.text : ""
            const n = item.Accessible ? String(item.Accessible.name ?? "") : ""
            verify(!/administrator|run as admin/i.test(t), t)
            verify(!/administrator|run as admin/i.test(n), n)
        }
    }

    // ---- close handling (D-22 / D-27) ------------------------------------------

    function test_closeWhileRunningStopsThenQuits() {
        const s = makeSession({ state: ScanSession.Running })
        const view = makeView(s)
        const quit = spyOn(view, "quitRequested")
        const dialog = child(view, "closeDialog")

        const ev = closeEvent()
        view.handleCloseRequest(ev)
        compare(ev.accepted, false)
        tryCompare(dialog, "opened", true)
        verify(dialog.destructive)
        verify(!dialog.primaryIsDefault, "Keep scanning is the default")
        compare(dialog.secondaryText, qsTr("Keep scanning"))
        compare(dialog.primaryText, qsTr("Stop and quit"))

        mouseClick(findChild(dialog.footer, "destructiveButton"))
        compare(s.calls, ["stop"])
        compare(s.state, ScanSession.Stopping)
        const stopping = child(view, "stoppingDialog")
        tryCompare(stopping, "opened", true)
        compare(stopping.contentItem.text, qsTr("Stopping the scan..."))
        verify(stopping.contentItem.visible)
        compare(quit.count, 0)

        // A second close while stopping still refuses.
        const ev2 = closeEvent()
        view.handleCloseRequest(ev2)
        compare(ev2.accepted, false)
        compare(quit.count, 0)

        s.hasUnexportedResults = true
        s.state = ScanSession.Partial
        compare(quit.count, 1)
        tryCompare(stopping, "visible", false)

        // The quit-triggered close is now accepted.
        const ev3 = closeEvent()
        view.handleCloseRequest(ev3)
        compare(ev3.accepted, true)
    }

    function test_closeWhileRunningKeepScanning() {
        const s = makeSession({ state: ScanSession.Running })
        const view = makeView(s)
        const quit = spyOn(view, "quitRequested")
        const dialog = child(view, "closeDialog")
        view.handleCloseRequest(closeEvent())
        tryCompare(dialog, "opened", true)
        keyClick(Qt.Key_Escape)
        tryCompare(dialog, "visible", false)
        compare(s.calls, [])
        compare(s.state, ScanSession.Running)
        s.state = ScanSession.Completed
        compare(quit.count, 0)
    }

    function test_closeWhileStoppingWaitsAndRechecks() {
        const s = makeSession({ state: ScanSession.Stopping })
        const view = makeView(s)
        const quit = spyOn(view, "quitRequested")
        const ev = closeEvent()
        view.handleCloseRequest(ev)
        compare(ev.accepted, false)
        tryCompare(child(view, "stoppingDialog"), "opened", true)
        s.hasUnexportedResults = true
        s.state = ScanSession.Partial
        compare(quit.count, 0)
        tryCompare(child(view, "quitDialog"), "opened", true)
    }

    function test_closeWithUnexportedResults() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 2,
                                hasUnexportedResults: true })
        s.hosts = TestData.hostModel(sampleHosts)
        const view = makeView(s)
        const quit = spyOn(view, "quitRequested")
        const dialog = child(view, "quitDialog")

        const ev = closeEvent()
        view.handleCloseRequest(ev)
        compare(ev.accepted, false)
        tryCompare(dialog, "opened", true)
        compare(dialog.title, qsTr("Quit without exporting?"))
        compare(dialog.body, qsTr("This scan's results have not been saved."))
        compare(dialog.primaryText, qsTr("Export..."))
        compare(dialog.secondaryText, qsTr("Quit anyway"))
        verify(!dialog.destructive)
        verify(dialog.primaryIsDefault, "Export... is the default")

        // Escape stays in the app.
        keyClick(Qt.Key_Escape)
        tryCompare(dialog, "visible", false)
        compare(quit.count, 0)

        view.handleCloseRequest(closeEvent())
        tryCompare(dialog, "opened", true)
        mouseClick(findChild(dialog.footer, "secondaryButton"))
        compare(quit.count, 1)
    }

    function test_quitDialogExportOpensSheet() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 2,
                                hasUnexportedResults: true })
        const view = makeView(s)
        const dialog = child(view, "quitDialog")
        view.handleCloseRequest(closeEvent())
        tryCompare(dialog, "opened", true)
        mouseClick(findChild(dialog.footer, "primaryButton"))
        tryCompare(child(view, "exportSheet"), "opened", true)
        child(view, "exportSheet").close()
    }

    function test_closeWhenIdleAccepted() {
        const view = makeView(makeSession())
        const ev = closeEvent()
        view.handleCloseRequest(ev)
        compare(ev.accepted, true)
        verify(!child(view, "closeDialog").visible)
        verify(!child(view, "quitDialog").visible)
    }

    function test_closeWhenExportedAccepted() {
        const view = makeView(makeSession({ state: ScanSession.Completed, hostsFound: 2,
                                            resultsExported: true }))
        const ev = closeEvent()
        view.handleCloseRequest(ev)
        compare(ev.accepted, true)
    }

    // ---- discard prompt ----------------------------------------------------------

    function test_startWithUnexportedAsksDiscard() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 2,
                                hasUnexportedResults: true })
        const view = makeView(s)
        const dialog = child(view, "discardDialog")
        mouseClick(child(view, "startButton"))
        tryCompare(dialog, "opened", true)
        compare(dialog.title, qsTr("Discard current results?"))
        compare(dialog.body, qsTr("These results have not been exported. Starting a new scan clears them."))
        compare(dialog.primaryText, qsTr("Discard and scan"))
        compare(dialog.secondaryText, qsTr("Keep results"))
        verify(!dialog.destructive)
        compare(s.calls, [])

        mouseClick(findChild(dialog.footer, "primaryButton"))
        compare(s.calls, ["discardResults", "start"])
        compare(s.lastStart[0][0], "192.0.2.0/24")
    }

    function test_keepResultsDoesNothing() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 2,
                                hasUnexportedResults: true })
        const view = makeView(s)
        const dialog = child(view, "discardDialog")
        mouseClick(child(view, "startButton"))
        tryCompare(dialog, "opened", true)
        mouseClick(findChild(dialog.footer, "secondaryButton"))
        tryCompare(dialog, "visible", false)
        compare(s.calls, [])
        compare(s.state, ScanSession.Completed)
    }

    function test_startWithoutResultsStartsDirectly() {
        const s = makeSession()
        const view = makeView(s)
        mouseClick(child(view, "startButton"))
        compare(s.calls, ["start"])
        verify(!child(view, "discardDialog").visible)
        // Stop goes to the session.
        mouseClick(child(view, "stopButton"))
        compare(s.calls, ["start", "stop"])
        compare(child(view, "stopButton").text, qsTr("Stopping..."))
    }

    // ---- export -------------------------------------------------------------------

    function test_exportButtonEnablement() {
        const s = makeSession()
        const view = makeView(s)
        const button = child(view, "exportButton")
        compare(button.text, qsTr("Export results"))
        verify(!button.enabled)
        s.state = ScanSession.Running
        verify(!button.enabled)
        s.hostsFound = 1
        verify(button.enabled)
        s.hostsFound = 0
        s.state = ScanSession.Completed
        verify(button.enabled)
    }

    function test_exportSheetWithoutPayload() {
        const s = makeSession({ state: ScanSession.Partial, partial: true, hostsFound: 2,
                                hasPayload: false })
        const view = makeView(s)
        const sheet = child(view, "exportSheet")
        view.openExport()
        tryCompare(sheet, "opened", true)
        verify(sheet.partial)
        verify(!sheet.jsonAvailable)
        verify(!findChild(sheet.contentItem, "jsonChoice").enabled)
        verify(findChild(sheet.contentItem, "jsonUnavailable").visible)
        compare(findChild(sheet.contentItem, "jsonUnavailable").text,
                qsTr("The JSON payload is not available because the scan did not finish writing it. Export the CSV table instead."))
        verify(findChild(sheet.contentItem, "partialBadge").visible)
        compare(sheet.format, "csv")
        compare(findChild(sheet.contentItem, "chooseButton").text, qsTr("Choose location..."))
        compare(findChild(sheet.contentItem, "cancelButton").text, qsTr("Cancel"))
        sheet.close()
    }

    function test_exportSheetWithPayload() {
        const s = makeSession({ state: ScanSession.Completed, partial: false, hostsFound: 2,
                                hasPayload: true, payloadPath: "/nonexistent" })
        const view = makeView(s)
        const sheet = child(view, "exportSheet")
        view.openExport()
        tryCompare(sheet, "opened", true)
        verify(sheet.jsonAvailable)
        verify(!sheet.partial)
        verify(findChild(sheet.contentItem, "jsonChoice").enabled)
        verify(!findChild(sheet.contentItem, "jsonUnavailable").visible)
        verify(!findChild(sheet.contentItem, "partialBadge").visible)
        compare(sheet.format, "json")
        sheet.close()
    }

    function test_partialDefaultFileName() {
        const s = makeSession({ state: ScanSession.Partial, partial: true, hostsFound: 2 })
        const view = makeView(s)
        const sheet = child(view, "exportSheet")
        const dialog = child(view, "exportFileDialog")
        view.openExport()
        tryCompare(sheet, "opened", true)
        sheet.choose()
        const name = String(dialog.selectedFile)
        verify(/cysec-scan-\d{8}-\d{6}-partial\.csv$/.test(name), name)
        dialog.close()
    }

    function test_completeDefaultFileName() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 2, hasPayload: true,
                                payloadPath: "/nonexistent" })
        const view = makeView(s)
        const sheet = child(view, "exportSheet")
        const dialog = child(view, "exportFileDialog")
        view.openExport()
        tryCompare(sheet, "opened", true)
        sheet.choose()
        const name = String(dialog.selectedFile)
        verify(/cysec-scan-\d{8}-\d{6}\.json$/.test(name), name)
        dialog.close()
    }

    function test_exportCsvWritesAndMarksExported() {
        const s = makeSession({ state: ScanSession.Partial, partial: true, hostsFound: 2,
                                hasUnexportedResults: true })
        s.hosts = TestData.hostModel(sampleHosts)
        const view = makeView(s)
        const dialog = child(view, "exportFileDialog")
        view.openExport()
        child(view, "exportSheet").choose()
        dialog.close()
        const url = TestData.tempFileUrl("view-export.csv")
        dialog.selectedFile = url
        dialog.accepted()
        compare(s.calls, ["markExported"])
        const csv = String(TestData.readFile(url))
        verify(csv.indexOf("192.0.2.10") >= 0, csv)
        verify(csv.indexOf("partial") >= 0, csv)
        const toast = child(view, "savedToast")
        verify(toast.visible)
        verify(child(view, "savedText").text.indexOf("view-export.csv") >= 0)
        compare(child(view, "showInFolderButton").text, qsTr("Show in folder"))
    }

    function test_midScanExportIsPartialAndNotMarked() {
        const s = makeSession({ state: ScanSession.Running, hostsFound: 2 })
        s.hosts = TestData.hostModel(sampleHosts)
        const view = makeView(s)
        const sheet = child(view, "exportSheet")
        view.openExport()
        tryCompare(sheet, "opened", true)
        verify(sheet.partial)
        verify(!sheet.jsonAvailable)
        sheet.choose()
        const dialog = child(view, "exportFileDialog")
        verify(/-partial\.csv$/.test(String(dialog.selectedFile)))
        dialog.close()
        const url = TestData.tempFileUrl("mid-scan.csv")
        dialog.selectedFile = url
        dialog.accepted()
        compare(s.calls, [])
    }

    function test_exportErrorOffersAnotherLocation() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 2,
                                hasUnexportedResults: true })
        s.hosts = TestData.hostModel(sampleHosts)
        const view = makeView(s)
        const dialog = child(view, "exportFileDialog")
        view.openExport()
        child(view, "exportSheet").choose()
        dialog.close()
        dialog.selectedFile = TestData.tempFileUrl("missing-dir/x.csv")
        dialog.accepted()
        const err = child(view, "exportErrorDialog")
        tryCompare(err, "opened", true)
        verify(err.body.indexOf(qsTr("Could not save the file: %1. Choose another location.").arg("").split("%1")[0].substring(0, 10)) === 0)
        compare(err.primaryText, qsTr("Choose another location"))
        compare(s.calls, [])
        mouseClick(findChild(err.footer, "primaryButton"))
        tryCompare(dialog, "visible", true)
        dialog.close()
    }

    // ---- failure, reconcile ----------------------------------------------------------

    function test_engineNotFound() {
        const s = makeSession({ state: ScanSession.Failed, failure: ScanSession.EngineNotFound,
                                hostsFound: 2 })
        s.hosts = TestData.hostModel(sampleHosts)
        const view = makeView(s)
        verify(!child(view, "progressPanel").visible)
        verify(child(view, "failureBox").visible)
        compare(child(view, "failureText").text,
                qsTr("The scan engine was not found next to this app. Reinstall Cysec Scanner or set CYSEC_SCANNER_BIN."))
        verify(child(view, "resultsTable").visible)
        verify(child(view, "exportButton").enabled)
    }

    function test_exitNonZeroShowsCodeAndPlainDetail() {
        const s = makeSession({ state: ScanSession.Failed,
                                failure: ScanSession.EngineExitedNonZero, exitCode: 3,
                                failureDetail: "<b>boom</b>" })
        const view = makeView(s)
        compare(child(view, "failureText").text,
                qsTr("The scan stopped unexpectedly (exit code %1). Hosts found so far are kept; you can export them as partial results. See the log for details.").arg(3))
        const detail = child(view, "failureDetail")
        compare(detail.text, "<b>boom</b>")
        compare(detail.textFormat, Text.PlainText)
    }

    function test_rejectedInput() {
        const s = makeSession({ state: ScanSession.Failed,
                                failure: ScanSession.EngineRejectedInput,
                                failureDetail: "bad cidr" })
        const view = makeView(s)
        compare(child(view, "failureText").text,
                qsTr("The scanner could not use that target: %1. Correct the network and start again.").arg("bad cidr"))
    }

    function test_reconcileNote() {
        const s = makeSession({ state: ScanSession.Completed })
        const view = makeView(s)
        const note = child(view, "reconcileNote")
        verify(!note.visible)
        s.reconciled(false)
        verify(!note.visible)
        s.reconciled(true)
        verify(note.visible)
        compare(note.text, qsTr("Results updated from final scan data"))
    }

    // ---- shortcuts, about, accessibility ------------------------------------------------

    function test_findFocusesFilter() {
        const view = makeView(makeSession())
        const filter = child(view, "filterField")
        compare(filter.placeholderText, qsTr("Filter hosts"))
        verify(!filter.activeFocus)
        keySequence(StandardKey.Find)
        tryVerify(() => filter.activeFocus)
    }

    function test_ctrlEOpensExport() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 1 })
        const view = makeView(s)
        keySequence("Ctrl+E")
        const sheet = child(view, "exportSheet")
        tryCompare(sheet, "opened", true)
        sheet.close()
    }

    function test_aboutGetsNoticesAndVersions() {
        const view = makeView(makeSession())
        const about = child(view, "aboutDialog")
        compare(about.noticesText, "NOTICES")
        compare(about.engineVersion, "v0.2.0")
        verify(about.qtVersion.length > 0)
        child(view, "settingsMenu").aboutRequested()
        tryCompare(about, "opened", true)
        about.close()
    }

    function test_everyControlNamed() {
        const s = makeSession({ state: ScanSession.Completed, hostsFound: 2 })
        s.hosts = TestData.hostModel(sampleHosts)
        const view = makeView(s, "describe-no-icmp.json")
        child(view, "resultsTable").selectRow(0)
        waitForRendering(view)
        let checked = 0
        for (const item of allItems(view)) {
            // Controls (buttons, fields, checks, combos) take Tab focus;
            // views such as the table header do not.
            if (!item.visible || item.focusPolicy === undefined
                    || !(item.focusPolicy & Qt.TabFocus) || !item.activeFocusOnTab)
                continue
            verify(String(item.Accessible.name ?? "").length > 0, String(item))
            ++checked
        }
        verify(checked >= 10, "checked " + checked)
    }
}
