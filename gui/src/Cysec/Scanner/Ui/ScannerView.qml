// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

pragma ComponentBehavior: Bound

import QtCore
import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Controls.impl
import QtQuick.Dialogs
import QtQuick.Layouts

// The whole scanner screen in one window (D-09), composed from the module
// components, top to bottom: capability banner (D-21), setup bar, progress,
// results table beside the detail panel, the collapsible log, and a footer
// with Export and Settings. No wizard, no tabs.
//
// The hosting window binds its title to windowTitle, forwards close
// requests to handleCloseRequest(close) and quits on quitRequested(). A
// running scan is never abandoned: closing asks first, stops the engine
// cooperatively and quits only once the session is terminal (D-22/D-27).
// The session and engine facts come in from C++; nothing here constructs a
// transport (D-18).
//
// Public surface fixed by plan 13-07. Additive (plan 13-16): noticesText,
// quitRequested(), openExport(), focusFilter().
Item {
    id: root

    property var session
    property var engineInfo
    readonly property string windowTitle: qsTr("Cysec Scanner")
    // THIRD_PARTY_NOTICES text, read by the app in C++ (no QML file access).
    property string noticesText

    signal quitRequested()

    function handleCloseRequest(close) {
        if (d.quitApproved) {
            close.accepted = true
            return
        }
        if (d.active) {
            // Never quit while the engine may still run (D-22).
            close.accepted = false
            if (d.closeMode !== d.closeNone)
                return
            if (d.state === ScanSession.Stopping) {
                // Already stopping: wait, then apply the unexported rule.
                d.closeMode = d.closeRecheck
                stoppingDialog.open()
            } else {
                closeDialog.open()
            }
            return
        }
        if (root.session && root.session.hasUnexportedResults) {
            close.accepted = false
            quitDialog.open()
            return
        }
        close.accepted = true
    }

    function openExport() {
        if (!exportButton.enabled)
            return
        exportSheet.open()
    }

    function focusFilter() {
        filterField.forceActiveFocus(Qt.ShortcutFocusReason)
        filterField.selectAll()
    }

    implicitWidth: 1024
    implicitHeight: 720

    QtObject {
        id: d

        readonly property int closeNone: 0
        readonly property int closeQuit: 1     // "Stop and quit": quit when terminal
        readonly property int closeRecheck: 2  // closed while stopping: re-ask if unexported

        readonly property int state: root.session ? root.session.state : ScanSession.Idle
        readonly property bool active: d.state === ScanSession.Running
            || d.state === ScanSession.Stopping
        readonly property bool terminal: d.state === ScanSession.Completed
            || d.state === ScanSession.Partial || d.state === ScanSession.Failed
        readonly property int hostsFound: root.session ? root.session.hostsFound : 0
        // A mid-scan export is partial even though the session is not.
        readonly property bool exportPartial: root.session
            ? (root.session.partial || d.active) : false
        readonly property bool hasPayload: !!root.session && root.session.hasPayload
            && d.terminal

        property bool bannerDismissed: false
        property bool quitApproved: false
        property int closeMode: d.closeNone
        property var pendingStart: null
        property string pendingFormat: "csv"
        property bool reconcileNote: false
        property string exportError: ""
        property url savedUrl
        property string savedPath: ""

        readonly property bool showBanner: !d.bannerDismissed && (
            (!!root.engineInfo && root.engineInfo.loaded && !root.engineInfo.unprivilegedIcmp)
            || (!!root.session && root.session.capabilitiesKnown && !root.session.unprivilegedIcmp))

        readonly property string failureText: {
            if (!root.session || d.state !== ScanSession.Failed)
                return ""
            switch (root.session.failure) {
            case ScanSession.EngineNotFound:
            case ScanSession.EngineFailedToStart:
                return qsTr("The scan engine was not found next to this app. Reinstall Cysec Scanner or set CYSEC_SCANNER_BIN.")
            case ScanSession.EngineRejectedInput:
                return qsTr("The scanner could not use that target: %1. Correct the network and start again.")
                    .arg(root.session.failureDetail)
            default:
                return qsTr("The scan stopped unexpectedly (exit code %1). Hosts found so far are kept; you can export them as partial results. See the log for details.")
                    .arg(root.session.exitCode)
            }
        }
        // The engine diagnostic line, shown as plain text below the message.
        readonly property string failureDetailLine: !!root.session
            && d.state === ScanSession.Failed
            && root.session.failure === ScanSession.EngineExitedNonZero
            ? root.session.failureDetail : ""

        readonly property string statusText: {
            if (d.state === ScanSession.Completed)
                return qsTr("Scan complete: %n host(s) found.", "", d.hostsFound)
            if (d.state === ScanSession.Partial)
                return qsTr("Partial results: scan stopped before finishing.")
            // Empty while running: ProgressPanel shows the stage line.
            return ""
        }

        readonly property string emptyTitle: d.state === ScanSession.Idle ? qsTr("No scan yet")
            : d.terminal ? qsTr("No hosts found") : ""
        readonly property string emptyBody: d.state === ScanSession.Idle
            ? qsTr("Check the target network above, then choose Start scan. Hosts appear here as they are found.")
            : d.terminal
              ? qsTr("Nothing responded on %1. Check the network range, or see the log for warnings.")
                    .arg(root.session && root.session.scope ? root.session.scope.join(", ") : "")
              : ""

        function startScan(request) {
            d.reconcileNote = false
            d.savedPath = ""
            root.session.start(request.cidrs, request.portSpec, request.probeFragile)
        }

        function requestStart(cidrs, portSpec, probeFragile) {
            if (!root.session)
                return
            const request = { cidrs: cidrs, portSpec: portSpec, probeFragile: probeFragile }
            if (root.session.hasUnexportedResults) {
                d.pendingStart = request
                discardDialog.open()
                return
            }
            d.startScan(request)
        }

        function approveQuit() {
            d.quitApproved = true
            root.quitRequested()
        }

        function onTerminal() {
            if (d.closeMode === d.closeNone)
                return
            const mode = d.closeMode
            d.closeMode = d.closeNone
            stoppingDialog.close()
            if (mode === d.closeRecheck && root.session.hasUnexportedResults)
                quitDialog.open()
            else
                d.approveQuit()
        }

        function openFileDialog(format) {
            d.pendingFormat = format
            fileDialog.defaultSuffix = format
            fileDialog.currentFolder = StandardPaths.writableLocation(StandardPaths.DocumentsLocation)
            fileDialog.selectedFile = fileDialog.currentFolder + "/"
                + Exporter.defaultFileName(format, d.exportPartial)
            fileDialog.open()
        }

        function localPath(url): string {
            let s = String(url)
            if (s.startsWith("file:///") && /^file:\/\/\/[A-Za-z]:/.test(s))
                s = s.substring(8)
            else if (s.startsWith("file://"))
                s = s.substring(7)
            return decodeURIComponent(s)
        }

        // Writes the chosen format to url; returns true on success.
        function exportTo(format, url): bool {
            if (!root.session)
                return false
            const result = format === "json" && d.hasPayload
                ? Exporter.exportJson(root.session.payloadPath, url)
                : Exporter.exportCsv(root.session.hosts, d.exportPartial, url)
            if (result.ok) {
                // Only a finished scan's results count as exported; a
                // mid-scan export keeps the quit/discard prompts armed.
                if (d.terminal)
                    root.session.markExported()
                d.savedUrl = url
                d.savedPath = d.localPath(url)
                toastTimer.restart()
                return true
            }
            d.exportError = String(result.error ?? "")
            exportErrorDialog.open()
            return false
        }
    }

    Connections {
        target: root.session ?? null
        ignoreUnknownSignals: true
        function onStateChanged() {
            if (d.terminal)
                d.onTerminal()
        }
        function onReconciled(changed) {
            d.reconcileNote = changed
        }
    }

    Shortcut {
        sequences: [StandardKey.Find]
        onActivated: root.focusFilter()
    }

    Shortcut {
        // Qt maps Ctrl to Cmd on macOS.
        sequence: "Ctrl+E"
        onActivated: root.openExport()
    }

    Rectangle {
        anchors.fill: parent
        color: Theme.surface
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        CapabilityBanner {
            id: banner
            objectName: "capabilityBanner"
            Layout.fillWidth: true
            visible: d.showBanner
            text: qsTr("Limited discovery: this computer cannot send ICMP pings without extra privileges, so host discovery uses ARP and TCP only. Some hosts may be missing from the results.")
            onDismissed: d.bannerDismissed = true
        }

        SetupBar {
            id: setupBar
            objectName: "setupBar"
            Layout.fillWidth: true
            Layout.preferredHeight: implicitHeight
            engineInfo: root.engineInfo
            running: d.active
            stopping: d.state === ScanSession.Stopping
            onStartRequested: (cidrs, portSpec, probeFragile) =>
                d.requestStart(cidrs, portSpec, probeFragile)
            onStopRequested: if (root.session) root.session.stop()
        }

        ProgressPanel {
            id: progress
            objectName: "progressPanel"
            Layout.fillWidth: true
            Layout.preferredHeight: implicitHeight
            visible: d.state !== ScanSession.Idle && d.state !== ScanSession.Failed
            stages: [qsTr("Discovery"), qsTr("Ports"), qsTr("Fingerprint")]
            scanState: d.state
            currentStage: root.session ? root.session.currentStageIndex : -1
            stageDone: root.session ? root.session.stageDone : 0
            stageTotal: root.session ? root.session.stageTotal : 0
            elapsedSeconds: root.session ? root.session.elapsedSeconds : 0
            hostsFound: d.hostsFound
            statusText: d.statusText

            PlainLabel {
                objectName: "reconcileNote"
                visible: d.reconcileNote
                text: qsTr("Results updated from final scan data")
                color: Theme.muted
                font.pixelSize: Theme.fontSizeLabel
                wrapMode: Text.Wrap
                elide: Text.ElideNone
            }
        }

        // Failed: the reason replaces the progress bar; the table stays.
        Item {
            id: failureBox
            objectName: "failureBox"
            Layout.fillWidth: true
            Layout.preferredHeight: failureRow.implicitHeight + 2 * Theme.spaceMd
            visible: d.state === ScanSession.Failed
            Accessible.role: Accessible.AlertMessage
            Accessible.name: d.failureText

            Rectangle {
                anchors.fill: parent
                anchors.margins: Theme.spaceSm
                color: Theme.errorFill
                radius: Theme.radiusSm
                border.width: 1
                border.color: Theme.errorEdge
            }

            RowLayout {
                id: failureRow
                anchors.fill: parent
                anchors.margins: Theme.spaceMd
                spacing: Theme.spaceSm

                ColorImage {
                    Layout.alignment: Qt.AlignTop
                    source: Theme.iconError
                    color: Theme.errorText
                    sourceSize.width: 16
                    sourceSize.height: 16
                    Layout.preferredWidth: 16
                    Layout.preferredHeight: 16
                    Accessible.ignored: true
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spaceXs

                    PlainLabel {
                        objectName: "failureText"
                        Layout.fillWidth: true
                        text: d.failureText
                        color: Theme.errorText
                        wrapMode: Text.Wrap
                        elide: Text.ElideNone
                    }

                    PlainLabel {
                        objectName: "failureDetail"
                        Layout.fillWidth: true
                        visible: text.length > 0
                        mono: true
                        text: d.failureDetailLine
                        color: Theme.errorText
                        font.pixelSize: Theme.fontSizeLabel
                        wrapMode: Text.Wrap
                        elide: Text.ElideNone
                    }
                }
            }
        }

        SplitView {
            id: split
            objectName: "mainSplit"
            Layout.fillWidth: true
            Layout.fillHeight: true
            orientation: Qt.Horizontal

            handle: Rectangle {
                implicitWidth: 8
                color: "transparent"
                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: 1
                    height: parent.height
                    color: Theme.hairline
                }
            }

            ColumnLayout {
                SplitView.fillWidth: true
                SplitView.minimumWidth: 320
                spacing: Theme.spaceSm

                TextField {
                    id: filterField
                    objectName: "filterField"
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.spaceMd
                    Layout.rightMargin: Theme.spaceMd
                    Layout.topMargin: Theme.spaceSm
                    implicitHeight: Theme.controlHeight
                    placeholderText: qsTr("Filter hosts")
                    placeholderTextColor: Theme.muted
                    color: Theme.ink
                    font.family: Theme.sansFamily
                    font.pixelSize: Theme.fontSizeBody
                    selectByMouse: true
                    Accessible.name: qsTr("Filter hosts")
                    background: Rectangle {
                        implicitHeight: Theme.controlHeight
                        radius: Theme.radiusSm
                        color: Theme.surface
                        border.width: filterField.activeFocus ? Theme.focusRingWidth : 1
                        border.color: filterField.activeFocus ? Theme.accent : Theme.borderStrong
                    }
                }

                ResultsTable {
                    id: results
                    objectName: "resultsTable"
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    model: root.session ? root.session.hosts : null
                    filterText: filterField.text
                    emptyTitle: d.emptyTitle
                    emptyBody: d.emptyBody
                    onHostActivated: detail.forceActiveFocus(Qt.TabFocusReason)
                }
            }

            DetailPanel {
                id: detail
                objectName: "detailPanel"
                SplitView.preferredWidth: 360
                SplitView.minimumWidth: 280
                SplitView.maximumWidth: 560
                host: results.currentHost
            }
        }

        LogPanel {
            id: logPanel
            objectName: "logPanel"
            Layout.fillWidth: true
            Layout.preferredHeight: implicitHeight
            model: root.session ? root.session.log : null
            warningCount: root.session && root.session.log ? root.session.log.warningCount : 0
            errorCount: root.session && root.session.log ? root.session.log.errorCount : 0
        }

        // Footer: export result toast, Export and Settings.
        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: footerRow.implicitHeight + 2 * Theme.spaceSm

            Rectangle {
                anchors.fill: parent
                color: Theme.surfaceMuted
                Rectangle {
                    width: parent.width
                    height: 1
                    color: Theme.hairline
                }
            }

            RowLayout {
                id: footerRow
                anchors.fill: parent
                anchors.leftMargin: Theme.spaceMd
                anchors.rightMargin: Theme.spaceMd
                anchors.topMargin: Theme.spaceSm
                anchors.bottomMargin: Theme.spaceSm
                spacing: Theme.spaceSm

                RowLayout {
                    id: toast
                    objectName: "savedToast"
                    Layout.fillWidth: true
                    visible: d.savedPath.length > 0
                    opacity: visible ? 1 : 0
                    spacing: Theme.spaceSm

                    Behavior on opacity {
                        NumberAnimation { duration: Theme.durationFast }
                    }

                    PlainLabel {
                        objectName: "savedText"
                        Layout.fillWidth: true
                        text: qsTr("Saved to %1").arg(d.savedPath)
                        color: Theme.muted
                        elide: Text.ElideMiddle
                    }

                    SecondaryButton {
                        objectName: "showInFolderButton"
                        text: qsTr("Show in folder")
                        onClicked: Exporter.showInFolder(d.savedUrl)
                    }
                }

                Item {
                    Layout.fillWidth: true
                    visible: !toast.visible
                }

                SecondaryButton {
                    id: exportButton
                    objectName: "exportButton"
                    text: qsTr("Export results")
                    enabled: !!root.session && (d.hostsFound > 0 || d.terminal)
                    onClicked: root.openExport()
                }

                SettingsMenu {
                    id: settings
                    objectName: "settingsMenu"
                    onAboutRequested: about.open()
                }
            }
        }
    }

    Timer {
        id: toastTimer
        interval: 10000
        onTriggered: d.savedPath = ""
    }

    ExportSheet {
        id: exportSheet
        objectName: "exportSheet"
        parent: root
        partial: d.exportPartial
        jsonAvailable: d.hasPayload
        onFormatChosen: format => d.openFileDialog(format)
    }

    FileDialog {
        id: fileDialog
        objectName: "exportFileDialog"
        title: qsTr("Export results")
        fileMode: FileDialog.SaveFile
        onAccepted: d.exportTo(d.pendingFormat, fileDialog.selectedFile)
    }

    AboutDialog {
        id: about
        objectName: "aboutDialog"
        parent: root
        guiVersion: root.engineInfo ? root.engineInfo.guiVersion : ""
        engineVersion: root.engineInfo ? root.engineInfo.engineVersion : ""
        qtVersion: root.engineInfo ? root.engineInfo.qtVersion : ""
        noticesText: root.noticesText
    }

    ConfirmDialog {
        id: closeDialog
        objectName: "closeDialog"
        parent: root
        destructive: true
        title: qsTr("Stop scan and quit?")
        body: qsTr("A scan is still running. Quitting stops it and keeps no further results. Hosts found so far can be lost unless exported.")
        primaryText: qsTr("Stop and quit")
        secondaryText: qsTr("Keep scanning")
        onPrimaryChosen: {
            if (!root.session || !d.active) {
                d.approveQuit()
                return
            }
            d.closeMode = d.closeQuit
            stoppingDialog.open()
            root.session.stop()
        }
    }

    // Shown while the engine winds down; the app quits once it is gone.
    Dialog {
        id: stoppingDialog
        objectName: "stoppingDialog"
        parent: root
        modal: true
        closePolicy: Popup.NoAutoClose
        anchors.centerIn: parent
        width: Math.min(480, root.width - 2 * Theme.spaceLg)
        padding: Theme.spaceLg
        topPadding: Theme.spaceSm
        title: qsTr("Stop scan and quit?")

        background: Rectangle {
            color: Theme.surfaceMuted
            radius: Theme.radiusMd
            border.width: 1
            border.color: Theme.hairline
        }

        header: PlainLabel {
            text: stoppingDialog.title
            leftPadding: Theme.spaceLg
            rightPadding: Theme.spaceLg
            topPadding: Theme.spaceLg
            font.pixelSize: Theme.fontSizeHeading
            font.weight: Theme.weightSemiBold
            wrapMode: Text.Wrap
            elide: Text.ElideNone
        }

        contentItem: PlainLabel {
            objectName: "stoppingText"
            text: qsTr("Stopping the scan...")
            color: Theme.muted
            wrapMode: Text.Wrap
            elide: Text.ElideNone
        }
    }

    ConfirmDialog {
        id: quitDialog
        objectName: "quitDialog"
        parent: root
        destructive: false
        title: qsTr("Quit without exporting?")
        body: qsTr("This scan's results have not been saved.")
        primaryText: qsTr("Export...")
        secondaryText: qsTr("Quit anyway")
        onPrimaryChosen: root.openExport()
        // Escape means "stay", not "quit anyway".
        onSecondaryChosen: if (quitDialog.choiceExplicit) d.approveQuit()
    }

    ConfirmDialog {
        id: discardDialog
        objectName: "discardDialog"
        parent: root
        destructive: false
        title: qsTr("Discard current results?")
        body: qsTr("These results have not been exported. Starting a new scan clears them.")
        primaryText: qsTr("Discard and scan")
        secondaryText: qsTr("Keep results")
        onPrimaryChosen: {
            const request = d.pendingStart
            d.pendingStart = null
            if (!request || !root.session)
                return
            root.session.discardResults()
            d.startScan(request)
        }
        onSecondaryChosen: d.pendingStart = null
    }

    ConfirmDialog {
        id: exportErrorDialog
        objectName: "exportErrorDialog"
        parent: root
        destructive: false
        title: qsTr("Export results")
        body: qsTr("Could not save the file: %1. Choose another location.").arg(d.exportError)
        primaryText: qsTr("Choose another location")
        secondaryText: qsTr("Cancel")
        onPrimaryChosen: d.openFileDialog(d.pendingFormat)
    }
}
