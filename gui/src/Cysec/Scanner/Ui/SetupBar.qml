// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Controls.impl
import QtQuick.Layouts

// Scan setup: targets, ports, fragile-probe switch, start and stop.
//
// The target field is pre-filled once from the first detected network
// (D-08) and the interface picker fills it with another one. Options are
// the target list, the port preset and the fragile-probe switch only; no
// speed tier is offered (D-12, deferred). A target outside every
// detected local network needs the authorisation tick before Start is
// enabled (D-11). The tick is reset on every edit of the target and is
// never stored or sent anywhere.
//
// Public surface fixed by plan 13-07. Additive (plan 13-16): targetText,
// customPorts, startEnabled, needsAuthorisation and focusTarget().
Item {
    id: root

    property var engineInfo
    property bool running: false
    property bool stopping: false

    signal startRequested(var cidrs, string portSpec, bool probeFragile)
    signal stopRequested()

    // Current raw text of the target field.
    readonly property alias targetText: cidrField.text
    readonly property bool customPorts: portsPicker.currentIndex === 1
    readonly property bool needsAuthorisation: d.targets.ok && d.requiresAuth
    readonly property bool startEnabled: !root.running && d.targets.ok && d.ports.ok
        && (!d.requiresAuth || authCheck.checked)

    implicitWidth: 800
    implicitHeight: layout.implicitHeight + 2 * Theme.spaceMd

    function focusTarget() {
        cidrField.forceActiveFocus(Qt.ShortcutFocusReason)
    }

    QtObject {
        id: d

        property bool touched: false
        property bool prefilled: false

        readonly property var networks: root.engineInfo && root.engineInfo.networks
            ? root.engineInfo.networks : []
        readonly property var localCidrs: root.engineInfo && root.engineInfo.localCidrs
            ? root.engineInfo.localCidrs : []
        readonly property string firstCidr: d.networks.length > 0
            ? String(d.networks[0].cidr ?? "") : ""

        readonly property var targets: Validators.validateTargets(cidrField.text)
        readonly property string portText: root.customPorts ? customPortsField.text : ""
        readonly property var ports: Validators.validatePorts(d.portText)
        // 13-11 semantics: no known local networks means every target is
        // gated, so a failed or empty describe never opens the gate.
        readonly property bool requiresAuth: d.targets.ok
            && Validators.requiresAuthorisation(d.targets.cidrs, d.localCidrs)

        readonly property string targetError: d.targets.ok ? ""
            : d.targets.error === Validators.InvalidTarget
              || (d.targets.error === Validators.Empty && d.touched)
              ? qsTr("Enter a network like 192.168.1.0/24.") : ""
        readonly property string portsError: d.ports.ok ? ""
            : qsTr("Use numbers 1-65535, separated by commas, ranges like 8000-8100 allowed.")

        function networkLabel(net: var): string {
            const iface = String(net.interface ?? "")
            const cidr = String(net.cidr ?? "")
            return iface.length > 0 ? qsTr("%1 — %2").arg(iface).arg(cidr) : cidr
        }

        function prefill() {
            if (d.prefilled || d.touched || !root.engineInfo || !root.engineInfo.loaded)
                return
            if (d.firstCidr.length === 0)
                return
            d.prefilled = true
            cidrField.text = d.firstCidr
        }

        function requestStart() {
            if (!root.startEnabled)
                return
            root.startRequested(d.targets.cidrs, d.ports.ports ?? "", probeCheck.checked)
        }
    }

    Connections {
        target: root.engineInfo ?? null
        ignoreUnknownSignals: true
        function onChanged() { d.prefill() }
    }
    onEngineInfoChanged: d.prefill()
    Component.onCompleted: d.prefill()

    // Themed inputs. The Basic defaults ignore Theme, and accent is reserved
    // for focus rings and checked states.
    component ThemedField: TextField {
        id: field
        property bool mono: false
        implicitHeight: Theme.controlHeight
        font.family: field.mono ? Theme.monoFamily : Theme.sansFamily
        font.pixelSize: Theme.fontSizeBody
        color: Theme.ink
        placeholderTextColor: Theme.muted
        selectByMouse: true
        background: Rectangle {
            implicitHeight: Theme.controlHeight
            radius: Theme.radiusSm
            color: field.enabled ? Theme.surface : Theme.neutralFill
            border.width: field.activeFocus ? Theme.focusRingWidth : 1
            border.color: field.activeFocus ? Theme.accent : Theme.borderStrong
        }
    }

    component ThemedCheck: CheckBox {
        id: check
        font.family: Theme.sansFamily
        font.pixelSize: Theme.fontSizeBody
        spacing: Theme.spaceSm
        focusPolicy: Qt.StrongFocus
        Accessible.name: check.text

        indicator: Rectangle {
            x: check.leftPadding
            y: (check.height - height) / 2
            implicitWidth: 18
            implicitHeight: 18
            radius: Theme.radiusSm
            color: check.checked ? Theme.accent : Theme.surface
            border.width: check.visualFocus ? Theme.focusRingWidth : 1
            border.color: check.visualFocus || check.checked ? Theme.accent : Theme.borderStrong

            Text {
                anchors.centerIn: parent
                visible: check.checked
                // U+2713 check mark.
                text: "✓"
                textFormat: Text.PlainText
                color: Theme.textOnAccent
                font.family: Theme.sansFamily
                font.pixelSize: Theme.fontSizeLabel
                font.weight: Theme.weightSemiBold
            }
        }

        contentItem: PlainLabel {
            leftPadding: check.indicator.width + check.spacing
            text: check.text
            font: check.font
            color: check.enabled ? Theme.ink : Theme.subtle
            wrapMode: Text.Wrap
            elide: Text.ElideNone
            verticalAlignment: Text.AlignVCenter
        }
    }

    component ThemedCombo: ComboBox {
        id: combo
        implicitHeight: Theme.controlHeight
        font.family: Theme.sansFamily
        font.pixelSize: Theme.fontSizeBody
        focusPolicy: Qt.StrongFocus
        background: Rectangle {
            implicitHeight: Theme.controlHeight
            radius: Theme.radiusSm
            color: combo.enabled ? Theme.surface : Theme.neutralFill
            border.width: combo.visualFocus ? Theme.focusRingWidth : 1
            border.color: combo.visualFocus ? Theme.accent : Theme.borderStrong
        }
        contentItem: PlainLabel {
            leftPadding: Theme.spaceSm
            rightPadding: combo.indicator ? combo.indicator.width + Theme.spaceXs : Theme.spaceSm
            text: combo.displayText
            font: combo.font
            color: combo.currentIndex < 0 ? Theme.muted : Theme.ink
            verticalAlignment: Text.AlignVCenter
        }
    }

    Rectangle {
        anchors.fill: parent
        color: Theme.surfaceMuted
    }

    Rectangle {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        height: 1
        color: Theme.hairline
    }

    ColumnLayout {
        id: layout
        anchors.fill: parent
        anchors.margins: Theme.spaceMd
        spacing: Theme.spaceSm

        // Row 1: target, interface picker, Start/Stop.
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spaceMd

            LabeledField {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                label: qsTr("Target network (CIDR)")
                errorText: d.targetError

                ThemedField {
                    id: cidrField
                    objectName: "cidrField"
                    mono: true
                    enabled: !root.running
                    placeholderText: d.firstCidr
                    Accessible.name: qsTr("Target network (CIDR)")
                    onTextEdited: d.touched = true
                    // Any change to the scope invalidates the tick (D-11).
                    onTextChanged: authCheck.checked = false
                    onAccepted: d.requestStart()
                }
            }

            LabeledField {
                Layout.preferredWidth: 260
                Layout.alignment: Qt.AlignTop
                label: qsTr("Detected networks")

                ThemedCombo {
                    id: interfacePicker
                    objectName: "interfacePicker"
                    enabled: !root.running && d.networks.length > 0
                    model: d.networks.map(n => d.networkLabel(n))
                    currentIndex: -1
                    displayText: currentIndex < 0 ? qsTr("Choose an interface") : currentText
                    Accessible.name: qsTr("Detected networks")
                    onActivated: index => {
                        const net = d.networks[index]
                        if (!net)
                            return
                        d.touched = true
                        cidrField.text = String(net.cidr ?? "")
                    }
                }
            }

            // Start and Stop share one slot (UI-SPEC layout item 2).
            Item {
                objectName: "startStopSlot"
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: captionSpacer.implicitHeight + Theme.spaceXs
                implicitWidth: Math.max(startButton.implicitWidth, stopButton.implicitWidth)
                implicitHeight: Theme.controlHeight

                PrimaryButton {
                    id: startButton
                    objectName: "startButton"
                    anchors.fill: parent
                    visible: !root.running
                    enabled: root.startEnabled
                    text: qsTr("Start scan")
                    onClicked: d.requestStart()
                }

                SecondaryButton {
                    id: stopButton
                    objectName: "stopButton"
                    anchors.fill: parent
                    visible: root.running
                    enabled: root.running && !root.stopping
                    text: root.stopping ? qsTr("Stopping...") : qsTr("Stop scan")
                    onClicked: root.stopRequested()
                }
            }
        }

        // Row 2: ports preset, custom ports, fragile probes.
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spaceMd

            LabeledField {
                Layout.preferredWidth: 200
                Layout.alignment: Qt.AlignTop
                label: qsTr("Ports")

                ThemedCombo {
                    id: portsPicker
                    objectName: "portsPicker"
                    enabled: !root.running
                    model: [qsTr("Default ports"), qsTr("Custom...")]
                    currentIndex: 0
                    Accessible.name: qsTr("Ports")
                }
            }

            LabeledField {
                Layout.preferredWidth: 280
                Layout.alignment: Qt.AlignTop
                visible: root.customPorts
                // Keeps the caption row aligned with the other fields.
                label: " "
                errorText: d.portsError

                ThemedField {
                    id: customPortsField
                    objectName: "customPortsField"
                    mono: true
                    enabled: !root.running
                    Accessible.name: qsTr("Ports")
                    onAccepted: d.requestStart()
                }
            }

            RowLayout {
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: captionSpacer.implicitHeight + Theme.spaceXs
                spacing: Theme.spaceXs

                ThemedCheck {
                    id: probeCheck
                    objectName: "probeCheck"
                    enabled: !root.running
                    text: qsTr("Probe fragile devices")
                    Accessible.description: probeTip.text
                    implicitHeight: Theme.controlHeight

                    ToolTip {
                        id: probeTip
                        objectName: "probeTip"
                        visible: probeCheck.hovered || probeCheck.visualFocus
                        delay: 500
                        text: qsTr("Sends extra probes that some older printers, PLCs and embedded devices handle poorly. Leave off unless you know the network is safe to probe.")
                        contentItem: PlainLabel {
                            text: probeTip.text
                            font.pixelSize: Theme.fontSizeLabel
                            wrapMode: Text.Wrap
                            elide: Text.ElideNone
                        }
                        background: Rectangle {
                            color: Theme.surfaceMuted
                            border.width: 1
                            border.color: Theme.hairline
                            radius: Theme.radiusSm
                        }
                        width: Math.min(360, root.width - 2 * Theme.spaceMd)
                    }
                }

                ColorImage {
                    Layout.alignment: Qt.AlignVCenter
                    source: Theme.iconInfo
                    color: Theme.muted
                    sourceSize.width: 16
                    sourceSize.height: 16
                    Layout.preferredWidth: 16
                    Layout.preferredHeight: 16
                    Accessible.ignored: true

                    HoverHandler { id: infoHover }
                    ToolTip.visible: infoHover.hovered
                    ToolTip.delay: 500
                    ToolTip.text: probeTip.text
                }
            }

            Item { Layout.fillWidth: true }
        }

        // Authorisation gate (D-11). Warning-neutral ink, not error.
        ColumnLayout {
            id: authRow
            objectName: "authRow"
            Layout.fillWidth: true
            visible: root.needsAuthorisation
            spacing: Theme.spaceXs

            ThemedCheck {
                id: authCheck
                objectName: "authCheck"
                Layout.fillWidth: true
                enabled: !root.running
                text: qsTr("I am authorised to scan this network")
                Accessible.description: authHelper.text
            }

            PlainLabel {
                id: authHelper
                objectName: "authHelper"
                Layout.fillWidth: true
                leftPadding: 18 + Theme.spaceSm
                text: qsTr("This range is outside your local subnet. Scan only networks you own or have written permission to test.")
                color: Theme.muted
                font.pixelSize: Theme.fontSizeLabel
                wrapMode: Text.Wrap
                elide: Text.ElideNone
            }
        }
    }

    // Measures the caption height so buttons line up with the inputs.
    PlainLabel {
        id: captionSpacer
        visible: false
        text: " "
        font.pixelSize: Theme.fontSizeBody
        font.weight: Theme.weightSemiBold
    }
}
