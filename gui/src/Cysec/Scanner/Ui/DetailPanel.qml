// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// Details of the selected host with copy buttons. Callers append extra
// sections through the default slot.
//
// host: {ip, hostname, mac, vendor, osGuess, services: [{port, protocol,
// serviceName, product, version}]} (HostModel host map). Facts only (D-14):
// neutral colours, no risk styling or ordering. Values are read-only plain
// text edits so they can be selected, and markup is shown verbatim.
Item {
    id: root

    property var host

    default property alias sections: extraSections.data

    readonly property bool hasHost: !!host && ((host.ip ?? "").length > 0
                                               || (host.externalId ?? "").length > 0)
    readonly property var services: hasHost && host.services ? host.services : []

    implicitWidth: 320
    implicitHeight: 360

    // Puts text on the system clipboard through a hidden plain-text edit.
    function copyText(value: string) {
        clipboardHelper.text = value
        clipboardHelper.selectAll()
        clipboardHelper.copy()
        clipboardHelper.text = ""
    }

    TextEdit {
        id: clipboardHelper
        visible: false
        textFormat: TextEdit.PlainText
    }

    Menu {
        id: contextMenu
        property string value

        MenuItem {
            text: qsTr("Copy")
            onTriggered: root.copyText(contextMenu.value)
        }
    }

    // A read-only, selectable plain-text value with copy affordances.
    component FactValue: TextEdit {
        id: fact
        property bool mono: false
        property bool unknown: false

        readOnly: true
        selectByMouse: true
        selectByKeyboard: true
        activeFocusOnPress: true
        textFormat: TextEdit.PlainText
        wrapMode: TextEdit.Wrap
        color: unknown ? Theme.muted : Theme.ink
        selectionColor: Theme.accentTint
        selectedTextColor: Theme.ink
        font.family: mono && !unknown ? Theme.monoFamily : Theme.sansFamily
        font.pixelSize: Theme.fontSizeBody

        TapHandler {
            acceptedButtons: Qt.RightButton
            enabled: !fact.unknown
            onTapped: {
                contextMenu.value = fact.text
                contextMenu.popup()
            }
        }
    }

    component CopyButton: ToolButton {
        id: copyButton
        property string value
        property string fieldLabel

        visible: value.length > 0
        implicitHeight: 28
        focusPolicy: Qt.StrongFocus
        text: qsTr("Copy")
        Accessible.name: qsTr("Copy %1").arg(fieldLabel)
        onClicked: root.copyText(value)

        contentItem: Text {
            text: copyButton.text
            textFormat: Text.PlainText
            font.family: Theme.sansFamily
            font.pixelSize: Theme.fontSizeLabel
            font.weight: Theme.weightSemiBold
            color: Theme.muted
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: Theme.radiusSm
            color: copyButton.down ? Theme.neutralFill : "transparent"
            border.width: copyButton.activeFocus ? Theme.focusRingWidth : 1
            border.color: copyButton.activeFocus ? Theme.accent : Theme.hairline
        }
    }

    component FactRow: ColumnLayout {
        id: factRow
        property string label
        property string value
        property bool mono: false

        Layout.fillWidth: true
        spacing: 2

        PlainLabel {
            Layout.fillWidth: true
            text: factRow.label
            color: Theme.muted
            font.pixelSize: Theme.fontSizeLabel
            font.weight: Theme.weightSemiBold
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spaceSm

            FactValue {
                Layout.fillWidth: true
                objectName: "fact_" + factRow.label
                text: factRow.value.length > 0 ? factRow.value : qsTr("Unknown")
                unknown: factRow.value.length === 0
                mono: factRow.mono
                Accessible.name: factRow.label
            }

            CopyButton {
                value: factRow.value
                fieldLabel: factRow.label
            }
        }
    }

    Rectangle {
        anchors.fill: parent
        color: Theme.surfaceMuted
    }

    PlainLabel {
        objectName: "detailEmpty"
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.spaceLg
        horizontalAlignment: Text.AlignHCenter
        visible: !root.hasHost
        text: qsTr("Select a host to see its details.")
        color: Theme.muted
        wrapMode: Text.Wrap
        elide: Text.ElideNone
    }

    Flickable {
        id: flick
        anchors.fill: parent
        visible: root.hasHost
        clip: true
        contentWidth: width
        contentHeight: content.implicitHeight + 2 * Theme.spaceMd
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.vertical: ScrollBar {}

        ColumnLayout {
            id: content
            x: Theme.spaceMd
            y: Theme.spaceMd
            width: flick.width - 2 * Theme.spaceMd
            spacing: Theme.spaceLg

            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceSm

                FactValue {
                    objectName: "detailHeading"
                    Layout.fillWidth: true
                    text: root.hasHost ? (root.host.ip || root.host.externalId || "") : ""
                    mono: true
                    font.pixelSize: Theme.fontSizeHeading
                    font.weight: Theme.weightSemiBold
                    Accessible.role: Accessible.Heading
                    Accessible.name: text
                }

                CopyButton {
                    value: root.hasHost ? (root.host.ip ?? "") : ""
                    fieldLabel: qsTr("IP address")
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceSm

                PlainLabel {
                    Layout.fillWidth: true
                    text: qsTr("Host")
                    font.pixelSize: Theme.fontSizeBody
                    font.weight: Theme.weightSemiBold
                    Accessible.role: Accessible.Heading
                }

                FactRow {
                    label: qsTr("Hostname")
                    value: root.hasHost ? (root.host.hostname ?? "") : ""
                }
                FactRow {
                    label: qsTr("MAC address")
                    value: root.hasHost ? (root.host.mac ?? "") : ""
                    mono: true
                }
                FactRow {
                    label: qsTr("MAC vendor")
                    value: root.hasHost ? (root.host.vendor ?? "") : ""
                }
                FactRow {
                    label: qsTr("OS guess")
                    value: root.hasHost ? (root.host.osGuess ?? "") : ""
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceSm

                PlainLabel {
                    Layout.fillWidth: true
                    text: qsTr("Open ports and services")
                    font.pixelSize: Theme.fontSizeBody
                    font.weight: Theme.weightSemiBold
                    wrapMode: Text.Wrap
                    elide: Text.ElideNone
                    Accessible.role: Accessible.Heading
                }

                PlainLabel {
                    objectName: "noPorts"
                    Layout.fillWidth: true
                    visible: root.services.length === 0
                    text: qsTr("No open ports found among the scanned ports.")
                    color: Theme.muted
                    wrapMode: Text.Wrap
                    elide: Text.ElideNone
                }

                Repeater {
                    model: root.services

                    delegate: RowLayout {
                        id: serviceRow
                        required property int index
                        required property var modelData

                        readonly property string portText: String(modelData.port ?? "")
                            + "/" + (modelData.protocol ?? "")
                        readonly property string detailText: [modelData.product ?? "",
                                                              modelData.version ?? ""]
                            .filter(s => s.length > 0).join(" ")

                        Layout.fillWidth: true
                        spacing: Theme.spaceSm

                        FactValue {
                            objectName: "servicePort" + serviceRow.index
                            Layout.preferredWidth: 88
                            text: serviceRow.portText
                            mono: true
                            Accessible.name: text
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0

                            FactValue {
                                objectName: "serviceName" + serviceRow.index
                                Layout.fillWidth: true
                                text: (serviceRow.modelData.serviceName ?? "").length > 0
                                      ? serviceRow.modelData.serviceName : qsTr("Unknown")
                                unknown: (serviceRow.modelData.serviceName ?? "").length === 0
                                Accessible.name: text
                            }

                            FactValue {
                                objectName: "serviceDetail" + serviceRow.index
                                Layout.fillWidth: true
                                visible: serviceRow.detailText.length > 0
                                text: serviceRow.detailText
                                color: Theme.muted
                                font.pixelSize: Theme.fontSizeLabel
                                Accessible.name: text
                            }
                        }

                        CopyButton {
                            value: [serviceRow.portText, serviceRow.modelData.serviceName ?? "",
                                    serviceRow.detailText].filter(s => s.length > 0).join(" ")
                            fieldLabel: serviceRow.portText
                        }
                    }
                }
            }

            ColumnLayout {
                id: extraSections
                Layout.fillWidth: true
                spacing: Theme.spaceLg
            }
        }
    }
}
