// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// Chooser for the export format, shown before the platform file dialog.
// JSON is offered only when the engine wrote a payload; otherwise the
// option is disabled and the sheet says why. Partial results carry the
// Partial badge here too (UI-SPEC Export).
//
// Public surface fixed by plan 13-07. Additive (plan 13-16): format (the
// selected choice) and choose().
Popup {
    id: root

    property bool partial: false
    property bool jsonAvailable: false

    signal formatChosen(string format)

    // "json" or "csv".
    property string format: "csv"

    function choose() {
        const chosen = root.format === "json" && !root.jsonAvailable ? "csv" : root.format
        root.close()
        root.formatChosen(chosen)
    }

    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape
    anchors.centerIn: parent
    width: Math.min(440, parent ? parent.width - 2 * Theme.spaceLg : 440)
    padding: Theme.spaceLg

    onAboutToShow: root.format = root.jsonAvailable ? "json" : "csv"
    onOpened: chooseButton.forceActiveFocus(Qt.PopupFocusReason)

    background: Rectangle {
        color: Theme.surfaceMuted
        radius: Theme.radiusMd
        border.width: 1
        border.color: Theme.hairline
    }

    component Choice: RadioButton {
        id: choice
        font.family: Theme.sansFamily
        font.pixelSize: Theme.fontSizeBody
        spacing: Theme.spaceSm
        focusPolicy: Qt.StrongFocus
        Accessible.name: choice.text

        indicator: Rectangle {
            x: choice.leftPadding
            y: (choice.height - height) / 2
            implicitWidth: 18
            implicitHeight: 18
            radius: 9
            color: Theme.surface
            border.width: choice.visualFocus ? Theme.focusRingWidth : 1
            border.color: choice.visualFocus || choice.checked ? Theme.accent : Theme.borderStrong

            Rectangle {
                anchors.centerIn: parent
                width: 8
                height: 8
                radius: 4
                visible: choice.checked
                color: choice.enabled ? Theme.accent : Theme.subtle
            }
        }

        contentItem: PlainLabel {
            leftPadding: choice.indicator.width + choice.spacing
            text: choice.text
            font: choice.font
            color: choice.enabled ? Theme.ink : Theme.subtle
            wrapMode: Text.Wrap
            elide: Text.ElideNone
            verticalAlignment: Text.AlignVCenter
        }
    }

    contentItem: FocusScope {
        implicitWidth: content.implicitWidth
        implicitHeight: content.implicitHeight
        Keys.onReturnPressed: root.choose()
        Keys.onEnterPressed: root.choose()

        ColumnLayout {
            id: content
            width: parent.width
            spacing: Theme.spaceMd

            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceSm

                PlainLabel {
                    objectName: "exportTitle"
                    Layout.fillWidth: true
                    text: qsTr("Export results")
                    font.pixelSize: Theme.fontSizeHeading
                    font.weight: Theme.weightSemiBold
                    wrapMode: Text.Wrap
                    elide: Text.ElideNone
                    Accessible.role: Accessible.Heading
                }

                StatusBadge {
                    objectName: "partialBadge"
                    visible: root.partial
                    kind: "partial"
                    text: qsTr("Partial")
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceXs

                Choice {
                    objectName: "jsonChoice"
                    Layout.fillWidth: true
                    text: qsTr("JSON payload")
                    enabled: root.jsonAvailable
                    checked: root.format === "json"
                    onClicked: root.format = "json"
                }

                PlainLabel {
                    objectName: "jsonUnavailable"
                    Layout.fillWidth: true
                    visible: !root.jsonAvailable
                    leftPadding: 18 + Theme.spaceSm
                    text: qsTr("The JSON payload is not available because the scan did not finish writing it. Export the CSV table instead.")
                    color: Theme.muted
                    font.pixelSize: Theme.fontSizeLabel
                    wrapMode: Text.Wrap
                    elide: Text.ElideNone
                }

                Choice {
                    objectName: "csvChoice"
                    Layout.fillWidth: true
                    text: qsTr("CSV table")
                    checked: root.format === "csv"
                    onClicked: root.format = "csv"
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceSm

                Item { Layout.fillWidth: true }

                SecondaryButton {
                    objectName: "cancelButton"
                    text: qsTr("Cancel")
                    onClicked: root.close()
                }

                PrimaryButton {
                    id: chooseButton
                    objectName: "chooseButton"
                    text: qsTr("Choose location...")
                    onClicked: root.choose()
                }
            }
        }
    }
}
