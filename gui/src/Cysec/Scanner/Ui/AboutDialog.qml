// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// Version rows and third-party notices (D-23, as amended by D-24: the
// vendor line names the company only).
//
// noticesText is set by the caller. loadNotices() fills it from the module
// resource with XMLHttpRequest, which keeps this dialog free of C++ file
// access. Qt treats qrc: like a local file, so XMLHttpRequest reads it only
// when the process sets QML_XHR_ALLOW_FILE_READ=1 before the engine starts;
// otherwise loadNotices() returns false, leaves noticesText unchanged and
// the caller must supply the text another way.
Dialog {
    id: root

    property string guiVersion
    property string engineVersion
    property string qtVersion
    property string noticesText

    // Resource alias set up by the module CMakeLists (plan 13-07).
    readonly property url noticesUrl: "qrc:/qt/qml/Cysec/Scanner/Ui/THIRD_PARTY_NOTICES.md"
    property bool noticesShown: false

    // Returns true when the request was started.
    function loadNotices(): bool {
        const xhr = new XMLHttpRequest()
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE && xhr.responseText.length > 0)
                root.noticesText = xhr.responseText
        }
        try {
            xhr.open("GET", root.noticesUrl)
            xhr.send()
        } catch (e) {
            return false
        }
        return true
    }

    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape
    anchors.centerIn: parent
    width: 480
    padding: Theme.spaceLg
    topPadding: Theme.spaceSm
    title: qsTr("About Cysec Scanner")

    onOpened: closeButton.forceActiveFocus(Qt.PopupFocusReason)
    onClosed: root.noticesShown = false

    background: Rectangle {
        color: Theme.surfaceMuted
        radius: Theme.radiusMd
        border.width: 1
        border.color: Theme.hairline
    }

    header: PlainLabel {
        objectName: "aboutTitle"
        text: root.title
        leftPadding: Theme.spaceLg
        rightPadding: Theme.spaceLg
        topPadding: Theme.spaceLg
        font.pixelSize: Theme.fontSizeHeading
        font.weight: Theme.weightSemiBold
        wrapMode: Text.Wrap
        elide: Text.ElideNone
        Accessible.role: Accessible.Heading
    }

    component SectionTitle: PlainLabel {
        Layout.fillWidth: true
        font.weight: Theme.weightSemiBold
        wrapMode: Text.Wrap
        elide: Text.ElideNone
        Accessible.role: Accessible.Heading
    }

    component BodyLine: PlainLabel {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        elide: Text.ElideNone
    }

    contentItem: FocusScope {
        implicitWidth: content.implicitWidth
        implicitHeight: content.implicitHeight
        Keys.onReturnPressed: root.close()
        Keys.onEnterPressed: root.close()

        ColumnLayout {
            id: content
            width: parent.width
            spacing: Theme.spaceMd

            GridLayout {
                Layout.fillWidth: true
                columns: 2
                columnSpacing: Theme.spaceMd
                rowSpacing: Theme.spaceXs

                PlainLabel {
                    text: qsTr("Version")
                    color: Theme.muted
                    elide: Text.ElideNone
                }
                PlainLabel {
                    objectName: "guiVersionValue"
                    Layout.fillWidth: true
                    mono: root.guiVersion.length > 0
                    text: root.guiVersion.length > 0 ? root.guiVersion : qsTr("Unknown")
                    color: root.guiVersion.length > 0 ? Theme.ink : Theme.muted
                }

                PlainLabel {
                    text: qsTr("Scan engine")
                    color: Theme.muted
                    elide: Text.ElideNone
                }
                PlainLabel {
                    objectName: "engineVersionValue"
                    Layout.fillWidth: true
                    mono: root.engineVersion.length > 0
                    text: root.engineVersion.length > 0 ? root.engineVersion : qsTr("Unknown")
                    color: root.engineVersion.length > 0 ? Theme.ink : Theme.muted
                }

                PlainLabel {
                    text: qsTr("Qt")
                    color: Theme.muted
                    elide: Text.ElideNone
                }
                PlainLabel {
                    objectName: "qtVersionValue"
                    Layout.fillWidth: true
                    mono: root.qtVersion.length > 0
                    text: root.qtVersion.length > 0 ? root.qtVersion : qsTr("Unknown")
                    color: root.qtVersion.length > 0 ? Theme.ink : Theme.muted
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceXs

                SectionTitle { text: qsTr("Licences") }
                BodyLine { text: qsTr("Cysec Scanner: Apache-2.0") }
                BodyLine { text: qsTr("Qt: LGPLv3 (dynamically linked)") }
                BodyLine { text: qsTr("IEEE OUI data: MAC vendor names derived from the IEEE registry") }
                BodyLine { text: qsTr("IBM Plex fonts: SIL Open Font License 1.1") }
                BodyLine {
                    objectName: "copyrightLine"
                    Layout.topMargin: Theme.spaceSm
                    color: Theme.muted
                    text: qsTr("© 2026 59k GmbH")
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceXs

                SectionTitle { text: qsTr("Third-party notices") }

                // Text link (accent is reserved for About dialog links).
                AbstractButton {
                    id: noticesLink
                    objectName: "noticesButton"
                    Layout.fillWidth: true
                    implicitHeight: Math.max(32, linkText.implicitHeight)
                    focusPolicy: Qt.StrongFocus
                    text: qsTr("View third-party notices")
                    Accessible.role: Accessible.Link
                    Accessible.name: noticesLink.text
                    onClicked: root.noticesShown = !root.noticesShown

                    contentItem: PlainLabel {
                        id: linkText
                        text: noticesLink.text
                        color: Theme.accent
                        font.underline: true
                        verticalAlignment: Text.AlignVCenter
                        wrapMode: Text.Wrap
                        elide: Text.ElideNone
                    }
                    background: Rectangle {
                        color: "transparent"
                        radius: Theme.radiusSm
                        border.width: noticesLink.activeFocus ? Theme.focusRingWidth : 0
                        border.color: Theme.accent
                    }
                }

                ScrollView {
                    objectName: "noticesScroll"
                    Layout.fillWidth: true
                    Layout.preferredHeight: 240
                    visible: root.noticesShown
                    clip: true

                    TextArea {
                        objectName: "noticesView"
                        readOnly: true
                        selectByMouse: true
                        textFormat: TextEdit.PlainText
                        wrapMode: TextEdit.Wrap
                        text: root.noticesText
                        color: Theme.ink
                        font.family: Theme.monoFamily
                        font.pixelSize: Theme.fontSizeLabel
                        Accessible.name: qsTr("Third-party notices")
                        background: Rectangle {
                            color: Theme.surface
                            border.width: 1
                            border.color: Theme.hairline
                            radius: Theme.radiusSm
                        }
                    }
                }
            }
        }
    }

    footer: Item {
        implicitHeight: closeButton.implicitHeight + 2 * Theme.spaceLg
        Keys.onReturnPressed: root.close()
        Keys.onEnterPressed: root.close()

        SecondaryButton {
            id: closeButton
            objectName: "closeButton"
            anchors.right: parent.right
            anchors.rightMargin: Theme.spaceLg
            anchors.verticalCenter: parent.verticalCenter
            text: qsTr("Close")
            onClicked: root.close()
        }
    }
}
