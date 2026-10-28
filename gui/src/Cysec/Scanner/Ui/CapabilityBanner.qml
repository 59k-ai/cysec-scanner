// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Controls.impl
import QtQuick.Layouts

// Inline notice about a missing host capability (for example no
// unprivileged ICMP). Warning colours, a 4 px left edge, a warning icon and
// the caller's text. The caller hides it on dismissed() for the session;
// it offers no "run elevated" action by design (D-21).
Item {
    id: root

    property string text
    property bool dismissible: true

    signal dismissed()

    implicitWidth: 400
    implicitHeight: Math.max(Theme.controlHeight, row.implicitHeight) + 2 * Theme.spaceSm

    Accessible.role: Accessible.AlertMessage
    Accessible.name: root.text

    Rectangle {
        anchors.fill: parent
        color: Theme.warningFill
    }

    Rectangle {
        width: 4
        height: parent.height
        color: Theme.warningEdge
    }

    RowLayout {
        id: row
        anchors.fill: parent
        anchors.leftMargin: 4 + Theme.spaceMd
        anchors.rightMargin: Theme.spaceSm
        anchors.topMargin: Theme.spaceSm
        anchors.bottomMargin: Theme.spaceSm
        spacing: Theme.spaceSm

        ColorImage {
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 2
            source: Theme.iconWarning
            color: Theme.warningText
            sourceSize.width: 16
            sourceSize.height: 16
            Layout.preferredWidth: 16
            Layout.preferredHeight: 16
            Accessible.ignored: true
        }

        PlainLabel {
            objectName: "bannerText"
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            text: root.text
            color: Theme.warningText
            wrapMode: Text.Wrap
            elide: Text.ElideNone
            Accessible.ignored: true
        }

        ToolButton {
            id: dismiss
            objectName: "dismissButton"
            Layout.alignment: Qt.AlignTop
            visible: root.dismissible
            implicitWidth: 32
            implicitHeight: 32
            focusPolicy: Qt.StrongFocus
            Accessible.name: qsTr("Dismiss")
            onClicked: root.dismissed()

            contentItem: Text {
                // U+00D7 multiplication sign as the close glyph.
                text: "×"
                textFormat: Text.PlainText
                font.family: Theme.sansFamily
                font.pixelSize: Theme.fontSizeHeading
                color: Theme.warningText
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
            }

            background: Rectangle {
                radius: Theme.radiusSm
                color: dismiss.down ? Theme.neutralFill : "transparent"
                border.width: dismiss.activeFocus ? Theme.focusRingWidth : 0
                border.color: Theme.accent
            }
        }
    }
}
