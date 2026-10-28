// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Filled button for an action that discards work. Use only in a confirmation.
Button {
    id: control

    implicitWidth: Math.max(Theme.buttonMinWidth,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(Theme.controlHeight,
                             implicitContentHeight + topPadding + bottomPadding)
    leftPadding: Theme.spaceMd
    rightPadding: Theme.spaceMd
    topPadding: Theme.spaceSm
    bottomPadding: Theme.spaceSm

    focusPolicy: Qt.StrongFocus
    activeFocusOnTab: true
    Accessible.name: control.text

    font.family: Theme.sansFamily
    font.pixelSize: Theme.fontSizeBody
    font.weight: Theme.weightSemiBold

    contentItem: Text {
        text: control.text
        font: control.font
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        color: control.enabled ? Theme.textOnError : Theme.subtle
    }

    background: Rectangle {
        implicitWidth: Theme.buttonMinWidth
        implicitHeight: Theme.controlHeight
        radius: Theme.radiusSm
        color: control.enabled ? (control.down ? Qt.darker(Theme.errorEdge, 1.15) : Theme.errorEdge) : Theme.neutralFill
        border.width: 0
        border.color: control.enabled ? "transparent" : Theme.hairline

        Rectangle {
            // Focus ring: 2 px accent, 2 px outside the button.
            anchors.fill: parent
            anchors.margins: -2 * Theme.focusRingWidth
            radius: Theme.radiusSm + 2 * Theme.focusRingWidth
            color: "transparent"
            border.width: Theme.focusRingWidth
            border.color: Theme.accent
            visible: control.activeFocus
        }
    }
}
