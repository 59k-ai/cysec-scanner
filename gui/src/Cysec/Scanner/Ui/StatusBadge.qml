// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.impl

// Small status chip for operational state. Always icon plus text, never
// colour alone. Kinds: "partial" and "warning" (warning colours), "error",
// "running" and "info" (info colours).
Rectangle {
    id: badge

    property string kind: "info"
    property string text: ""

    readonly property bool isWarning: kind === "partial" || kind === "warning"
    readonly property bool isError: kind === "error"

    readonly property color fillColor: isWarning ? Theme.warningFill
                                     : isError ? Theme.errorFill : Theme.infoFill
    readonly property color textColor: isWarning ? Theme.warningText
                                     : isError ? Theme.errorText : Theme.infoText
    readonly property color edgeColor: isWarning ? Theme.warningEdge
                                     : isError ? Theme.errorEdge : Theme.infoEdge
    readonly property url iconSource: isWarning ? Theme.iconWarning
                                    : isError ? Theme.iconError : Theme.iconInfo

    implicitWidth: content.implicitWidth + 2 * Theme.spaceSm
    implicitHeight: Math.max(Theme.fontSizeLabel + 2 * Theme.spaceXs + 4,
                             content.implicitHeight + 2 * Theme.spaceXs)
    radius: Theme.radiusSm
    color: fillColor
    border.width: 1
    border.color: edgeColor

    Accessible.role: Accessible.StaticText
    Accessible.name: badge.text

    Row {
        id: content
        anchors.centerIn: parent
        spacing: Theme.spaceXs

        ColorImage {
            objectName: "statusBadgeIcon"
            anchors.verticalCenter: parent.verticalCenter
            source: badge.iconSource
            color: badge.textColor
            sourceSize.width: Theme.fontSizeLabel
            sourceSize.height: Theme.fontSizeLabel
            width: Theme.fontSizeLabel
            height: Theme.fontSizeLabel
            Accessible.ignored: true
        }

        PlainLabel {
            objectName: "statusBadgeText"
            anchors.verticalCenter: parent.verticalCenter
            text: badge.text
            color: badge.textColor
            font.pixelSize: Theme.fontSizeLabel
            font.weight: Theme.weightSemiBold
            Accessible.ignored: true
        }
    }
}
