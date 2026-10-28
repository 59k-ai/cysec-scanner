// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Controls.impl
import QtQuick.Layouts

// Collapsible scan log with warning and error counts in its header.
// model roles: time (date), level ("info" | "warn" | "error"), text.
// The counts stay visible while collapsed. Each line carries a level icon
// and a level word, never colour alone, and the message is plain text.
// There is deliberately no control that empties the view: the log is the record.
Item {
    id: root

    property var model
    property int warningCount: 0
    property int errorCount: 0
    property bool expanded: false

    // Height of the line list when expanded.
    property int expandedHeight: 160

    readonly property int headerHeight: Theme.controlHeight + Theme.spaceXs

    implicitWidth: 640
    implicitHeight: headerHeight + (expanded ? expandedHeight : 0)

    Behavior on implicitHeight {
        NumberAnimation { duration: Theme.durationFast }
    }

    QtObject {
        id: d
        property int lastErrorCount: 0
        property bool follow: true
        property bool autoScrolling: false

        function scrollToEnd() {
            d.autoScrolling = true
            list.forceLayout()
            list.positionViewAtEnd()
            d.autoScrolling = false
        }
    }

    onErrorCountChanged: {
        if (root.errorCount > d.lastErrorCount && !Theme.reducedMotion)
            errorPulse.restart()
        d.lastErrorCount = root.errorCount
    }

    onExpandedChanged: if (root.expanded && d.follow) Qt.callLater(d.scrollToEnd)

    Rectangle {
        anchors.fill: parent
        color: Theme.surfaceMuted
    }

    Rectangle {
        width: parent.width
        height: 1
        color: Theme.hairline
    }

    Item {
        id: header
        width: parent.width
        height: root.headerHeight

        TapHandler {
            onTapped: root.expanded = !root.expanded
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.spaceSm
            anchors.rightMargin: Theme.spaceMd
            spacing: Theme.spaceSm

            ToolButton {
                id: toggle
                objectName: "logToggle"
                implicitWidth: 32
                implicitHeight: 32
                focusPolicy: Qt.StrongFocus
                Accessible.name: root.expanded ? qsTr("Hide log") : qsTr("Show log")
                onClicked: root.expanded = !root.expanded

                contentItem: Item {
                    ColorImage {
                        anchors.centerIn: parent
                        source: Theme.iconChevron
                        color: Theme.ink
                        width: 16
                        height: 16
                        sourceSize.width: 16
                        sourceSize.height: 16
                        // Points right when collapsed, up when expanded.
                        rotation: root.expanded ? -90 : 0
                        Accessible.ignored: true
                    }
                }
                background: Rectangle {
                    radius: Theme.radiusSm
                    color: toggle.down ? Theme.neutralFill : "transparent"
                    border.width: toggle.activeFocus ? Theme.focusRingWidth : 0
                    border.color: Theme.accent
                }
            }

            PlainLabel {
                text: qsTr("Log")
                font.weight: Theme.weightSemiBold
                elide: Text.ElideNone
            }

            StatusBadge {
                objectName: "warningBadge"
                kind: "warning"
                visible: root.warningCount > 0
                text: qsTr("%n warning(s)", "", root.warningCount)
            }

            StatusBadge {
                id: errorBadge
                objectName: "errorBadge"
                kind: "error"
                visible: root.errorCount > 0
                text: qsTr("%n error(s)", "", root.errorCount)

                SequentialAnimation {
                    id: errorPulse
                    objectName: "errorPulse"
                    NumberAnimation {
                        target: errorBadge
                        property: "scale"
                        to: 1.15
                        duration: 150
                    }
                    NumberAnimation {
                        target: errorBadge
                        property: "scale"
                        to: 1.0
                        duration: 150
                    }
                }
            }

            Item { Layout.fillWidth: true }
        }
    }

    ListView {
        id: list
        objectName: "logList"
        anchors.top: header.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: Theme.spaceMd
        anchors.rightMargin: Theme.spaceMd
        visible: root.expanded
        clip: true
        model: root.model
        boundsBehavior: Flickable.StopAtBounds
        activeFocusOnTab: root.expanded
        reuseItems: true
        currentIndex: -1
        ScrollBar.vertical: ScrollBar {}

        Accessible.role: Accessible.List
        Accessible.name: qsTr("Log")

        // Follow the newest line unless the user scrolled away from the end.
        onContentYChanged: if (!d.autoScrolling && (moving || dragging || flicking))
                               d.follow = atYEnd
        onMovementEnded: d.follow = atYEnd
        onCountChanged: if (d.follow && root.expanded) Qt.callLater(d.scrollToEnd)
        // The list grows while the panel expands; re-anchor at the newest
        // line so the viewport never ends past the content.
        onHeightChanged: if (d.follow && root.expanded) d.scrollToEnd()

        delegate: RowLayout {
            id: line
            required property int index
            required property var time
            required property string level
            required property string text

            readonly property bool isWarn: level === "warn"
            readonly property bool isError: level === "error"

            width: ListView.view.width
            spacing: Theme.spaceSm

            Accessible.role: Accessible.ListItem
            Accessible.name: levelText.text + " " + message.text

            PlainLabel {
                objectName: "logTime" + line.index
                Layout.alignment: Qt.AlignTop
                mono: true
                font.pixelSize: Theme.fontSizeLabel
                color: Theme.muted
                elide: Text.ElideNone
                text: Formatter.logTime(line.time, LanguageController.revision)
                Accessible.ignored: true
            }

            ColorImage {
                objectName: "logIcon" + line.index
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 2
                source: line.isError ? Theme.iconError : line.isWarn ? Theme.iconWarning
                                                                    : Theme.iconInfo
                color: line.isError ? Theme.errorText : line.isWarn ? Theme.warningText
                                                                   : Theme.infoText
                Layout.preferredWidth: 12
                Layout.preferredHeight: 12
                sourceSize.width: 12
                sourceSize.height: 12
                Accessible.ignored: true
            }

            PlainLabel {
                id: levelText
                objectName: "logLevel" + line.index
                Layout.alignment: Qt.AlignTop
                Layout.minimumWidth: 56
                font.pixelSize: Theme.fontSizeLabel
                font.weight: Theme.weightSemiBold
                elide: Text.ElideNone
                color: line.isError ? Theme.errorText : line.isWarn ? Theme.warningText
                                                                   : Theme.infoText
                text: line.isError ? qsTr("Error") : line.isWarn ? qsTr("Warning") : qsTr("Info")
                Accessible.ignored: true
            }

            PlainLabel {
                id: message
                objectName: "logText" + line.index
                Layout.fillWidth: true
                mono: true
                font.pixelSize: Theme.fontSizeLabel
                wrapMode: Text.Wrap
                elide: Text.ElideNone
                text: line.text
                Accessible.ignored: true
            }
        }
    }

    PlainLabel {
        objectName: "logEmpty"
        anchors.centerIn: list
        visible: root.expanded && list.count === 0
        text: qsTr("No warnings or errors.")
        color: Theme.muted
    }
}
