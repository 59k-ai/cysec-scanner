// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// Display-only scan progress: stage stepper, counters, elapsed time and a
// status line. Callers append extra rows through the default slot.
// The bar shows progress within the current stage only (D-03); there is no
// time estimate anywhere (D-07), only elapsed time.
Item {
    id: root

    property var stages: []
    property int currentStage: -1
    property int stageDone: 0
    property int stageTotal: 0
    property int elapsedSeconds: 0
    // ScanSession.State. Named scanState because Item already owns a string
    // "state" property (the States machinery); shadowing it is a lint error.
    // Values: Idle 0, Running 1, Stopping 2, Completed 3, Partial 4, Failed 5.
    property int scanState: 0
    property string title
    // When set it replaces the generated "Stage N of 3" line.
    property string statusText
    property int hostsFound: 0

    default property alias extraContent: extra.data

    readonly property var effectiveStages: stages && stages.length > 0
        ? stages : [qsTr("Discovery"), qsTr("Ports"), qsTr("Fingerprint")]
    readonly property bool active: scanState === 1 || scanState === 2
    readonly property bool completed: scanState === 3
    readonly property real ratio: completed ? 1
        : stageTotal > 0 ? Math.max(0, Math.min(1, stageDone / stageTotal)) : 0
    // Before the first total arrives the bar slides instead of showing 0.
    readonly property bool indeterminate: active && stageTotal <= 0
    readonly property int revision: LanguageController.revision

    implicitWidth: 400
    implicitHeight: layout.implicitHeight + 2 * Theme.spaceMd

    ColumnLayout {
        id: layout
        anchors.fill: parent
        anchors.margins: Theme.spaceMd
        spacing: Theme.spaceSm

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spaceSm

            PlainLabel {
                objectName: "titleText"
                text: root.title
                visible: text.length > 0
                font.pixelSize: Theme.fontSizeHeading
                font.weight: Theme.weightSemiBold
            }

            StatusBadge {
                objectName: "stateBadge"
                visible: root.scanState === 1 || root.scanState === 2
                         || root.scanState === 4 || root.scanState === 5
                kind: root.scanState === 4 ? "partial"
                    : root.scanState === 5 ? "error" : "running"
                text: root.scanState === 1 ? qsTr("Running")
                    : root.scanState === 2 ? qsTr("Stopping...")
                    : root.scanState === 4 ? qsTr("Partial")
                    : root.scanState === 5 ? qsTr("Failed") : ""
            }

            Item { Layout.fillWidth: true }

            PlainLabel {
                objectName: "hostsText"
                text: qsTr("%n host(s) found", "", root.hostsFound)
                color: Theme.muted
                elide: Text.ElideNone
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spaceLg

            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceSm

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spaceXs

                    Repeater {
                        model: root.effectiveStages

                        delegate: ColumnLayout {
                            id: stageItem
                            required property int index
                            required property string modelData

                            readonly property bool done: root.completed || index < root.currentStage
                            readonly property bool current: index === root.currentStage
                                                            && !root.completed

                            Layout.fillWidth: true
                            Layout.preferredWidth: 1
                            spacing: Theme.spaceXs

                            Rectangle {
                                objectName: "stageSegment" + stageItem.index
                                Layout.fillWidth: true
                                implicitHeight: Theme.barHeight
                                radius: Theme.radiusSm
                                color: stageItem.done || (stageItem.current && root.scanState !== 0)
                                       ? Theme.accent : Theme.neutralFill
                            }

                            PlainLabel {
                                objectName: "stageName" + stageItem.index
                                Layout.fillWidth: true
                                text: stageItem.modelData
                                font.pixelSize: Theme.fontSizeLabel
                                font.weight: stageItem.current ? Theme.weightSemiBold
                                                               : Theme.weightRegular
                                color: stageItem.current ? Theme.ink : Theme.muted
                            }
                        }
                    }
                }

                Rectangle {
                    id: track
                    objectName: "stageTrack"
                    Layout.fillWidth: true
                    implicitHeight: Theme.barHeight
                    radius: Theme.radiusSm
                    color: Theme.neutralFill
                    clip: true

                    Accessible.role: Accessible.ProgressBar
                    Accessible.name: qsTr("Stage progress")
                    Accessible.description: percentText.text

                    Rectangle {
                        objectName: "stageFill"
                        visible: !root.indeterminate
                        height: parent.height
                        radius: Theme.radiusSm
                        color: Theme.accent
                        width: track.width * root.ratio

                        Behavior on width {
                            NumberAnimation { duration: Theme.durationBar }
                        }
                    }

                    Rectangle {
                        id: slider
                        objectName: "indeterminateSegment"
                        visible: root.indeterminate
                        width: track.width * 0.3
                        height: parent.height
                        radius: Theme.radiusSm
                        color: Theme.accent
                        x: 0

                        // 2 s sliding segment; static under reduced motion.
                        NumberAnimation {
                            objectName: "indeterminateAnimation"
                            target: slider
                            property: "x"
                            from: -slider.width
                            to: track.width
                            duration: 2000
                            loops: Animation.Infinite
                            running: slider.visible && !Theme.reducedMotion
                            onRunningChanged: if (!running) slider.x = 0
                        }
                    }
                }

                PlainLabel {
                    objectName: "statusText"
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    elide: Text.ElideNone
                    color: Theme.muted
                    visible: text.length > 0
                    text: root.statusText.length > 0 ? root.statusText
                        : root.currentStage >= 0 && root.currentStage < root.effectiveStages.length
                          ? qsTr("Stage %1 of 3: %2 (%3 of %4 done)")
                                .arg(root.currentStage + 1)
                                .arg(root.effectiveStages[root.currentStage])
                                .arg(Formatter.count(root.stageDone, root.revision))
                                .arg(Formatter.count(root.stageTotal, root.revision))
                          : ""
                }
            }

            ColumnLayout {
                Layout.alignment: Qt.AlignTop
                spacing: Theme.spaceXs

                PlainLabel {
                    id: percentText
                    objectName: "percentText"
                    Layout.alignment: Qt.AlignRight
                    mono: true
                    elide: Text.ElideNone
                    font.pixelSize: Theme.fontSizeDisplay
                    font.weight: Theme.weightSemiBold
                    text: Formatter.percent(root.ratio, root.revision)
                }

                PlainLabel {
                    objectName: "elapsedText"
                    Layout.alignment: Qt.AlignRight
                    mono: true
                    elide: Text.ElideNone
                    font.pixelSize: Theme.fontSizeDisplay
                    font.weight: Theme.weightSemiBold
                    color: Theme.muted
                    text: qsTr("Elapsed %1").arg(Formatter.elapsed(root.elapsedSeconds))
                }
            }
        }

        ColumnLayout {
            id: extra
            Layout.fillWidth: true
            spacing: Theme.spaceSm
        }
    }
}
