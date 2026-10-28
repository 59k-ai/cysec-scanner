// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Display-only scan progress: stage stepper, counters, elapsed time and a
// status line. Callers append extra rows through the default slot.
// Public surface fixed by plan 13-07; content in 13-12.
Item {
    id: root

    property var stages: []
    property int currentStage: -1
    property int stageDone: 0
    property int stageTotal: 0
    property int elapsedSeconds: 0
    // ScanSession.State. Named scanState because Item already owns a string
    // "state" property (the States machinery); shadowing it is a lint error.
    property int scanState: 0
    property string title
    property string statusText
    property int hostsFound: 0

    default property alias extraContent: extra.data

    implicitWidth: 400
    implicitHeight: 120

    Item {
        id: extra
        anchors.fill: parent
    }
}
