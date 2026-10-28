// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Details of the selected host with copy buttons. Callers append extra
// sections through the default slot.
// Public surface fixed by plan 13-07; content in 13-12.
Item {
    id: root

    property var host

    default property alias sections: extraSections.data

    implicitWidth: 320
    implicitHeight: 360

    Column {
        id: extraSections
        anchors.fill: parent
    }
}
