// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Scan setup: targets, ports, fragile-probe switch, start and stop.
// Public surface fixed by plan 13-07; content in 13-16.
Item {
    id: root

    property var engineInfo
    property bool running: false
    property bool stopping: false

    signal startRequested(var cidrs, string portSpec, bool probeFragile)
    signal stopRequested()

    implicitWidth: 800
    implicitHeight: 64
}
