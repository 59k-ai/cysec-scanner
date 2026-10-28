// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Collapsible scan log with warning and error counts in its header.
// Public surface fixed by plan 13-07; content in 13-12.
Item {
    id: root

    property var model
    property int warningCount: 0
    property int errorCount: 0
    property bool expanded: false

    implicitWidth: 640
    implicitHeight: 40
}
