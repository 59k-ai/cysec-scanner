// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Toolbar button that opens the settings menu (language, about).
// Public surface fixed by plan 13-07; content in 13-12.
ToolButton {
    id: root

    signal aboutRequested()

    onClicked: menu.open()

    Menu {
        id: menu
    }
}
