// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Chooser for the export format. JSON is offered only when the engine wrote
// a payload. Public surface fixed by plan 13-07; content in 13-16.
Popup {
    id: root

    property bool partial: false
    property bool jsonAvailable: false

    signal formatChosen(string format)

    modal: true
}
