// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// The whole scanner screen, composed from the module components. The
// hosting window binds its title to windowTitle and forwards close requests
// to handleCloseRequest(close) so unexported results can be confirmed.
// Public surface fixed by plan 13-07; content in 13-16.
Item {
    id: root

    property var session
    property var engineInfo
    readonly property string windowTitle: ""

    function handleCloseRequest(close) {
        close.accepted = true;
    }

    implicitWidth: 1024
    implicitHeight: 720
}
