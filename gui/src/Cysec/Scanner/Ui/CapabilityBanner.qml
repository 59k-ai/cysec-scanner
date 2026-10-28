// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Inline notice about a missing host capability (for example no
// unprivileged ICMP). Public surface fixed by plan 13-07; content in 13-12.
Item {
    id: root

    property string text
    property bool dismissible: true

    signal dismissed()

    implicitWidth: 400
    implicitHeight: 40
}
