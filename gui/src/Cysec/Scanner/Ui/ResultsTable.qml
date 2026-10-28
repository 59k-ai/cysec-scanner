// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Sortable, filterable host table. Columns are data, so callers can add
// their own. Public surface fixed by plan 13-07; content in 13-12.
Item {
    id: root

    property var model
    property var columns: [] // [{title, role, width, mono}]
    property string filterText
    property var currentHost

    signal hostActivated(int row)

    implicitWidth: 640
    implicitHeight: 360
}
