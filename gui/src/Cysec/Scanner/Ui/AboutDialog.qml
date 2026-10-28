// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Version rows and third-party notices.
// Public surface fixed by plan 13-07; content in 13-12.
Dialog {
    id: root

    property string guiVersion
    property string engineVersion
    property string qtVersion
    property string noticesText

    modal: true
}
