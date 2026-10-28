// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// The only way this module renders text it does not own. The text format is
// fixed to plain so markup inside network-derived strings is shown verbatim and never
// interpreted (no rich text, no remote images).
Label {
    id: label

    // Monospace for IPs, MACs, ports, counts, timestamps and log lines.
    property bool mono: false

    textFormat: Text.PlainText
    color: Theme.ink
    font.family: label.mono ? Theme.monoFamily : Theme.sansFamily
    font.pixelSize: Theme.fontSizeBody
    font.weight: Theme.weightRegular
    elide: Text.ElideRight
}
