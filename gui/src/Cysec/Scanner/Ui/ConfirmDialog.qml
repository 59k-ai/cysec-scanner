// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic

// Modal two-choice confirmation. title is the Dialog title; destructive
// styles the primary choice as destructive.
// Public surface fixed by plan 13-07; content in 13-12.
Dialog {
    id: root

    property string body
    property string primaryText
    property string secondaryText
    property bool destructive: false

    signal primaryChosen()
    signal secondaryChosen()

    modal: true
}
