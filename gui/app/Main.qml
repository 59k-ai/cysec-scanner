// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import Cysec.Scanner.Ui

ApplicationWindow {
    id: root

    property string heading: "Cysec Scanner"

    minimumWidth: 960
    minimumHeight: 640
    width: 1280
    height: 800
    visible: true
    color: Theme.surface
    title: root.heading

    PlainLabel {
        anchors.centerIn: parent
        text: root.heading
    }
}
