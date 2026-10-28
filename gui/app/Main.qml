// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import Cysec.Scanner.Ui

// The standalone window. All copy lives in the Cysec.Scanner.Ui module
// (ScannerView), so this file has no translatable strings and one catalogue
// covers the whole GUI. session and engineInfo are injected from C++.
ApplicationWindow {
    id: root

    required property ScanSession session
    required property EngineInfo engineInfo
    required property string noticesText

    minimumWidth: 960
    minimumHeight: 640
    width: 1280
    height: 800
    visible: true
    color: Theme.surface
    title: view.windowTitle

    // A running scan or unexported results hold the close (D-22/D-27).
    onClosing: close => view.handleCloseRequest(close)

    ScannerView {
        id: view
        anchors.fill: parent
        session: root.session
        engineInfo: root.engineInfo
        noticesText: root.noticesText
        onQuitRequested: Qt.quit()
    }
}
