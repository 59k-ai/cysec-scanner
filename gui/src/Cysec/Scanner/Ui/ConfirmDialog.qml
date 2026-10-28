// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts

// Modal two-choice confirmation. title is the Dialog title; destructive
// styles the primary choice as destructive.
//
// Keyboard: Escape (or any close without a choice) means secondaryChosen().
// Enter triggers the default choice: the secondary one for a destructive
// confirmation (the safe "keep" action), the primary one otherwise. The
// default button has focus when the dialog opens; Tab stays inside.
Dialog {
    id: root

    property string body
    property string primaryText
    property string secondaryText
    property bool destructive: false

    signal primaryChosen()
    signal secondaryChosen()

    readonly property bool primaryIsDefault: !destructive
    // False while secondaryChosen() is emitted for a close without a choice
    // (Escape, outside close), true for a button or Enter. Callers whose
    // secondary action loses data use it to treat Escape as "cancel".
    readonly property bool choiceExplicit: d.explicit

    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape
    anchors.centerIn: parent
    width: Math.min(480, parent ? parent.width - 2 * Theme.spaceLg : 480)
    padding: Theme.spaceLg
    topPadding: Theme.spaceSm

    QtObject {
        id: d
        property bool chosen: false
        property bool explicit: false
    }

    function choosePrimary() {
        d.chosen = true
        d.explicit = true
        root.close()
        root.primaryChosen()
    }

    function chooseSecondary() {
        d.chosen = true
        d.explicit = true
        root.close()
        root.secondaryChosen()
    }

    function chooseDefault() {
        if (root.primaryIsDefault)
            root.choosePrimary()
        else
            root.chooseSecondary()
    }

    onAboutToShow: {
        d.chosen = false
        d.explicit = false
    }
    onOpened: (root.primaryIsDefault ? primaryButton : secondaryButton)
                  .forceActiveFocus(Qt.PopupFocusReason)
    onClosed: if (!d.chosen) {
        d.chosen = true
        d.explicit = false
        root.secondaryChosen()
    }

    background: Rectangle {
        color: Theme.surfaceMuted
        radius: Theme.radiusMd
        border.width: 1
        border.color: Theme.hairline
    }

    header: PlainLabel {
        objectName: "dialogTitle"
        text: root.title
        leftPadding: Theme.spaceLg
        rightPadding: Theme.spaceLg
        topPadding: Theme.spaceLg
        font.pixelSize: Theme.fontSizeHeading
        font.weight: Theme.weightSemiBold
        wrapMode: Text.Wrap
        elide: Text.ElideNone
    }

    contentItem: FocusScope {
        implicitWidth: bodyText.implicitWidth
        implicitHeight: bodyText.implicitHeight
        Keys.onReturnPressed: root.chooseDefault()
        Keys.onEnterPressed: root.chooseDefault()

        PlainLabel {
            id: bodyText
            objectName: "dialogBody"
            width: parent.width
            text: root.body
            color: Theme.muted
            wrapMode: Text.Wrap
            elide: Text.ElideNone
        }
    }

    footer: Item {
        implicitHeight: buttons.implicitHeight + 2 * Theme.spaceLg
        implicitWidth: buttons.implicitWidth + 2 * Theme.spaceLg
        Keys.onReturnPressed: root.chooseDefault()
        Keys.onEnterPressed: root.chooseDefault()

        RowLayout {
            id: buttons
            anchors.right: parent.right
            anchors.rightMargin: Theme.spaceLg
            anchors.verticalCenter: parent.verticalCenter
            spacing: Theme.spaceSm

            SecondaryButton {
                id: secondaryButton
                objectName: "secondaryButton"
                text: root.secondaryText
                onClicked: root.chooseSecondary()
            }

            PrimaryButton {
                id: primaryButton
                objectName: "primaryButton"
                visible: !root.destructive
                text: root.primaryText
                onClicked: root.choosePrimary()
            }

            DestructiveButton {
                id: destructiveButton
                objectName: "destructiveButton"
                visible: root.destructive
                text: root.primaryText
                onClicked: root.choosePrimary()
            }
        }
    }
}
