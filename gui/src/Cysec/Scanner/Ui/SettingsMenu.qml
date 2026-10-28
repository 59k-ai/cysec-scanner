// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls.Basic

// Button that opens the settings menu: the language choice and About
// (D-28). The host view places it in its footer, not in a top bar.
// Language names are shown as data in their own language, untranslated.
ToolButton {
    id: root

    signal aboutRequested()

    readonly property alias menu: menu

    text: qsTr("Settings")
    focusPolicy: Qt.StrongFocus
    implicitHeight: Theme.controlHeight
    Accessible.name: qsTr("Settings")
    onClicked: menu.open()

    contentItem: Text {
        text: root.text
        textFormat: Text.PlainText
        font.family: Theme.sansFamily
        font.pixelSize: Theme.fontSizeBody
        font.weight: Theme.weightSemiBold
        color: Theme.ink
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }

    background: Rectangle {
        implicitHeight: Theme.controlHeight
        radius: Theme.radiusSm
        color: root.down ? Theme.neutralFill : "transparent"
        border.width: root.activeFocus ? Theme.focusRingWidth : 0
        border.color: Theme.accent
    }

    Menu {
        id: menu
        objectName: "settingsMenu"
        y: -implicitHeight

        Menu {
            id: languageMenu
            objectName: "languageMenu"
            title: qsTr("Language")

            Instantiator {
                model: LanguageController.availableLanguages

                delegate: MenuItem {
                    id: languageItem
                    required property var modelData

                    objectName: "language_" + modelData.code
                    text: modelData.name
                    checkable: true
                    checked: modelData.code === LanguageController.language
                    Accessible.name: modelData.name
                    onTriggered: {
                        LanguageController.setLanguage(languageItem.modelData.code)
                        // Toggling broke the binding; the controller decides.
                        languageItem.checked = Qt.binding(
                            () => languageItem.modelData.code === LanguageController.language)
                    }
                }

                onObjectAdded: (index, object) => languageMenu.insertItem(index, object)
                onObjectRemoved: (index, object) => languageMenu.removeItem(object)
            }
        }

        MenuSeparator {}

        MenuItem {
            objectName: "aboutItem"
            text: qsTr("About Cysec Scanner")
            onTriggered: root.aboutRequested()
        }
    }
}
