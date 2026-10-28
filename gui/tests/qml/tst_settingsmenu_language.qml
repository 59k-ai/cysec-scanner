// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import QtTest
import Cysec.Scanner.Ui

// The settings menu drives the runtime language switch (D-28): picking an
// entry changes LanguageController.language and bumps revision, which is
// what Formatter bindings pass to re-evaluate.
TestCase {
    id: testCase
    name: "SettingsMenuLanguage"
    when: windowShown
    visible: true
    width: 900
    height: 700

    Component {
        id: settingsComponent
        SettingsMenu {}
    }

    function cleanup() {
        LanguageController.setLanguage("en")
        TestData.resetSettings()
    }

    function openLanguageMenu() {
        const button = createTemporaryObject(settingsComponent, testCase, { x: 100, y: 600 })
        verify(button)
        mouseClick(button)
        tryCompare(button.menu, "opened", true)
        const languageMenu = button.menu.menuAt(0)
        verify(languageMenu)
        return languageMenu
    }

    function itemFor(languageMenu, code) {
        for (let i = 0; i < languageMenu.count; ++i) {
            const it = languageMenu.itemAt(i)
            if (it && it.objectName === "language_" + code)
                return it
        }
        return null
    }

    function test_switchToGermanAndBack() {
        compare(LanguageController.language, "en")
        const revisionBefore = LanguageController.revision

        let languageMenu = openLanguageMenu()
        const de = itemFor(languageMenu, "de")
        verify(de, "Deutsch entry")
        compare(de.text, "Deutsch")
        de.triggered()
        compare(LanguageController.language, "de")
        compare(LanguageController.revision, revisionBefore + 1)
        compare(Formatter.count(12345, LanguageController.revision), "12.345")
        verify(de.checked)

        languageMenu = openLanguageMenu()
        const en = itemFor(languageMenu, "en")
        verify(en, "English entry")
        en.triggered()
        compare(LanguageController.language, "en")
        compare(LanguageController.revision, revisionBefore + 2)
        compare(Formatter.count(12345, LanguageController.revision), "12,345")
    }

    function test_reselectingCurrentLanguageIsNoOp() {
        const revisionBefore = LanguageController.revision
        const languageMenu = openLanguageMenu()
        const en = itemFor(languageMenu, "en")
        verify(en)
        en.triggered()
        compare(LanguageController.language, "en")
        compare(LanguageController.revision, revisionBefore)
    }
}
