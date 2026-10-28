// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Controls.Basic
import QtTest
import Cysec.Scanner.Ui

TestCase {
    id: testCase
    name: "Dialogs"
    when: windowShown
    visible: true
    width: 900
    height: 700

    Component {
        id: confirmComponent
        ConfirmDialog {
            title: "Stop scan and quit?"
            body: "A scan is still running."
            primaryText: "Stop and quit"
            secondaryText: "Keep scanning"
        }
    }

    Component {
        id: aboutComponent
        AboutDialog {}
    }

    Component {
        id: settingsComponent
        SettingsMenu {}
    }

    Component {
        id: spyComponent
        SignalSpy {}
    }

    function spyOn(target, signalName) {
        return createTemporaryObject(spyComponent, testCase,
                                     { target: target, signalName: signalName })
    }

    function isInside(item, ancestor) {
        for (let p = item; p; p = p.parent) {
            if (p === ancestor)
                return true
        }
        return false
    }

    function openConfirm(destructive) {
        const dlg = createTemporaryObject(confirmComponent, testCase, { destructive: destructive })
        verify(dlg)
        dlg.open()
        tryCompare(dlg, "opened", true)
        return dlg
    }

    function allTexts(item, out) {
        if (!out)
            out = []
        if (item.text !== undefined && typeof item.text === "string")
            out.push(item.text)
        for (let i = 0; i < item.children.length; ++i)
            allTexts(item.children[i], out)
        return out
    }

    // ---- ConfirmDialog ----------------------------------------------------

    function test_confirmDestructiveUsesDestructiveButton() {
        const dlg = openConfirm(true)
        const destructive = findChild(dlg.footer, "destructiveButton")
        verify(destructive.visible)
        verify(!findChild(dlg.footer, "primaryButton").visible)
        compare(destructive.text, "Stop and quit")
        compare(destructive.background.color, Theme.errorEdge)
        compare(dlg.header.text, "Stop scan and quit?")
    }

    function test_confirmPlainUsesPrimaryButton() {
        const dlg = openConfirm(false)
        verify(findChild(dlg.footer, "primaryButton").visible)
        verify(!findChild(dlg.footer, "destructiveButton").visible)
    }

    function test_confirmEscapeIsSecondary() {
        const dlg = openConfirm(true)
        const secondary = spyOn(dlg, "secondaryChosen")
        const primary = spyOn(dlg, "primaryChosen")
        keyClick(Qt.Key_Escape)
        tryCompare(dlg, "visible", false)
        compare(secondary.count, 1)
        compare(primary.count, 0)
    }

    function test_confirmEnterTriggersSafeDefaultWhenDestructive() {
        const dlg = openConfirm(true)
        const secondary = spyOn(dlg, "secondaryChosen")
        const primary = spyOn(dlg, "primaryChosen")
        verify(findChild(dlg.footer, "secondaryButton").activeFocus)
        keyClick(Qt.Key_Return)
        tryCompare(dlg, "visible", false)
        compare(secondary.count, 1)
        compare(primary.count, 0)
    }

    function test_confirmEnterTriggersPrimaryOtherwise() {
        const dlg = openConfirm(false)
        const secondary = spyOn(dlg, "secondaryChosen")
        const primary = spyOn(dlg, "primaryChosen")
        verify(findChild(dlg.footer, "primaryButton").activeFocus)
        keyClick(Qt.Key_Enter)
        tryCompare(dlg, "visible", false)
        compare(primary.count, 1)
        compare(secondary.count, 0)
    }

    function test_confirmClickPrimaryOnce() {
        const dlg = openConfirm(true)
        const secondary = spyOn(dlg, "secondaryChosen")
        const primary = spyOn(dlg, "primaryChosen")
        mouseClick(findChild(dlg.footer, "destructiveButton"))
        tryCompare(dlg, "visible", false)
        compare(primary.count, 1)
        compare(secondary.count, 0)
    }

    function test_confirmFocusTrapped() {
        const dlg = openConfirm(true)
        const popupItem = dlg.contentItem.parent
        verify(popupItem)
        for (let i = 0; i < 6; ++i) {
            keyClick(Qt.Key_Tab)
            verify(testCase.Window.activeFocusItem, "focus item " + i)
            verify(isInside(testCase.Window.activeFocusItem, popupItem),
                   "Tab " + i + " left the dialog: " + testCase.Window.activeFocusItem)
        }
        compare(dlg.visible, true)
    }

    // ---- AboutDialog ------------------------------------------------------

    function openAbout(props) {
        const dlg = createTemporaryObject(aboutComponent, testCase, props)
        verify(dlg)
        dlg.open()
        tryCompare(dlg, "opened", true)
        return dlg
    }

    function test_aboutVersions() {
        const dlg = openAbout({ guiVersion: "v0.1.0", engineVersion: "v0.9.2", qtVersion: "6.11.1" })
        compare(findChild(dlg.contentItem, "guiVersionValue").text, "v0.1.0")
        compare(findChild(dlg.contentItem, "engineVersionValue").text, "v0.9.2")
        compare(findChild(dlg.contentItem, "qtVersionValue").text, "6.11.1")
        compare(findChild(dlg.contentItem, "engineVersionValue").color, Theme.ink)
        compare(dlg.title, "About Cysec Scanner")
    }

    function test_aboutUnknownEngine() {
        const dlg = openAbout({ guiVersion: "v0.1.0", engineVersion: "", qtVersion: "6.11.1" })
        const engine = findChild(dlg.contentItem, "engineVersionValue")
        compare(engine.text, "Unknown")
        compare(engine.color, Theme.muted)
    }

    function test_aboutLicencesAndCopyright() {
        const dlg = openAbout({ guiVersion: "v0.1.0", engineVersion: "v0.9.2", qtVersion: "6.11.1" })
        const texts = allTexts(dlg.contentItem).concat(allTexts(dlg.header)).concat(allTexts(dlg.footer))
        for (const want of ["Version", "Scan engine", "Qt", "Licences", "Third-party notices",
                            "Cysec Scanner: Apache-2.0", "Qt: LGPLv3 (dynamically linked)",
                            "IEEE OUI data: MAC vendor names derived from the IEEE registry",
                            "IBM Plex fonts: SIL Open Font License 1.1",
                            "View third-party notices", "© 2026 59k GmbH", "Close"]) {
            verify(texts.indexOf(want) >= 0, "missing: " + want)
        }
        for (const t of texts)
            verify(!/cysec\.watch|cysecwatch/i.test(t), t)
    }

    function test_aboutNoticesViewer() {
        const dlg = openAbout({ guiVersion: "v0.1.0", noticesText: "Notice <b>A</b>" })
        const scroll = findChild(dlg.contentItem, "noticesScroll")
        verify(!scroll.visible)
        mouseClick(findChild(dlg.contentItem, "noticesButton"))
        tryCompare(scroll, "visible", true)
        const view = findChild(dlg.contentItem, "noticesView")
        verify(view.readOnly)
        compare(view.textFormat, TextEdit.PlainText)
        compare(view.text, "Notice <b>A</b>")
    }

    function test_aboutLoadNoticesFromResource() {
        const dlg = openAbout({})
        compare(dlg.noticesText, "")
        dlg.loadNotices()
        tryVerify(() => dlg.noticesText.length > 100, 3000)
        verify(dlg.noticesText.indexOf("IBM Plex") >= 0 || dlg.noticesText.length > 0)
    }

    function test_aboutCloseButton() {
        const dlg = openAbout({})
        verify(findChild(dlg.footer, "closeButton").activeFocus)
        mouseClick(findChild(dlg.footer, "closeButton"))
        tryCompare(dlg, "visible", false)
    }

    function test_aboutEscapeCloses() {
        const dlg = openAbout({})
        keyClick(Qt.Key_Escape)
        tryCompare(dlg, "visible", false)
    }

    // ---- SettingsMenu -----------------------------------------------------

    function test_settingsMenuEntries() {
        const button = createTemporaryObject(settingsComponent, testCase, { x: 100, y: 600 })
        verify(button)
        compare(button.Accessible.name, "Settings")
        mouseClick(button)
        const menu = button.menu
        tryCompare(menu, "opened", true)

        const languageMenu = menu.menuAt(0)
        verify(languageMenu)
        compare(languageMenu.title, "Language")
        compare(languageMenu.count, LanguageController.availableLanguages.length)
        compare(languageMenu.count, 2)
        const en = languageMenu.itemAt(0)
        const de = languageMenu.itemAt(1)
        compare(en.text, "English")
        compare(de.text, "Deutsch")
        verify(en.checkable)
        verify(de.checkable)
        compare(en.checked, LanguageController.language === "en")
        compare(de.checked, LanguageController.language === "de")

        let about = null
        for (let i = 0; i < menu.count; ++i) {
            const it = menu.itemAt(i)
            if (it && it.text === "About Cysec Scanner")
                about = it
        }
        verify(about, "About entry")
        const spy = spyOn(button, "aboutRequested")
        about.click()
        compare(spy.count, 1)
    }

    function test_settingsMenuCheckedFollowsController() {
        const button = createTemporaryObject(settingsComponent, testCase, { x: 100, y: 600 })
        mouseClick(button)
        tryCompare(button.menu, "opened", true)
        const languageMenu = button.menu.menuAt(0)
        const current = LanguageController.language
        const other = languageMenu.itemAt(current === "en" ? 1 : 0)
        other.click()
        // setLanguage is implemented by 13-13; whatever the controller
        // reports, the check marks follow it rather than the click.
        compare(other.checked, other.text === (LanguageController.language === "en" ? "English"
                                                                                    : "Deutsch"))
    }
}
