// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtTest
import Cysec.Scanner.Ui

// ResultsTable over a real HostModel (built by TestData in tst_main.cpp) and
// DetailPanel over a host map. Hostile strings must render verbatim.
Item {
    id: rootItem
    width: 1000
    height: 600

    readonly property string hostile: "<img src=\"http://192.0.2.99/\">"

    function hosts() {
        return [
            { ip: "192.0.2.10", hostname: rootItem.hostile, mac: "00:11:22:33:44:55",
              vendor: "", osGuess: "Linux", services: [{ port: 22, serviceName: "ssh" }] },
            { ip: "192.0.2.9", hostname: "printer", vendor: "Example Print",
              osGuess: "", services: [{ port: 631 }, { port: 9100 }] },
            { ip: "192.0.2.100", hostname: "nas", vendor: "Example Storage",
              osGuess: "Linux", services: [{ port: 23 }, { port: 445 }, { port: 3389 }] }
        ]
    }

    // The first visible descendant with this objectName (TableView pools
    // delegates, so stale hidden copies can exist).
    function findVisible(item, name) {
        if (item.objectName === name && item.visible)
            return item
        const kids = item.children
        for (let i = 0; i < kids.length; ++i) {
            const hit = findVisible(kids[i], name)
            if (hit)
                return hit
        }
        return null
    }

    function allVisibleText(item, out) {
        if (!out)
            out = []
        if (!item.visible)
            return out
        if (item.text !== undefined && typeof item.text === "string")
            out.push(item)
        const kids = item.children
        for (let i = 0; i < kids.length; ++i)
            allVisibleText(kids[i], out)
        return out
    }

    Component {
        id: tableComponent
        ResultsTable {
            width: 900
            height: 400
        }
    }

    Component {
        id: spyComponent
        SignalSpy {}
    }

    TestCase {
        id: tableCase
        name: "ResultsTable"
        when: windowShown
        visible: true
        anchors.fill: parent

        function makeTable(props) {
            const model = TestData.hostModel(rootItem.hosts())
            const base = { model: model }
            for (const k in props)
                base[k] = props[k]
            const t = createTemporaryObject(tableComponent, tableCase, base)
            verify(t)
            const view = findChild(t, "hostTable")
            tryVerify(() => view.rows === model.count && view.columns === 5)
            waitForRendering(t)
            return t
        }

        function cell(t, row, column) {
            let found = null
            tryVerify(() => (found = rootItem.findVisible(t, "cell_" + row + "_" + column)) !== null,
                      2000, "cell " + row + "," + column)
            return found
        }

        function test_headers() {
            const t = makeTable({})
            const titles = ["IP address", "Hostname", "MAC vendor", "Open ports", "OS guess"]
            for (let c = 0; c < 5; ++c) {
                let h = null
                tryVerify(() => (h = rootItem.findVisible(t, "header_" + c)) !== null)
                compare(h.Accessible.name, titles[c])
            }
        }

        function test_customColumns() {
            const t = makeTable({ columns: [{ title: "Address", role: "ip", width: 200, mono: true },
                                            { title: "Name", role: "hostname", width: 200 }] })
            const view = findChild(t, "hostTable")
            tryCompare(view, "columns", 2)
            let h = null
            tryVerify(() => (h = rootItem.findVisible(t, "header_1")) !== null)
            compare(h.Accessible.name, "Name")
        }

        function test_defaultSortIsNumericIp() {
            const t = makeTable({})
            compare(cell(t, 0, 0).text, "192.0.2.9")
            compare(cell(t, 1, 0).text, "192.0.2.10")
            compare(cell(t, 2, 0).text, "192.0.2.100")
        }

        function test_hostileHostnameIsPlainText() {
            const t = makeTable({})
            const c = cell(t, 1, 1)
            compare(c.text, rootItem.hostile)
            compare(c.textFormat, Text.PlainText)
        }

        function test_emptyCellShowsUnknown() {
            const t = makeTable({})
            const vendor = cell(t, 1, 2)
            compare(vendor.text, "Unknown")
            compare(vendor.color, Theme.muted)
            compare(cell(t, 0, 4).text, "Unknown")
        }

        function test_neutralColoursOnly() {
            // D-14: no risk colours, even for 23/445/3389.
            const t = makeTable({})
            const allowed = [String(Theme.ink), String(Theme.muted), String(Theme.subtle)]
            for (let r = 0; r < 3; ++r) {
                for (let c = 0; c < 5; ++c) {
                    const col = String(cell(t, r, c).color)
                    verify(allowed.indexOf(col) >= 0, "cell " + r + "," + c + " " + col)
                }
            }
            compare(cell(t, 2, 3).text, "23, 445, 3389")
        }

        function test_headerClickSorts() {
            const t = makeTable({})
            compare(t.sortRole, "ip")
            compare(t.sortOrder, Qt.AscendingOrder)
            let h = null
            tryVerify(() => (h = rootItem.findVisible(t, "header_0")) !== null)
            mouseClick(h)
            compare(t.sortOrder, Qt.DescendingOrder)
            tryCompare(cell(t, 0, 0), "text", "192.0.2.100")
            compare(cell(t, 2, 0).text, "192.0.2.9")

            let hn = rootItem.findVisible(t, "header_1")
            mouseClick(hn)
            compare(t.sortRole, "hostname")
            compare(t.sortOrder, Qt.AscendingOrder)
            tryCompare(cell(t, 0, 1), "text", rootItem.hostile)
        }

        function test_accessibleTable() {
            const t = makeTable({})
            compare(findChild(t, "hostTable").Accessible.role, Accessible.Table)
        }

        function test_clickSelectsAndKeysMove() {
            const t = makeTable({})
            const spy = createTemporaryObject(spyComponent, tableCase,
                                              { target: t, signalName: "hostActivated" })
            mouseClick(cell(t, 0, 0))
            compare(t.currentRow, 0)
            compare(t.currentHost.ip, "192.0.2.9")
            verify(findChild(t, "hostTable").activeFocus)

            keyClick(Qt.Key_Down)
            compare(t.currentRow, 1)
            compare(t.currentHost.ip, "192.0.2.10")
            keyClick(Qt.Key_Down)
            keyClick(Qt.Key_Down)
            compare(t.currentHost.ip, "192.0.2.100")
            keyClick(Qt.Key_Up)
            compare(t.currentHost.ip, "192.0.2.10")

            keyClick(Qt.Key_Return)
            compare(spy.count, 1)
            compare(spy.signalArguments[0][0], 1)
        }

        function test_selectionStableAcrossInsertAndSort() {
            const t = makeTable({})
            t.selectRow(1)
            compare(t.currentHost.ip, "192.0.2.10")
            TestData.upsertHost(t.model, { ip: "192.0.2.1", hostname: "gateway" })
            tryCompare(findChild(t, "hostTable"), "rows", 4)
            compare(t.currentHost.ip, "192.0.2.10")
            compare(t.currentRow, 2)

            t.sortBy("ip") // descending
            tryCompare(t, "currentRow", 1)
            compare(t.currentHost.ip, "192.0.2.10")
        }

        function test_selectionUpdatesWithData() {
            const t = makeTable({})
            t.selectRow(0)
            TestData.upsertHost(t.model, { ip: "192.0.2.9", hostname: "printer-2" })
            tryCompare(t.currentHost, "hostname", "printer-2")
        }

        function test_filter() {
            const t = makeTable({})
            t.filterText = "printer"
            tryCompare(findChild(t, "hostTable"), "rows", 1)
            compare(cell(t, 0, 0).text, "192.0.2.9")
        }

        function test_emptyState() {
            const t = createTemporaryObject(tableComponent, tableCase,
                                            { model: TestData.hostModel([]),
                                              emptyTitle: "No scan yet",
                                              emptyBody: "Hosts appear here." })
            const title = findChild(t, "emptyTitle")
            tryVerify(() => title.visible)
            compare(title.text, "No scan yet")
            compare(findChild(t, "emptyBody").text, "Hosts appear here.")
        }

        function test_emptyStateHiddenWithRows() {
            const t = makeTable({ emptyTitle: "No scan yet" })
            verify(!findChild(t, "emptyState").visible)
        }
    }

    Component {
        id: detailComponent
        DetailPanel {
            width: 360
            height: 560
        }
    }

    Component {
        id: detailWithSection
        DetailPanel {
            width: 360
            height: 560
            Rectangle {
                objectName: "extraSection"
                implicitWidth: 10
                implicitHeight: 30
            }
        }
    }

    TestCase {
        id: detailCase
        name: "DetailPanel"
        when: windowShown
        visible: true
        anchors.fill: parent

        function sampleHost() {
            return { ip: "192.0.2.10", hostname: rootItem.hostile, mac: "00:11:22:33:44:55",
                     vendor: "", osGuess: "Linux",
                     services: [{ port: 22, protocol: "tcp", serviceName: "ssh",
                                  product: "OpenSSH", version: "9.6" },
                                { port: 3389, protocol: "tcp", serviceName: "",
                                  product: "", version: "" }] }
        }

        function test_emptyState() {
            const p = createTemporaryObject(detailComponent, detailCase)
            const empty = findChild(p, "detailEmpty")
            verify(empty.visible)
            compare(empty.text, "Select a host to see its details.")
        }

        function test_facts() {
            const p = createTemporaryObject(detailComponent, detailCase, { host: sampleHost() })
            verify(!findChild(p, "detailEmpty").visible)
            compare(findChild(p, "detailHeading").text, "192.0.2.10")
            const hn = findChild(p, "fact_Hostname")
            compare(hn.text, rootItem.hostile)
            compare(hn.textFormat, TextEdit.PlainText)
            verify(hn.readOnly)
            const vendor = findChild(p, "fact_MAC vendor")
            compare(vendor.text, "Unknown")
            compare(vendor.color, Theme.muted)
            compare(findChild(p, "servicePort0").text, "22/tcp")
            compare(findChild(p, "serviceName0").text, "ssh")
            compare(findChild(p, "serviceDetail0").text, "OpenSSH 9.6")
            compare(findChild(p, "servicePort1").text, "3389/tcp")
            verify(!findChild(p, "noPorts").visible)
        }

        function test_neutralColours() {
            // D-14: port 3389 looks exactly like port 22.
            const p = createTemporaryObject(detailComponent, detailCase, { host: sampleHost() })
            compare(findChild(p, "servicePort1").color, findChild(p, "servicePort0").color)
            compare(findChild(p, "servicePort1").color, Theme.ink)
            const allowed = [String(Theme.ink), String(Theme.muted), String(Theme.subtle)]
            for (const item of rootItem.allVisibleText(p)) {
                if (item.color !== undefined)
                    verify(allowed.indexOf(String(item.color)) >= 0, item.text + " " + item.color)
            }
        }

        function test_noPorts() {
            const h = sampleHost()
            h.services = []
            const p = createTemporaryObject(detailComponent, detailCase, { host: h })
            const np = findChild(p, "noPorts")
            verify(np.visible)
            compare(np.text, "No open ports found among the scanned ports.")
        }

        function test_copyButtons() {
            const p = createTemporaryObject(detailComponent, detailCase, { host: sampleHost() })
            const names = []
            const walk = function(item) {
                if (item.visible && item.Accessible && item.Accessible.name
                        && item.text === "Copy")
                    names.push(item.Accessible.name)
                for (let i = 0; i < item.children.length; ++i)
                    walk(item.children[i])
            }
            walk(p)
            verify(names.indexOf("Copy IP address") >= 0, names.join("|"))
            verify(names.indexOf("Copy Hostname") >= 0, names.join("|"))
            verify(names.indexOf("Copy 22/tcp") >= 0, names.join("|"))
            // Unknown values have nothing to copy.
            verify(names.indexOf("Copy MAC vendor") < 0, names.join("|"))
        }

        function test_sectionsSlot() {
            const p = createTemporaryObject(detailWithSection, detailCase, { host: sampleHost() })
            const extra = findChild(p, "extraSection")
            verify(extra)
            verify(extra.visible)
        }
    }
}
