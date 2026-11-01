// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Controls.impl

// Sortable, filterable host table. Columns are data, so callers can add
// their own: [{title, role, width, mono}], title already translated by the
// caller. The filter proxy and the table adapter are internal; callers pass
// the host list model (HostModel roles) and read currentHost.
//
// Facts only (D-14): every cell uses neutral text colours. Nothing here
// styles a host, port, service or OS by risk. Every engine string is drawn
// through PlainLabel, so markup in a hostname is shown verbatim.
Item {
    id: root

    property var model
    property var columns: [] // [{title, role, width, mono}]
    property string filterText
    property var currentHost

    // When set, replaces "Unknown" in the MAC vendor (and MAC) column for a
    // host without a MAC: macOS 27 hides other devices' MAC addresses from
    // programs without administrator rights. macUnavailableDetail is the
    // fuller wording shown as the cell's tooltip and accessible description.
    property string macUnavailableText
    property string macUnavailableDetail

    // Empty-state copy, supplied by the caller for the current scan state.
    property string emptyTitle
    property string emptyBody

    // Current sort, by role name ("ip" sorts numerically).
    property string sortRole: "ip"
    property int sortOrder: Qt.AscendingOrder

    // Selected row in view order, or -1.
    readonly property int currentRow: d.currentRow

    signal hostActivated(int row)

    readonly property var defaultColumns: [
        { title: qsTr("IP address"), role: "ip", width: 140, mono: true },
        { title: qsTr("Hostname"), role: "hostname", width: 200, mono: false },
        { title: qsTr("MAC vendor"), role: "vendor", width: 180, mono: false },
        { title: qsTr("Open ports"), role: "ports", width: 160, mono: true },
        { title: qsTr("OS guess"), role: "osGuess", width: 180, mono: false }
    ]
    readonly property var effectiveColumns: columns && columns.length > 0 ? columns : defaultColumns

    implicitWidth: 640
    implicitHeight: 360

    function sortBy(role: string) {
        if (role === root.sortRole)
            root.sortOrder = root.sortOrder === Qt.AscendingOrder ? Qt.DescendingOrder
                                                                  : Qt.AscendingOrder
        else {
            root.sortRole = role
            root.sortOrder = Qt.AscendingOrder
        }
        d.applySort()
    }

    function selectRow(row: int) {
        if (row < 0 || row >= adapter.rowCount()) {
            d.currentRow = -1
            d.currentKey = ""
            root.currentHost = null
            return
        }
        const host = adapter.rowData(row)
        d.currentRow = row
        d.currentKey = d.keyOf(host)
        root.currentHost = host
        table.positionViewAtRow(row, TableView.Contain)
    }

    QtObject {
        id: d

        property int currentRow: -1
        property string currentKey: ""

        function keyOf(host: var): string {
            if (!host)
                return ""
            return host.ip ? "ip:" + host.ip : "id:" + (host.externalId || "")
        }

        function applySort() {
            proxy.sortByRole(root.sortRole, root.sortOrder)
        }

        // Rows move on live inserts, re-sorts and filter changes; follow the
        // selected host by key so the selection never jumps to another host.
        function relocate() {
            if (d.currentKey.length === 0)
                return
            const n = adapter.rowCount()
            for (let r = 0; r < n; ++r) {
                const host = adapter.rowData(r)
                if (d.keyOf(host) === d.currentKey) {
                    const moved = r !== d.currentRow
                    d.currentRow = r
                    root.currentHost = host
                    if (moved)
                        table.positionViewAtRow(r, TableView.Contain)
                    return
                }
            }
            d.currentRow = -1
            d.currentKey = ""
            root.currentHost = null
        }
    }

    HostFilterProxy {
        id: proxy
        sourceModel: root.model ?? null
        filterText: root.filterText
        onSourceModelChanged: d.applySort()
    }

    HostTableAdapter {
        id: adapter
        sourceModel: proxy
        columnRoles: root.effectiveColumns.map(c => c.role)
    }

    Connections {
        target: adapter
        function onLayoutChanged() { d.relocate() }
        function onRowsInserted() { d.relocate() }
        function onRowsRemoved() { d.relocate() }
        function onModelReset() { d.relocate() }
        function onDataChanged() { d.relocate() }
    }

    // One shared tooltip for truncated cells; its text is plain.
    ToolTip {
        id: cellTip
        delay: 500
        contentItem: PlainLabel {
            text: cellTip.text
            font.pixelSize: Theme.fontSizeLabel
            wrapMode: Text.Wrap
            elide: Text.ElideNone
        }
        background: Rectangle {
            color: Theme.surfaceMuted
            border.width: 1
            border.color: Theme.hairline
            radius: Theme.radiusSm
        }
    }

    Rectangle {
        anchors.fill: parent
        color: Theme.surface
        border.width: 1
        border.color: Theme.hairline
    }

    HorizontalHeaderView {
        id: header
        objectName: "hostTableHeader"
        anchors.left: table.left
        anchors.right: table.right
        anchors.top: parent.top
        anchors.topMargin: 1
        syncView: table
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        // Not a Tab stop: the UI-SPEC order goes filter -> table, and the
        // header cells are sorted by pointer (each cell is announced as a
        // column header).
        activeFocusOnTab: false

        delegate: Rectangle {
            id: headerCell
            required property int column

            readonly property var spec: root.effectiveColumns[column] ?? ({})
            readonly property bool sorted: spec.role === root.sortRole

            objectName: "header_" + column
            implicitHeight: Theme.rowHeight
            implicitWidth: 120
            color: Theme.surfaceMuted

            Accessible.role: Accessible.ColumnHeader
            Accessible.name: headerTitle.text

            Rectangle {
                anchors.bottom: parent.bottom
                width: parent.width
                height: 1
                color: Theme.hairline
            }

            PlainLabel {
                id: headerTitle
                anchors.left: parent.left
                anchors.right: sortIcon.left
                anchors.leftMargin: Theme.spaceSm
                anchors.verticalCenter: parent.verticalCenter
                text: headerCell.spec.title ?? ""
                color: Theme.ink
                font.pixelSize: Theme.fontSizeLabel
                font.weight: Theme.weightSemiBold
                Accessible.ignored: true
            }

            ColorImage {
                id: sortIcon
                anchors.right: parent.right
                anchors.rightMargin: Theme.spaceSm
                anchors.verticalCenter: parent.verticalCenter
                visible: headerCell.sorted
                source: Theme.iconChevron
                color: Theme.muted
                width: 12
                height: 12
                sourceSize.width: 12
                sourceSize.height: 12
                rotation: root.sortOrder === Qt.AscendingOrder ? -90 : 90
                Accessible.ignored: true
            }

            TapHandler {
                onTapped: root.sortBy(headerCell.spec.role)
            }
        }
    }

    TableView {
        id: table
        objectName: "hostTable"
        anchors.top: header.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: 1
        anchors.topMargin: 0
        clip: true
        model: adapter
        focus: true
        activeFocusOnTab: true
        keyNavigationEnabled: false
        pointerNavigationEnabled: false
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.vertical: ScrollBar {}
        ScrollBar.horizontal: ScrollBar {}

        Accessible.role: Accessible.Table
        Accessible.name: qsTr("Hosts")

        columnWidthProvider: function(column) {
            const cols = root.effectiveColumns
            if (column >= cols.length)
                return 0
            const w = cols[column].width || 160
            if (column < cols.length - 1)
                return w
            let used = 0
            for (let i = 0; i < cols.length - 1; ++i)
                used += cols[i].width || 160
            return Math.max(w, table.width - used)
        }
        rowHeightProvider: function(row) { return Theme.rowHeight }
        onWidthChanged: forceLayout()

        Keys.onPressed: function(event) {
            const n = adapter.rowCount()
            if (n === 0)
                return
            if (event.key === Qt.Key_Down) {
                root.selectRow(Math.min(n - 1, d.currentRow < 0 ? 0 : d.currentRow + 1))
                event.accepted = true
            } else if (event.key === Qt.Key_Up) {
                root.selectRow(Math.max(0, d.currentRow < 0 ? 0 : d.currentRow - 1))
                event.accepted = true
            } else if (event.key === Qt.Key_Home) {
                root.selectRow(0)
                event.accepted = true
            } else if (event.key === Qt.Key_End) {
                root.selectRow(n - 1)
                event.accepted = true
            } else if ((event.key === Qt.Key_Return || event.key === Qt.Key_Enter)
                       && d.currentRow >= 0) {
                root.hostActivated(d.currentRow)
                event.accepted = true
            }
        }

        delegate: Rectangle {
            id: cell
            required property int row
            required property int column
            required property var display

            readonly property bool selected: row === d.currentRow
            readonly property bool unknown: display === undefined || display === null
                                            || String(display).length === 0
            readonly property var spec: root.effectiveColumns[column] ?? ({})
            // Unknown because the OS hid the MAC, not because nothing answered.
            readonly property bool macHidden: unknown && root.macUnavailableText.length > 0
                                              && (spec.role === "vendor" || spec.role === "mac")
                                              && !((adapter.rowData(row).mac ?? "").length > 0)

            implicitHeight: Theme.rowHeight
            color: selected ? Theme.accentTint : (row % 2 === 1 ? Theme.zebra : Theme.surface)

            Accessible.role: Accessible.Cell
            Accessible.name: cellText.text
            Accessible.description: cell.macHidden ? root.macUnavailableDetail : ""

            Rectangle {
                // Selection edge on the first column only.
                visible: cell.selected && cell.column === 0
                width: 3
                height: parent.height
                color: Theme.accent
            }

            PlainLabel {
                id: cellText
                objectName: "cell_" + cell.row + "_" + cell.column
                anchors.fill: parent
                anchors.leftMargin: Theme.spaceSm
                anchors.rightMargin: Theme.spaceSm
                verticalAlignment: Text.AlignVCenter
                mono: cell.spec.mono === true && !cell.unknown
                font.pixelSize: Theme.fontSizeLabel
                text: cell.macHidden ? root.macUnavailableText
                                     : (cell.unknown ? qsTr("Unknown") : String(cell.display))
                color: cell.unknown ? Theme.muted : Theme.ink
                Accessible.ignored: true
            }

            HoverHandler {
                id: hover
                onHoveredChanged: {
                    const tip = cell.macHidden && root.macUnavailableDetail.length > 0
                        ? root.macUnavailableDetail : cellText.text
                    if (hover.hovered && (cellText.truncated || tip !== cellText.text)) {
                        cellTip.parent = cell
                        cellTip.text = tip
                        cellTip.open()
                    } else if (cellTip.parent === cell) {
                        cellTip.close()
                    }
                }
            }

            TapHandler {
                onTapped: {
                    table.forceActiveFocus()
                    root.selectRow(cell.row)
                }
                onDoubleTapped: root.hostActivated(cell.row)
            }
        }
    }

    Rectangle {
        // Focus ring around the table body.
        anchors.fill: table
        color: "transparent"
        border.width: Theme.focusRingWidth
        border.color: Theme.accent
        visible: table.activeFocus
    }

    Column {
        objectName: "emptyState"
        anchors.centerIn: table
        width: Math.min(table.width - 2 * Theme.spaceLg, 480)
        spacing: Theme.spaceSm
        visible: table.rows === 0 && (root.emptyTitle.length > 0 || root.emptyBody.length > 0)

        PlainLabel {
            objectName: "emptyTitle"
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: root.emptyTitle
            visible: text.length > 0
            font.pixelSize: Theme.fontSizeHeading
            font.weight: Theme.weightSemiBold
            wrapMode: Text.Wrap
            elide: Text.ElideNone
        }

        PlainLabel {
            objectName: "emptyBody"
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: root.emptyBody
            visible: text.length > 0
            color: Theme.muted
            wrapMode: Text.Wrap
            elide: Text.ElideNone
        }
    }
}
