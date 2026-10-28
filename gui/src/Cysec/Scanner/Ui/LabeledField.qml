// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

import QtQuick
import QtQuick.Layouts

// A caption above an input control and an optional error line below it.
// The control goes in as the default child; the caption and error text are
// wired to its accessibility name and description.
ColumnLayout {
    id: field

    property string label: ""
    property string errorText: ""
    default property alias control: slot.data
    readonly property bool hasError: errorText.length > 0

    spacing: Theme.spaceXs
    Accessible.name: field.label
    Accessible.description: field.errorText

    PlainLabel {
        Layout.fillWidth: true
        text: field.label
        color: Theme.muted
        font.pixelSize: Theme.fontSizeBody
        font.weight: Theme.weightSemiBold
        wrapMode: Text.Wrap
        elide: Text.ElideNone
        visible: text.length > 0
    }

    Item {
        id: slot
        Layout.fillWidth: true
        implicitHeight: childrenRect.height
        implicitWidth: childrenRect.width

        onChildrenChanged: field.wireChildren()
    }

    PlainLabel {
        Layout.fillWidth: true
        text: field.errorText
        color: Theme.errorText
        font.pixelSize: Theme.fontSizeLabel
        wrapMode: Text.Wrap
        elide: Text.ElideNone
        visible: field.hasError
    }

    function wireChildren() {
        for (let i = 0; i < slot.children.length; ++i) {
            const child = slot.children[i]
            child.width = Qt.binding(function() { return slot.width })
            if (!child.Accessible.name)
                child.Accessible.name = Qt.binding(function() { return field.label })
            child.Accessible.description = Qt.binding(function() { return field.errorText })
        }
    }
}
