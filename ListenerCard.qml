import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Ui

Rectangle {
  id: root

  property var listener: ({})
  property bool expanded: false
  property bool busy: false
  property color foreground: "white"
  property color dim: "#a1a1aa"
  property string fontFamily: Style.font.family
  readonly property color warning: "#ff4664"

  signal toggleDetails()
  signal trustRequested(string key, bool shouldTrust)

  Layout.fillWidth: true
  implicitWidth: Style.space(480)
  implicitHeight: content.implicitHeight + Style.space(20)
  radius: Style.cornerRadius
  color: Util.alpha(root.foreground, 0.055)
  border.width: listener.exposed && !listener.trusted ? 1 : 0
  border.color: Util.alpha(root.warning, 0.62)

  function clean(value) {
    if (value === undefined || value === null) return ""
    var text = String(value).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim()
    if (text === "" || text.toLowerCase() === "unknown" || text.toLowerCase() === "n/a") return ""
    return text
  }

  function bounded(value, limit) {
    var text = clean(value)
    var maximum = Number(limit || 256)
    return text.length <= maximum ? text : text.slice(0, Math.max(1, maximum - 1)) + "…"
  }

  function pick() {
    for (var i = 0; i < arguments.length; ++i) {
      var text = clean(arguments[i])
      if (text !== "") return text
    }
    return ""
  }

  function objectValue(object, key) {
    return object && typeof object === "object" ? object[key] : undefined
  }

  function titleText() {
    return bounded(pick(listener.friendlyTitle, listener.title, listener.process, "Listener"), 96)
  }

  function purposeText() {
    return bounded(pick(listener.purpose, listener.description), 180)
  }

  function endpointText() {
    var protocol = bounded(listener.proto, 12).toUpperCase()
    var address = bounded(listener.host, 96)
    var port = bounded(listener.port, 8)
    var endpoint = address !== "" && port !== "" ? address + ":" + port : pick(address, port)
    return bounded((protocol + (endpoint !== "" ? "  " + endpoint : "")).trim(), 128)
  }

  function reviewText() {
    var scope = bounded(listener.scope, 48)
    var review = listener.trusted ? "reviewed" : listener.exposed ? "NEW" : ""
    return scope + (scope !== "" && review !== "" ? " · " : "") + review
  }

  function firewallObject() {
    return listener.firewall && typeof listener.firewall === "object" ? listener.firewall : ({})
  }

  function firewallText() {
    var firewall = firewallObject()
    return bounded(pick(firewall.summary, firewall.verdict, listener.firewallSummary, listener.firewallVerdict), 180)
  }

  function firewallRules() {
    var rules = firewallObject().rules
    return Array.isArray(rules) ? rules : []
  }

  function connectionNumber() {
    var value = listener.connectionCount
    if (value === undefined && listener.connections && typeof listener.connections === "object") value = listener.connections.activeCount
    var count = Number(value)
    return isFinite(count) && count >= 0 ? Math.floor(count) : -1
  }

  function connectionText() {
    var count = connectionNumber()
    if (count < 0) return ""
    if (count === 0) return "No active connections"
    return count + " active " + (count === 1 ? "connection" : "connections")
  }

  function unitName() {
    return bounded(pick(listener.unitName, typeof listener.unit === "object" ? listener.unit.name : listener.unit), 160)
  }

  function unitDetail(key, fallback) {
    return bounded(pick(objectValue(listener.unit, key), listener[fallback]), 256)
  }

  function ownerObject() {
    if (listener.owner && typeof listener.owner === "object") return listener.owner
    if (Array.isArray(listener.owners) && listener.owners.length > 0) return listener.owners[0]
    return ({})
  }

  function ownerText() {
    var owner = ownerObject()
    var user = bounded(pick(owner.username, owner.user, listener.ownerUser), 96)
    var pid = bounded(pick(owner.pid, listener.pid), 16)
    var executable = bounded(pick(owner.executable, listener.executable), 256)
    var pieces = []
    if (user !== "") pieces.push("user " + user)
    if (pid !== "") pieces.push("PID " + pid)
    if (executable !== "") pieces.push(executable)
    return pieces.join(" · ")
  }

  function containerObject() {
    return listener.container && typeof listener.container === "object" ? listener.container : ({})
  }

  function containerText() {
    var container = containerObject()
    var name = bounded(container.name, 128)
    var image = bounded(container.image, 256)
    var status = bounded(container.status, 256)
    var pieces = []
    if (name !== "") pieces.push(name)
    if (image !== "") pieces.push(image)
    if (status !== "") pieces.push(status)
    return pieces.join(" · ")
  }

  function registryObject() {
    return listener.registry && typeof listener.registry === "object" ? listener.registry : ({})
  }

  function ruleText(rule) {
    if (!rule || typeof rule !== "object") return bounded(rule, 180)
    return bounded(pick(rule.comment, rule.summary, rule.action), 180)
  }

  ColumnLayout {
    id: content
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.top: parent.top
    anchors.margins: Style.space(10)
    spacing: Style.space(7)

    RowLayout {
      Layout.fillWidth: true
      spacing: Style.space(9)

      Text {
        text: root.listener.exposed && !root.listener.trusted ? "󰀦" : root.listener.exposed ? "󰌾" : "󰌿"
        textFormat: Text.PlainText
        color: root.listener.exposed && !root.listener.trusted ? root.warning : root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.title
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: 1

        Text {
          Layout.fillWidth: true
          text: root.titleText()
          textFormat: Text.PlainText
          color: root.foreground
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.bold: true
          font.pixelSize: Style.font.body
        }
        Text {
          Layout.fillWidth: true
          visible: text !== ""
          text: root.purposeText()
          textFormat: Text.PlainText
          color: root.dim
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
    }

    Text {
      Layout.fillWidth: true
      text: root.bounded(root.listener.process, 128) + (root.bounded(root.listener.process, 128) !== "" && root.endpointText() !== "" ? " · " : "") + root.endpointText()
      textFormat: Text.PlainText
      color: root.foreground
      elide: Text.ElideMiddle
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
    }

    RowLayout {
      Layout.fillWidth: true
      spacing: Style.space(8)
      Text {
        Layout.fillWidth: true
        text: root.reviewText()
        textFormat: Text.PlainText
        color: root.listener.exposed && !root.listener.trusted ? root.warning : root.dim
        elide: Text.ElideRight
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: root.listener.exposed && !root.listener.trusted
      }
      Text {
        visible: text !== ""
        text: root.connectionText()
        textFormat: Text.PlainText
        color: root.dim
        elide: Text.ElideRight
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }

    Text {
      Layout.fillWidth: true
      visible: text !== ""
      text: root.firewallText()
      textFormat: Text.PlainText
      color: root.firewallText().toLowerCase().indexOf("allow") >= 0 ? root.warning : root.dim
      wrapMode: Text.WordWrap
      maximumLineCount: root.expanded ? 3 : 1
      elide: Text.ElideRight
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }

    ColumnLayout {
      Layout.fillWidth: true
      visible: root.expanded
      spacing: Style.space(6)

      Text {
        Layout.fillWidth: true
        visible: root.bounded(root.listener.description, 256) !== ""
        text: "What it is — " + root.bounded(root.listener.description, 256)
        textFormat: Text.PlainText
        color: root.foreground
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        Layout.fillWidth: true
        visible: root.bounded(root.listener.bindExplanation, 256) !== ""
        text: "Bind — " + root.bounded(root.listener.bindExplanation, 256)
        textFormat: Text.PlainText
        color: root.foreground
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        Layout.fillWidth: true
        visible: root.unitName() !== ""
        text: "Unit — " + root.unitName()
        textFormat: Text.PlainText
        color: root.foreground
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        Layout.fillWidth: true
        visible: text !== ""
        text: {
          var description = root.unitDetail("description", "unitDescription")
          var active = root.unitDetail("activeState", "activeState")
          return (description !== "" ? description : "") + (description !== "" && active !== "" ? " · " : "") + (active !== "" ? "State: " + active : "")
        }
        textFormat: Text.PlainText
        color: root.dim
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
      Text {
        Layout.fillWidth: true
        visible: root.ownerText() !== ""
        text: "Owner — " + root.ownerText()
        textFormat: Text.PlainText
        color: root.foreground
        wrapMode: Text.WrapAnywhere
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        Layout.fillWidth: true
        visible: root.containerText() !== ""
        text: "Docker — " + root.containerText()
        textFormat: Text.PlainText
        color: root.foreground
        wrapMode: Text.WrapAnywhere
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        Layout.fillWidth: true
        visible: root.bounded(root.registryObject().label, 64) !== ""
        text: "Port registry — " + root.bounded(root.registryObject().label, 64)
        textFormat: Text.PlainText
        color: root.foreground
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        Layout.fillWidth: true
        visible: root.bounded(root.registryObject().caveat, 256) !== ""
        text: root.bounded(root.registryObject().caveat, 256)
        textFormat: Text.PlainText
        color: root.dim
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
      Text {
        Layout.fillWidth: true
        visible: root.firewallText() !== ""
        text: "Firewall — " + root.firewallText()
        textFormat: Text.PlainText
        color: root.firewallText().toLowerCase().indexOf("allow") >= 0 ? root.warning : root.foreground
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Repeater {
        model: Math.min(root.firewallRules().length, 3)
        delegate: Text {
          required property int index
          Layout.fillWidth: true
          visible: root.ruleText(root.firewallRules()[index]) !== ""
          text: "Rule note — " + root.ruleText(root.firewallRules()[index])
          textFormat: Text.PlainText
          color: root.dim
          wrapMode: Text.WordWrap
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }
      Text {
        Layout.fillWidth: true
        visible: root.connectionText() !== ""
        text: "Connections — " + root.connectionText()
        textFormat: Text.PlainText
        color: root.foreground
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        Layout.fillWidth: true
        visible: root.bounded(root.listener.attention, 256) !== ""
        text: "Attention — " + root.bounded(root.listener.attention, 256)
        textFormat: Text.PlainText
        color: root.warning
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.bold: true
        font.pixelSize: Style.font.bodySmall
      }
      Text {
        Layout.fillWidth: true
        visible: root.bounded(root.listener.recommendation, 256) !== ""
        text: "Recommendation — " + root.bounded(root.listener.recommendation, 256)
        textFormat: Text.PlainText
        color: root.foreground
        wrapMode: Text.WordWrap
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
      }
    }

    RowLayout {
      Layout.fillWidth: true
      spacing: Style.space(8)
      Item { Layout.fillWidth: true }
      Button {
        text: root.expanded ? "Less" : "Details"
        onClicked: root.toggleDetails()
      }
      Button {
        visible: root.clean(root.listener.key) !== ""
        text: root.listener.trusted ? "Untrust" : "Trust"
        enabled: !root.busy && root.listener.trustable
        onClicked: root.trustRequested(String(root.listener.key), !root.listener.trusted)
      }
    }
  }
}
