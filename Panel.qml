import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "io.github.nixfred.watchtower"
  ipcTarget: moduleName
  manageIpc: false

  property string state: "unknown"
  property int socketCount: 0
  property int exposedCount: 0
  property int untrustedCount: 0
  property var sockets: []
  property string errorText: ""
  property string pendingAction: ""
  property string pendingKey: ""
  property bool scanBusy: false
  property bool actionBusy: false
  property string expandedKey: ""
  readonly property string pluginDir: String(Qt.resolvedUrl(".")).replace(/^file:\/\//, "")
  readonly property int refreshMs: Math.max(5, Number(root.setting("refreshIntervalSec", 15))) * 1000
  readonly property bool includeLocal: Boolean(root.setting("includeLocal", false))
  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.45)
  readonly property color stateColor: state === "alert" ? "#ff4664" : state === "guarded" ? "#35f28b" : state === "quiet" ? "#6b7280" : "#f5c542"
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property var visibleSockets: includeLocal ? sockets : sockets.filter(function(row) { return row.exposed })

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function applyReport(raw) {
    try {
      var data = JSON.parse(String(raw || ""))
      if (data.state === "error") throw new Error(data.error || "Watchtower scan failed")
      state = String(data.state || "unknown")
      socketCount = Number(data.socketCount || 0)
      exposedCount = Number(data.exposedCount || 0)
      untrustedCount = Number(data.untrustedCount || 0)
      sockets = Array.isArray(data.sockets) ? data.sockets : []
      errorText = ""
    } catch (error) {
      state = "error"
      errorText = String(error.message || error)
    }
  }

  function refresh() {
    if (scanBusy || actionBusy) return
    scanProc.begin()
  }

  function setTrusted(key, trusted) {
    if (scanBusy || actionBusy) return
    pendingAction = trusted ? "trust" : "untrust"
    pendingKey = String(key)
    actionProc.begin([root.pluginDir + "/watchtower.py", pendingAction, pendingKey])
  }

  function trustBaseline() {
    if (scanBusy || actionBusy) return
    pendingAction = "baseline"
    pendingKey = ""
    actionProc.begin([root.pluginDir + "/watchtower.py", "baseline"])
  }

  function switchPanel(direction) {
    if (bar && typeof bar.switchPanelFrom === "function") return bar.switchPanelFrom(root, direction)
    return false
  }

  Process {
    id: scanProc
    command: [root.pluginDir + "/watchtower.py", "scan"]
    property int generation: 0
    property int outputGeneration: -1
    property int exitGeneration: -1
    property bool outputReady: false
    property bool exitReady: false
    property int resultCode: -1
    property string response: ""
    function begin() {
      generation += 1
      outputGeneration = -1
      exitGeneration = -1
      outputReady = false
      exitReady = false
      resultCode = -1
      response = ""
      root.scanBusy = true
      running = true
    }
    function finishIfReady(expectedGeneration) {
      if (!root.scanBusy || expectedGeneration !== generation) return
      if (!outputReady || !exitReady) return
      if (outputGeneration !== expectedGeneration || exitGeneration !== expectedGeneration) return
      if (response !== "") root.applyReport(response)
      else root.errorText = "Watchtower scan returned no output"
      if (resultCode !== 0 || response === "") root.state = "error"
      root.scanBusy = false
    }
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var completedGeneration = scanProc.generation
        scanProc.response = text
        scanProc.outputGeneration = completedGeneration
        scanProc.outputReady = true
        scanProc.finishIfReady(completedGeneration)
      }
    }
    stderr: StdioCollector { waitForEnd: true; onStreamFinished: if (text.trim() !== "") root.errorText = text.trim() }
    onExited: function(exitCode) {
      var completedGeneration = generation
      resultCode = exitCode
      exitGeneration = completedGeneration
      exitReady = true
      finishIfReady(completedGeneration)
    }
  }

  Process {
    id: actionProc
    command: []
    property int generation: 0
    property int outputGeneration: -1
    property int exitGeneration: -1
    property bool outputReady: false
    property bool exitReady: false
    property int resultCode: -1
    property string response: ""
    function begin(commandParts) {
      generation += 1
      outputGeneration = -1
      exitGeneration = -1
      outputReady = false
      exitReady = false
      resultCode = -1
      response = ""
      command = commandParts
      root.actionBusy = true
      running = true
    }
    function finishIfReady(expectedGeneration) {
      if (!root.actionBusy || expectedGeneration !== generation) return
      if (!outputReady || !exitReady) return
      if (outputGeneration !== expectedGeneration || exitGeneration !== expectedGeneration) return
      if (resultCode === 0 && response !== "") root.applyReport(response)
      else root.state = "error"
      root.pendingAction = ""
      root.pendingKey = ""
      root.actionBusy = false
    }
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var completedGeneration = actionProc.generation
        actionProc.response = text
        actionProc.outputGeneration = completedGeneration
        actionProc.outputReady = true
        actionProc.finishIfReady(completedGeneration)
      }
    }
    stderr: StdioCollector { waitForEnd: true; onStreamFinished: if (text.trim() !== "") root.errorText = text.trim() }
    onExited: function(exitCode) {
      var completedGeneration = generation
      resultCode = exitCode
      exitGeneration = completedGeneration
      exitReady = true
      finishIfReady(completedGeneration)
    }
  }

  Timer {
    interval: root.refreshMs
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  onOpenedChanged: if (opened) refresh()

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { root.refresh(); return "ok" }
    function status(): string {
      return JSON.stringify({state: root.state, exposed: root.exposedCount, untrusted: root.untrustedCount})
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    tooltipText: root.state === "alert"
      ? root.untrustedCount + " new exposed " + (root.untrustedCount === 1 ? "socket" : "sockets") + " — review now"
      : root.state === "guarded"
        ? root.exposedCount + " reviewed exposed " + (root.exposedCount === 1 ? "socket" : "sockets")
        : root.state === "quiet" ? "Watchtower: no exposed listeners" : "Watchtower: " + (root.errorText || root.state)
    iconComponent: Component {
      Item {
        Text {
          anchors.centerIn: parent
          text: root.state === "alert" ? "󰒃" : "󰒄"
          textFormat: Text.PlainText
          color: root.stateColor
          font.family: root.fontFamily
          font.pixelSize: Style.bar.iconFont
        }
        Rectangle {
          visible: root.untrustedCount > 0
          anchors.right: parent.right
          anchors.top: parent.top
          width: Math.max(Style.space(12), badge.implicitWidth + Style.space(5))
          height: Style.space(12)
          radius: height / 2
          color: "#ff4664"
          Text {
            id: badge
            anchors.centerIn: parent
            text: root.untrustedCount > 99 ? "99+" : String(root.untrustedCount)
            color: "white"
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption * 0.8
            font.bold: true
          }
        }
      }
    }
    onPressed: function(code) {
      if (code === Qt.RightButton) root.refresh()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(560))
    contentHeight: panel.fittedContentHeight(content.implicitHeight, Style.space(650))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(text) { if (text === "r" || text === "R") root.refresh() }

      Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: content.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        ColumnLayout {
          id: content
          width: parent.width
          spacing: Style.space(10)

          PanelHero {
            Layout.fillWidth: true
            title: root.state === "alert" ? root.untrustedCount + " open " + (root.untrustedCount === 1 ? "door" : "doors") : "Perimeter clear"
            meta: root.exposedCount + " exposed · " + root.socketCount + " total listeners"
            detail: root.state === "alert" ? "New listeners are reachable beyond localhost. Review the process before trusting it." : "Watchtower will light up when a new service starts listening beyond localhost."
            foreground: root.stateColor
            fontFamily: root.fontFamily
            iconComponent: Component {
              Text { text: root.state === "alert" ? "󰒃" : "󰒄"; textFormat: Text.PlainText; color: root.stateColor; font.family: root.fontFamily; font.pixelSize: Style.font.display }
            }
          }

          Text {
            Layout.fillWidth: true
            visible: root.errorText !== ""
            text: root.errorText
            textFormat: Text.PlainText
            color: "#ff4664"
            wrapMode: Text.WrapAnywhere
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          PanelSectionHeader { Layout.fillWidth: true; text: root.includeLocal ? "ALL LISTENERS" : "EXPOSED LISTENERS"; foreground: root.foreground; fontFamily: root.fontFamily }

          Button {
            Layout.fillWidth: true
            visible: root.untrustedCount > 1
            text: "Trust current baseline (" + root.untrustedCount + ")"
            enabled: !root.scanBusy && !root.actionBusy
            onClicked: root.trustBaseline()
          }

          Text {
            Layout.fillWidth: true
            visible: root.visibleSockets.length === 0
            text: root.includeLocal ? "No listening sockets detected." : "Nothing is listening beyond localhost."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          Repeater {
            model: root.visibleSockets
            delegate: ListenerCard {
              required property var modelData
              listener: modelData
              expanded: root.expandedKey === String(modelData.key)
              busy: root.scanBusy || root.actionBusy
              foreground: root.foreground
              dim: root.dim
              fontFamily: root.fontFamily
              onToggleDetails: root.expandedKey = expanded ? "" : String(modelData.key)
              onTrustRequested: function(key, shouldTrust) { root.setTrusted(key, shouldTrust) }
            }
          }

          PanelSeparator { Layout.fillWidth: true; foreground: root.foreground }
          Text { Layout.fillWidth: true; text: "Right-click or press R to rescan · Trust only listeners you recognize"; textFormat: Text.PlainText; horizontalAlignment: Text.AlignHCenter; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.WordWrap }
        }
      }
    }
  }
}
