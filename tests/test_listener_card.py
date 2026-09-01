#!/usr/bin/env python3
"""Static contract tests for the reusable listener detail card."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CARD = ROOT / "ListenerCard.qml"


class ListenerCardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qml = CARD.read_text(encoding="utf-8")

    def test_component_exposes_listener_card_api(self):
        for declaration in (
            "property var listener",
            "property bool expanded",
            "property bool busy",
            "property color foreground",
            "property color dim",
            "property string fontFamily",
            "signal toggleDetails()",
            "signal trustRequested(string key, bool shouldTrust)",
        ):
            self.assertIn(declaration, self.qml)
        self.assertRegex(self.qml, r"implicitHeight\s*:\s*content\.implicitHeight")
        self.assertIn("Layout.fillWidth: true", self.qml)

    def test_compact_summary_contains_identity_endpoint_and_security_state(self):
        for field in (
            "friendlyTitle", "purpose", "process", "proto", "host", "port",
            "scope", "trusted", "firewall", "connectionCount",
        ):
            self.assertRegex(self.qml, rf'\b{field}\b', field)
        self.assertIn('"NEW"', self.qml)
        self.assertIn('"reviewed"', self.qml)
        self.assertIn('"No active connections"', self.qml)

    def test_expanded_details_cover_bounded_context_and_hide_unknowns(self):
        for field in (
            "description", "bindExplanation", "unit", "unitDescription",
            "activeState", "ownerUser", "pid", "executable", "container",
            "registry", "caveat", "firewall", "rules", "connectionCount",
            "attention", "recommendation",
        ):
            self.assertRegex(self.qml, rf'\b{field}\b', field)
        self.assertRegex(self.qml, r"Math\.min\([^\n]*[Rr]ules[^\n]*3")
        self.assertRegex(self.qml, r"visible\s*:\s*root\.expanded")
        self.assertIn("function clean", self.qml)
        self.assertIn("function bounded", self.qml)

    def test_text_is_plain_wrapped_or_elided_and_warnings_are_unambiguous(self):
        text_blocks = len(re.findall(r"\bText\s*\{", self.qml))
        self.assertGreaterEqual(text_blocks, 6)
        self.assertEqual(text_blocks, self.qml.count("textFormat: Text.PlainText"))
        self.assertIn("Text.WordWrap", self.qml)
        self.assertRegex(self.qml, r'Text\.Elide(?:Middle|Right)')
        self.assertIn('readonly property color warning: "#ff4664"', self.qml)
        self.assertIn("Style.space(", self.qml)
        self.assertIn("Util.alpha(", self.qml)

    def test_controls_emit_signals_and_preserve_guards(self):
        self.assertIn('text: root.expanded ? "Less" : "Details"', self.qml)
        self.assertIn("onClicked: root.toggleDetails()", self.qml)
        self.assertIn('text: root.listener.trusted ? "Untrust" : "Trust"', self.qml)
        self.assertRegex(self.qml, r"enabled\s*:\s*!root\.busy\s*&&\s*root\.listener\.trustable")
        self.assertIn("root.trustRequested(String(root.listener.key), !root.listener.trusted)", self.qml)

    def test_accepts_context_enrichment_shape(self):
        self.assertIn("listener.connections.activeCount", self.qml)
        self.assertIn("listener.unitName", self.qml)
        self.assertIn("owner.username", self.qml)
        self.assertIn("listener.owners[0]", self.qml)
        self.assertIn("firewall.verdict", self.qml)

    def test_unknown_optional_values_do_not_leave_empty_labels(self):
        self.assertRegex(
            self.qml,
            r'visible:\s*root\.bounded\(root\.listener\.description, 256\) !== ""',
        )
        self.assertRegex(
            self.qml,
            r'visible:\s*root\.bounded\(root\.listener\.bindExplanation, 256\) !== ""',
        )
        self.assertRegex(
            self.qml,
            r'visible:\s*root\.ruleText\(root\.firewallRules\(\)\[index\]\) !== ""',
        )

    def test_privacy_sensitive_values_are_never_rendered(self):
        lowered = self.qml.lower()
        for forbidden in ("commandline", "command line", "environment", "remotepeer", "remote peer"):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
