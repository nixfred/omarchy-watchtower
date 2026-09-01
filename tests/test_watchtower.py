#!/usr/bin/env python3
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import watchtower


def add_trusted_key(path, key):
    watchtower.update_trusted(Path(path), key, True)


class WatchtowerTests(unittest.TestCase):
    def test_parse_ss_handles_ipv4_ipv6_and_process_names(self):
        raw = '''tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=700,fd=3))
tcp LISTEN 0 4096 [::1]:631 [::]:* users:(("cupsd",pid=44,fd=7))
udp UNCONN 0 0 *:1716 *:* users:(("kdeconnectd",pid=88,fd=9))'''
        rows = watchtower.parse_ss(raw)
        self.assertEqual(rows[0]["host"], "0.0.0.0")
        self.assertEqual(rows[0]["port"], 22)
        self.assertEqual(rows[0]["process"], "sshd")
        self.assertEqual(rows[1]["host"], "::1")
        self.assertEqual(rows[2]["host"], "*")
        self.assertEqual(rows[2]["port"], 1716)

    def test_parse_ss_rejects_malformed_nonempty_rows_instead_of_hiding_listener(self):
        raw = '''tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=700,fd=3))
tcp LISTEN malformed-row'''

        with self.assertRaisesRegex(ValueError, "malformed ss row 2"):
            watchtower.parse_ss(raw)

    def test_parse_ss_rejects_every_invalid_required_field(self):
        malformed = {
            "missing peer endpoint": "tcp LISTEN 0 4096 0.0.0.0:22",
            "unsupported protocol": "garbage LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*",
            "invalid state": "tcp WRONG 0 4096 0.0.0.0:22 0.0.0.0:*",
            "nonnumeric receive queue": "tcp LISTEN NaN 4096 0.0.0.0:22 0.0.0.0:*",
            "nonnumeric send queue": "tcp LISTEN 0 NaN 0.0.0.0:22 0.0.0.0:*",
            "invalid peer endpoint": "tcp LISTEN 0 4096 0.0.0.0:22 peer-without-port",
        }
        for label, row in malformed.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "malformed ss row 1"):
                    watchtower.parse_ss(row)

    def test_parse_ss_rejects_malformed_endpoint_hosts(self):
        invalid_rows = {
            "local hostname": "tcp LISTEN 0 4096 not-an-address:22 0.0.0.0:*",
            "local unmatched bracket": "tcp LISTEN 0 4096 [::1:22 0.0.0.0:*",
            "local empty host": "tcp LISTEN 0 4096 :22 0.0.0.0:*",
            "peer hostname": "tcp LISTEN 0 4096 0.0.0.0:22 not-an-address:*",
            "peer unmatched bracket": "tcp LISTEN 0 4096 0.0.0.0:22 [::1:*",
            "peer empty host": "tcp LISTEN 0 4096 0.0.0.0:22 :*",
            "invalid IPv6 scope": "udp UNCONN 0 0 [fe80::1%bad/scope]:5353 [::]:*",
        }
        for name, row in invalid_rows.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    watchtower.parse_ss(row)

        valid = watchtower.parse_ss(
            "udp UNCONN 0 0 [fe80::1%wlan0]:5353 [::]:*\n"
            "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*"
        )
        self.assertEqual(valid[0]["host"], "fe80::1%wlan0")
        self.assertEqual(valid[1]["host"], "127.0.0.53%lo")

    def test_parse_ss_reports_every_process_owner(self):
        raw = 'tcp LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:* users:(("beta",pid=2,fd=4),("alpha",pid=1,fd=3))'
        self.assertEqual(watchtower.parse_ss(raw)[0]["process"], "alpha, beta")

    def test_multiple_owner_blocks_make_ownership_incomplete(self):
        raw = 'tcp LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:* users:(("trusted",pid=1,fd=3)) users:(("hidden",pid=2,fd=4))'

        row = watchtower.parse_ss(raw)[0]

        self.assertEqual(row["processes"], [])
        self.assertEqual(row["owners"], [])
        self.assertFalse(row["ownershipComplete"])

    def test_parse_ss_preserves_cgroup_without_confusing_owner_parser(self):
        raw = 'tcp LISTEN 0 4096 0.0.0.0:5900 0.0.0.0:* users:(("wayvnc",pid=1641,fd=10)) uid:1000 cgroup:/user.slice/app.slice/wayvnc.service <->'
        row = watchtower.parse_ss(raw)[0]
        self.assertEqual(row["processes"], ["wayvnc"])
        self.assertTrue(row["ownershipComplete"])
        self.assertEqual(row["cgroup"], "/user.slice/app.slice/wayvnc.service")

    def test_malformed_owner_list_cannot_trust_partially_parsed_owner_set(self):
        raw = r'tcp LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:* users:(("alpha",pid=1,fd=3),("broken\",pid=2,fd=4))'
        row = watchtower.parse_ss(raw)[0]
        partial_key = watchtower.socket_key(row)

        report = watchtower.summarize([row], {partial_key})

        self.assertEqual(row["processes"], [])
        self.assertFalse(report["sockets"][0]["trustable"])
        self.assertFalse(report["sockets"][0]["trusted"])

    def test_owner_list_with_dangling_entry_fails_closed(self):
        raw = 'tcp LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:* users:(("alpha",pid=1,fd=3),)'

        row = watchtower.parse_ss(raw)[0]
        report_row = watchtower.summarize([row], {watchtower.socket_key(row)})["sockets"][0]

        self.assertEqual(row["processes"], [])
        self.assertFalse(report_row["trustable"])
        self.assertFalse(report_row["trusted"])

    def test_escaped_owner_names_preserve_pid_and_fd_metadata(self):
        raw = r'tcp LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:* users:(("quote\"name",pid=999999998,fd=4),("slash\\name",pid=999999999,fd=3))'

        row = watchtower.parse_ss(raw)[0]
        report_row = watchtower.summarize([row], set())["sockets"][0]

        self.assertEqual(row["processes"], ['quote"name', "slash\\name"])
        self.assertEqual(
            report_row["owners"],
            [
                {"name": 'quote"name', "pid": 999999998, "fd": 4},
                {"name": "slash\\name", "pid": 999999999, "fd": 3},
            ],
        )
        self.assertTrue(report_row["ownershipComplete"])
        self.assertFalse(report_row["trustable"])

    def test_parse_ss_resolves_owner_uid_and_executable_for_trust_identity(self):
        pid = os.getpid()
        executable = os.readlink(f"/proc/{pid}/exe")
        raw = (f'tcp LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:* '
               f'users:(("spoofable-name",pid={pid},fd=3)) uid:{os.getuid()}')

        row = watchtower.parse_ss(raw)[0]
        report_row = watchtower.summarize([row], set())["sockets"][0]

        self.assertEqual(row["owners"][0]["uid"], os.getuid())
        self.assertEqual(row["owners"][0]["executable"], executable)
        self.assertTrue(report_row["trustable"])

    def test_trust_identity_uses_uid_and_executable_not_spoofable_process_name(self):
        base = {"proto": "tcp", "host": "0.0.0.0", "port": 9000,
                "process": "trusted-service", "processes": ["trusted-service"],
                "ownershipComplete": True}
        trusted_owner = {**base, "owners": [{"name": "trusted-service", "pid": 1, "fd": 3,
                                                "uid": 1000, "executable": "/usr/bin/trusted-service"}]}
        spoofed_owner = {**base, "owners": [{"name": "trusted-service", "pid": 2, "fd": 4,
                                                "uid": 1001, "executable": "/tmp/trusted-service"}]}

        trusted_key = watchtower.socket_key(trusted_owner)
        spoofed = watchtower.summarize([spoofed_owner], {trusted_key})["sockets"][0]

        self.assertTrue(trusted_key.split("|", 3)[3].startswith("identity-v3:"))
        self.assertNotEqual(trusted_key, watchtower.socket_key(spoofed_owner))
        self.assertFalse(spoofed["trusted"])

    def test_process_name_changes_do_not_change_canonical_trust_identity(self):
        first = {"proto": "tcp", "host": "0.0.0.0", "port": 9000, "process": "alpha",
                 "processes": ["alpha"], "ownershipComplete": True,
                 "owners": [{"name": "alpha", "pid": 1, "fd": 3,
                              "uid": 1000, "executable": "/usr/bin/service"}]}
        second = {**first, "process": "attacker-selected-name", "processes": ["attacker-selected-name"],
                  "owners": [{"name": "attacker-selected-name", "pid": 2, "fd": 4,
                              "uid": 1000, "executable": "/usr/bin/service"}]}

        self.assertEqual(watchtower.socket_key(first), watchtower.socket_key(second))

    def test_classify_bind_distinguishes_scope(self):
        cases = {
            "127.0.0.1": "loopback", "::1": "loopback",
            "0.0.0.0": "all", "::": "all", "*": "all",
            "10.0.0.4": "lan", "192.168.1.8": "lan",
            "100.101.102.103": "tailscale", "172.17.0.1": "lan",
            "0.0.0.0%virbr0": "private", "0.0.0.0%incusbr0": "private",
            "224.0.0.251": "multicast",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(watchtower.classify_bind(host), expected)

    def test_classify_bind_distinguishes_lan_ranges(self):
        for host in ("172.16.0.5", "172.31.255.254", "fd00::1", "fdff::1"):
            with self.subTest(host=host):
                self.assertEqual(watchtower.classify_bind(host), "lan")

    def test_classify_bind_uses_embedded_ipv4_scope_for_mapped_ipv6(self):
        cases = {
            "::ffff:127.0.0.1": "loopback",
            "::ffff:10.0.0.4": "lan",
            "::ffff:192.168.1.8": "lan",
            "::ffff:100.101.102.103": "tailscale",
            "::ffff:8.8.8.8": "public",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(watchtower.classify_bind(host), expected)

    def test_classify_bind_recognizes_tailscale_ipv6(self):
        self.assertEqual(
            watchtower.classify_bind("fd7a:115c:a1e0::1234"),
            "tailscale",
        )

    def test_summarize_alerts_only_on_untrusted_exposures(self):
        rows = [
            {"proto":"tcp","host":"127.0.0.1","port":8000,"process":"dev", "processes": ["dev"],
             "owners": [{"name": "dev", "pid": 1, "fd": 3, "uid": 1000, "executable": "/usr/bin/dev"}]},
            {"proto":"tcp","host":"0.0.0.0","port":22,"process":"sshd", "processes": ["sshd"],
             "owners": [{"name": "sshd", "pid": 2, "fd": 3, "uid": 0, "executable": "/usr/bin/sshd"}]},
            {"proto":"udp","host":"224.0.0.251","port":5353,"process":"avahi", "processes": ["avahi"],
             "owners": [{"name": "avahi", "pid": 3, "fd": 3, "uid": 980, "executable": "/usr/bin/avahi-daemon"}]},
        ]
        report = watchtower.summarize(rows, trusted=set())
        self.assertEqual(report["state"], "alert")
        self.assertEqual(report["exposedCount"], 1)
        self.assertEqual(report["untrustedCount"], 1)
        key = next(row["key"] for row in report["sockets"] if row["exposed"])
        trusted = watchtower.summarize(rows, trusted={key})
        self.assertEqual(trusted["state"], "guarded")
        self.assertEqual(trusted["untrustedCount"], 0)

    def test_duplicate_socket_rows_are_collapsed(self):
        row = {"proto":"tcp","host":"0.0.0.0","port":6333,"process":"docker-proxy"}
        report = watchtower.summarize([row, dict(row)], trusted=set())
        self.assertEqual(len(report["sockets"]), 1)

    def test_duplicate_identity_merges_conflicting_completeness_fail_closed_in_any_order(self):
        complete = {"proto": "tcp", "host": "0.0.0.0", "port": 6333,
                    "process": "service", "processes": ["service"], "ownershipComplete": True,
                    "owners": [{"name": "service", "pid": 1, "fd": 3,
                                "uid": 1000, "executable": "/usr/bin/service"}]}
        conflicting = {**complete, "ownershipComplete": False}
        key = watchtower.socket_key(complete)

        forward = watchtower.summarize([complete, conflicting], {key})
        reverse = watchtower.summarize([conflicting, complete], {key})

        self.assertEqual(forward["sockets"], reverse["sockets"])
        self.assertEqual(len(forward["sockets"]), 1)
        self.assertFalse(forward["sockets"][0]["trustable"])
        self.assertFalse(forward["sockets"][0]["trusted"])

    def test_high_port_udp_listener_on_lan_raises_alarm(self):
        row = {"proto":"udp","host":"10.0.0.4","port":48909,"process":"service"}
        report = watchtower.summarize([row], trusted=set())
        self.assertEqual(report["state"], "alert")
        self.assertEqual(report["untrustedCount"], 1)
        self.assertFalse(report["sockets"][0]["transient"])

    def test_missing_process_identity_cannot_inherit_trust(self):
        row = {"proto":"tcp","host":"0.0.0.0","port":9000,"process":"unknown"}
        key = watchtower.socket_key(row)
        report = watchtower.summarize([row], {key})
        self.assertEqual(report["state"], "alert")
        self.assertFalse(report["sockets"][0]["trusted"])

    def test_socket_keys_escape_unusual_process_names(self):
        row = {"proto":"tcp","host":"0.0.0.0","port":8443,"process":"service worker|blue",
               "processes": ["service worker|blue"], "ownershipComplete": True,
               "owners": [{"name": "service worker|blue", "pid": 1, "fd": 3,
                            "uid": 1000, "executable": "/opt/service worker|blue"}]}
        key = watchtower.socket_key(row)
        self.assertEqual(watchtower.validate_key(key), key)
        self.assertEqual(watchtower.summarize([row], {key})["state"], "guarded")

    def test_legacy_trust_store_is_not_silently_migrated_to_new_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trusted.json"
            path.write_text(json.dumps({"version": 1, "trusted": ["tcp|0.0.0.0|22|sshd"]}))

            self.assertEqual(watchtower.load_trusted(path), set())

    def test_trust_store_round_trip_and_rejects_invalid_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trusted.json"
            key = "tcp|0.0.0.0|22|sshd"
            watchtower.save_trusted(path, {key})
            self.assertEqual(watchtower.load_trusted(path), {key})
            with self.assertRaises(ValueError):
                watchtower.validate_key("bad\nkey")

    def test_concurrent_trust_updates_preserve_every_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trusted.json"
            keys = {f"tcp|0.0.0.0|{port}|svc{port}" for port in range(41000, 41016)}
            context = multiprocessing.get_context("fork")
            workers = [context.Process(target=add_trusted_key, args=(path, key)) for key in keys]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(10)
                self.assertEqual(worker.exitcode, 0)
            self.assertEqual(watchtower.load_trusted(path), keys)

    def test_qml_process_state_machine_prevents_cross_generation_pairing(self):
        panel = (ROOT / "Panel.qml").read_text()

        self.assertIn("property bool scanBusy: false", panel)
        self.assertIn("property bool actionBusy: false", panel)
        self.assertEqual(panel.count("if (scanBusy || actionBusy) return"), 3)
        self.assertEqual(panel.count("!root.scanBusy && !root.actionBusy"), 1)
        self.assertIn("busy: root.scanBusy || root.actionBusy", panel)
        self.assertNotIn("enabled: !actionProc.running && !scanProc.running", panel)

        self.assertEqual(panel.count("function finishIfReady(expectedGeneration)"), 2)
        self.assertEqual(panel.count("if (!outputReady || !exitReady) return"), 2)
        self.assertEqual(
            panel.count("if (outputGeneration !== expectedGeneration || exitGeneration !== expectedGeneration) return"),
            2,
        )
        self.assertIn("if (!root.scanBusy || expectedGeneration !== generation) return", panel)
        self.assertIn("if (!root.actionBusy || expectedGeneration !== generation) return", panel)
        self.assertEqual(panel.count("root.scanBusy = false"), 1)
        self.assertEqual(panel.count("root.actionBusy = false"), 1)
        self.assertIn("root.scanBusy = true\n      running = true", panel)
        self.assertIn("root.actionBusy = true\n      running = true", panel)

    def test_report_enrichment_is_merged_into_ui_ready_listener_rows(self):
        rows = [{"proto": "tcp", "host": "0.0.0.0", "port": 5900,
                 "process": "wayvnc", "processes": ["wayvnc"],
                 "owners": [{"name": "wayvnc", "pid": 1641, "fd": 10}],
                 "ownershipComplete": True, "cgroup": "/user.slice/app.slice/wayvnc.service"}]
        base = watchtower.summarize(rows, set())
        key = base["sockets"][0]["key"]
        enrichment = {key: {
            "purpose": "Virtual Network Computing (VNC) remote desktop",
            "unitName": "wayvnc.service",
            "unit": {"description": "wayvnc VNC server", "activeState": "active", "subState": "running"},
            "container": None,
            "firewall": {"verdict": "limited", "summary": "Limited to LAN and Tailscale", "rules": []},
            "connections": {"activeCount": 1, "summary": "1 active connection"},
            "owners": [{"pid": 1641, "username": "pi", "executable": "wayvnc", "executablePath": "/usr/bin/wayvnc", "processAgeSeconds": 60}],
            "registry": {"label": "rfb", "caveat": "Registry label only"},
        }}
        listener = watchtower.enrich_report(base, enrichment)["sockets"][0]
        self.assertEqual(listener["friendlyTitle"], "wayvnc VNC server")
        self.assertEqual(listener["purpose"], "Virtual Network Computing (VNC) remote desktop")
        self.assertEqual(listener["connections"]["activeCount"], 1)
        self.assertEqual(listener["unitName"], "wayvnc.service")
        self.assertIn("LAN and Tailscale", listener["firewallSummary"])
        self.assertTrue(listener["recommendation"])

    def test_bridge_only_enrichment_removes_false_exposure_and_recounts_report(self):
        row = {
            "proto": "tcp", "host": "172.17.0.1", "port": 8080,
            "process": "dockerd", "processes": ["dockerd"],
            "owners": [{"name": "dockerd", "pid": 1, "fd": 3,
                        "uid": 0, "executable": "/usr/bin/dockerd"}],
            "ownershipComplete": True, "cgroup": "",
            "key": "tcp|172.17.0.1|8080|identity-v3:test",
            "scope": "lan", "transient": False, "exposed": True,
            "trustable": True, "trusted": False,
        }
        report = {"state": "alert", "socketCount": 1, "exposedCount": 1,
                  "untrustedCount": 1, "sockets": [row]}
        enrichment = {row["key"]: {
            "bindInterfaces": ["docker0"],
            "firewall": {"verdict": "unknown", "summary": "Unknown", "rules": []},
        }}

        enriched = watchtower.enrich_report(report, enrichment)

        self.assertEqual(enriched["sockets"][0]["scope"], "private")
        self.assertFalse(enriched["sockets"][0]["exposed"])
        self.assertEqual(enriched["exposedCount"], 0)
        self.assertEqual(enriched["untrustedCount"], 0)
        self.assertEqual(enriched["state"], "quiet")

    def test_readme_documents_current_trust_identity_version(self):
        readme = (ROOT / "README.md").read_text()
        manifest = json.loads((ROOT / "manifest.json").read_text())
        self.assertIn("identity-v3", readme)
        self.assertNotIn("owners-v2", readme)
        self.assertIn("re-baseline", readme.lower())
        self.assertNotIn("active-connection count", readme)
        self.assertIn("does not collect established-connection records", readme)
        self.assertNotIn("active-use context", manifest["description"])
        self.assertNotIn("bounded output from `ss`", readme)

    def test_panel_uses_expandable_listener_cards(self):
        panel = (ROOT / "Panel.qml").read_text()
        self.assertIn("property string expandedKey", panel)
        self.assertIn("ListenerCard {", panel)
        self.assertIn("expanded: root.expandedKey === String(modelData.key)", panel)
        self.assertIn("onToggleDetails:", panel)
        self.assertIn("onTrustRequested:", panel)

    def test_cli_scan_is_machine_readable(self):
        sample = "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\\\"sshd\\\",pid=700,fd=3))"
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "XDG_STATE_HOME": tmp, "WATCHTOWER_SS_FIXTURE": sample, "WATCHTOWER_DISABLE_CONTEXT": "1"}
            result = subprocess.run(
                [sys.executable, str(ROOT / "watchtower.py"), "scan"],
                text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["untrustedCount"], 1)
            self.assertEqual(report["state"], "alert")

    def test_cli_baseline_trusts_current_exposures(self):
        sample = (f'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* '
                  f'users:(("sshd",pid={os.getpid()},fd=3)) uid:{os.getuid()}')
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "XDG_STATE_HOME": tmp, "WATCHTOWER_SS_FIXTURE": sample, "WATCHTOWER_DISABLE_CONTEXT": "1"}
            result = subprocess.run(
                [sys.executable, str(ROOT / "watchtower.py"), "baseline"],
                text=True, capture_output=True, env=env, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["state"], "guarded")
            self.assertEqual(report["untrustedCount"], 0)


if __name__ == "__main__":
    unittest.main()
