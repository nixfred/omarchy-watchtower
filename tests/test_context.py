#!/usr/bin/env python3
import json
import os
import pwd
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import watchtower_context as context


class SystemdContextTests(unittest.TestCase):
    def test_derives_unit_from_ss_cgroup_and_parses_batched_show(self):
        details = "users:((\"demo\",pid=42,fd=3)) cgroup:/user.slice/user-1000.slice/user@1000.service/app.slice/demo.service"
        self.assertEqual(context.unit_from_ss_cgroup(details), "demo.service")
        raw = "Id=demo.service\nDescription=Demo worker\nActiveState=active\nSubState=running\nMainPID=42\n\nId=other.socket\nDescription=Other\nActiveState=active\nSubState=listening\nMainPID=0\n"
        self.assertEqual(context.parse_systemctl_show(raw)["demo.service"], {
            "description": "Demo worker", "activeState": "active", "subState": "running", "mainPid": 42,
        })

    def test_unit_parser_rejects_malformed_and_bounds_external_text(self):
        self.assertIsNone(context.unit_from_ss_cgroup("cgroup:/x/not-a-unit"))
        huge = "Id=x.service\nDescription=" + ("z" * 10000) + "\nActiveState=active\n"
        parsed = context.parse_systemctl_show(huge)
        self.assertLessEqual(len(parsed["x.service"]["description"]), context.MAX_TEXT)


class ServiceAndContainerTests(unittest.TestCase):
    def test_registry_labels_are_caveated_and_curated_descriptions_win(self):
        services = "ssh 22/tcp # Secure Shell\nweird 6333/tcp\ninvalid nope/tcp\n"
        self.assertEqual(context.parse_services(services)[("tcp", 22)], "ssh")
        label = context.registry_label(22, "tcp", services_text=services)
        self.assertEqual(label, {"label": "ssh", "caveat": context.REGISTRY_CAVEAT})
        self.assertIn("Secure Shell", context.describe_port(22, "tcp"))
        self.assertIn("DNS", context.describe_port(53, "udp"))
        self.assertIn("KDE Connect", context.describe_port(1716, "udp"))
        self.assertNotIn("Qdrant", context.describe_port(6333, "tcp"))
        self.assertIn("Qdrant", context.describe_port(6333, "tcp", {"image": "qdrant/qdrant"}))

    def test_services_parser_bounds_malformed_and_oversized_input(self):
        raw = "\n".join(f"svc{i} {i}/tcp" for i in range(1, 5000))
        parsed = context.parse_services(raw)
        self.assertLessEqual(len(parsed), context.MAX_ITEMS)
        self.assertNotIn(("tcp", 70000), context.parse_services("bad 70000/tcp"))

    def test_docker_json_maps_host_port_ranges(self):
        raw = "\n".join([
            json.dumps({"Names": "vector-db", "Image": "qdrant/qdrant:v1", "Status": "Up 2 hours", "Ports": "0.0.0.0:6333-6334->6333-6334/tcp"}),
            "not-json",
        ])
        records = context.parse_docker_ps(raw)
        match = context.match_container(records, 6334, "tcp")
        self.assertEqual(match["name"], "vector-db")
        self.assertEqual(match["containerPort"], 6334)
        self.assertNotIn("0.0.0.0", json.dumps(match))

    def test_docker_matching_uses_protocol_port_and_bind_address(self):
        raw = "\n".join([
            json.dumps({"Names": "loopback", "Image": "one", "Status": "Up", "Ports": "127.0.0.1:8080->80/tcp"}),
            json.dumps({"Names": "lan", "Image": "two", "Status": "Up", "Ports": "192.168.1.10:8080->81/tcp"}),
            json.dumps({"Names": "v6-wild", "Image": "three", "Status": "Up", "Ports": "[::]:8080->82/tcp"}),
            json.dumps({"Names": "udp-wild", "Image": "four", "Status": "Up", "Ports": "0.0.0.0:8080->83/udp"}),
        ])
        records = context.parse_docker_ps(raw)
        self.assertEqual(context.match_container(records, 8080, "tcp", "192.168.1.10")["name"], "lan")
        self.assertEqual(context.match_container(records, 8080, "tcp", "2001:db8::5")["name"], "v6-wild")
        self.assertIsNone(context.match_container(records, 8080, "tcp", "10.0.0.2"))
        self.assertEqual(context.match_container(records, 8080, "udp", "10.0.0.2")["name"], "udp-wild")


class FirewallAndConnectionsTests(unittest.TestCase):
    def test_ufw_rules_preserve_comments_and_produce_human_verdicts(self):
        raw = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    192.168.1.0/24 # office only
5353/udp                   ALLOW IN    Anywhere # discovery
6000:6010/tcp              ALLOW IN    Anywhere
"""
        fw = context.parse_ufw_status(raw)
        self.assertTrue(fw["active"])
        self.assertEqual(fw["defaults"]["incoming"], "deny")
        listener = {"host": "10.0.0.4", "interfaces": ["eth0"]}
        self.assertEqual(context.firewall_verdict(fw, 22, "tcp", **listener)["verdict"], "limited")
        self.assertEqual(context.firewall_verdict(fw, 5353, "udp", **listener)["verdict"], "allowed")
        self.assertEqual(context.firewall_verdict(fw, 6005, "tcp", **listener)["verdict"], "allowed")
        self.assertEqual(context.firewall_verdict(fw, 9999, "tcp", **listener)["verdict"], "default-deny")
        docker_verdict = context.firewall_verdict(fw, 6333, "tcp", container_published=True, **listener)
        self.assertEqual(docker_verdict["verdict"], "unknown")
        self.assertIn("Docker", docker_verdict["summary"])
        self.assertNotIn("denied", docker_verdict["summary"].lower())
        self.assertEqual(context.firewall_verdict(fw, 22, "tcp", **listener)["rules"][0]["comment"], "office only")

    def test_ufw_models_family_interface_destination_order_limit_and_uncertainty(self):
        raw = """Status: active
Default: deny (incoming), allow (outgoing), deny (routed)
To                         Action      From
22/tcp on eth0             ALLOW IN    Anywhere
22/tcp (v6)                DENY IN     Anywhere (v6)
10.0.0.4 444/tcp           ALLOW IN    192.168.1.0/24
443/tcp                    LIMIT IN    Anywhere
8080/tcp                   ALLOW IN    Anywhere
8080/tcp                   DENY IN     Anywhere
"""
        fw = context.parse_ufw_status(raw)
        self.assertEqual(context.firewall_verdict(fw, 22, "tcp", host="10.0.0.4", interfaces=["eth0"])["verdict"], "allowed")
        self.assertEqual(context.firewall_verdict(fw, 22, "tcp", host="10.0.0.4", interfaces=["wlan0"])["verdict"], "default-deny")
        self.assertEqual(context.firewall_verdict(fw, 22, "tcp", host="10.0.0.4", interfaces=[])["verdict"], "unknown")
        self.assertEqual(context.firewall_verdict(fw, 22, "tcp", host="2001:db8::4", interfaces=["eth0"])["verdict"], "denied")
        self.assertEqual(context.firewall_verdict(fw, 444, "tcp", host="10.0.0.4", interfaces=["eth0"])["verdict"], "limited")
        self.assertEqual(context.firewall_verdict(fw, 444, "tcp", host="10.0.0.5", interfaces=["eth0"])["verdict"], "default-deny")
        limited = context.firewall_verdict(fw, 443, "tcp", host="10.0.0.5", interfaces=["eth0"])
        self.assertNotEqual(limited["summary"], "Allowed from anywhere")
        self.assertEqual(context.firewall_verdict(fw, 8080, "tcp", host="10.0.0.4", interfaces=["eth0"])["verdict"], "unknown")

        unsupported = context.parse_ufw_status("Status: active\nDefault: deny (incoming)\n22/tcp ALLOW IN Anywhere via magic\n")
        verdict = context.firewall_verdict(unsupported, 22, "tcp", host="10.0.0.4", interfaces=["eth0"])
        self.assertEqual(verdict["verdict"], "unknown")
        self.assertIn("unsupported", verdict["summary"].lower())

    def test_source_specific_deny_does_not_claim_global_protection(self):
        firewall = context.parse_ufw_status("""Status: active
Default: allow (incoming), allow (outgoing), deny (routed)
22/tcp DENY IN 192.168.1.0/24
""")

        verdict = context.firewall_verdict(
            firewall, 22, "tcp", host="10.0.0.4", interfaces=["eth0"]
        )

        self.assertEqual(verdict["verdict"], "unknown")
        self.assertIn("specific source", verdict["summary"].lower())

    def test_ufw_unavailable_or_oversized_is_bounded_and_unknown(self):
        self.assertEqual(context.parse_ufw_status("sudo: a password is required")["active"], None)
        verdict = context.firewall_verdict(context.parse_ufw_status(""), 22, "tcp")
        self.assertEqual(verdict["verdict"], "unknown")
        raw = "Status: active\nDefault: deny (incoming)\n" + ("22/tcp ALLOW IN Anywhere # x\n" * 1000)
        self.assertLessEqual(len(context.parse_ufw_status(raw)["rules"]), context.MAX_ITEMS)

class OwnerAndCollectorTests(unittest.TestCase):
    def test_owner_context_reads_safe_proc_fields_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            pid_dir = proc / "42"
            pid_dir.mkdir()
            (pid_dir / "status").write_text("Name:\tdemo\nUid:\t1234\t1234\t1234\t1234\n")
            fields = ["42", "(demo)", "S"] + ["0"] * 18 + ["5000"] + ["0"] * 3
            (pid_dir / "stat").write_text(" ".join(fields))
            (proc / "uptime").write_text("100.0 0.0\n")
            executable = proc / "demo-bin"
            executable.write_text("")
            (pid_dir / "exe").symlink_to(executable)
            (pid_dir / "cmdline").write_text("demo\x00--token=TOPSECRET")
            (pid_dir / "environ").write_text("SECRET=TOPSECRET")
            with mock.patch.object(context.pwd, "getpwuid", return_value=mock.Mock(pw_name="alice")):
                owner = context.owner_context(42, proc_root=proc, clock_ticks=100)
        self.assertEqual(owner["username"], "alice")
        self.assertEqual(owner["executable"], "demo-bin")
        self.assertEqual(owner["executablePath"], str(executable))
        self.assertEqual(owner["processAgeSeconds"], 50)
        self.assertNotIn("TOPSECRET", json.dumps(owner))
        self.assertNotIn("command", json.dumps(owner).lower())

    def test_collect_context_is_deterministic_timeout_safe_and_falls_back(self):
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            if args[:2] == ["docker", "ps"]:
                return mock.Mock(returncode=0, stdout=json.dumps({"Names": "web", "Image": "nginx", "Status": "Up", "Ports": "0.0.0.0:8080->80/tcp"}), stderr="")
            if args[:3] == ["sudo", "-n", "ufw"]:
                return mock.Mock(returncode=0, stdout="Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n", stderr="")
            if args[0] == "ss":
                raise AssertionError("collector must not request peer-bearing established socket output")
            if args[0] == "systemctl":
                return mock.Mock(returncode=0, stdout="Id=web.service\nDescription=Web Service\nActiveState=active\nSubState=running\nMainPID=0\n", stderr="")
            raise FileNotFoundError

        rows = [{"proto": "tcp", "host": "0.0.0.0", "port": 8080, "cgroup": "/user.slice/app.slice/web.service", "owners": []}]
        first = context.collect_context(rows, runner=runner)
        second = context.collect_context(rows, runner=runner)
        self.assertEqual(first, second)
        key = context.listener_context_key(rows[0])
        self.assertEqual(first[key]["container"]["name"], "web")
        self.assertEqual(first[key]["unit"]["description"], "Web Service")
        self.assertEqual(first[key]["firewall"]["verdict"], "unknown")
        self.assertNotIn("activeCount", first[key]["connections"])
        self.assertIn("privacy", first[key]["connections"]["summary"].lower())
        for args, kwargs in calls:
            self.assertIsInstance(args, list)
            self.assertNotIn("shell", kwargs)
            self.assertLessEqual(kwargs["timeout"], context.COMMAND_TIMEOUT)
        docker_args = next(args for args, _ in calls if args[:2] == ["docker", "ps"])
        docker_format = docker_args[docker_args.index("--format") + 1]
        self.assertNotIn("{{json .}}", docker_format)
        for field in ("Names", "Image", "Status", "Ports"):
            self.assertIn(f".{field}", docker_format)


class ListenerDescriptionTests(unittest.TestCase):
    def test_ui_description_prefers_strong_identity_over_registry_label(self):
        row = {"proto": "tcp", "host": "0.0.0.0", "port": 22, "process": "custom-gateway", "processes": ["custom-gateway"]}
        enrichment = {
            "purpose": "Secure Shell (SSH) remote administration",
            "registry": {"label": "ssh", "caveat": context.REGISTRY_CAVEAT},
            "firewall": {"verdict": "unknown", "summary": "Firewall unavailable", "rules": []},
            "connections": {"activeCount": 2, "summary": "2 active connections"},
            "owners": [{"username": "alice", "executable": "custom-gateway", "executablePath": "/usr/bin/custom-gateway", "processAgeSeconds": 30}],
            "unitName": "custom.service",
            "unit": {"description": "Custom Gateway", "activeState": "active", "subState": "running", "mainPid": 42},
            "container": None,
        }
        view = context.describe_listener(row, enrichment)
        self.assertEqual(view["title"], "Custom Gateway")
        self.assertIn("custom-gateway", view["whatThisIs"])
        self.assertIn("commonly associated", view["whatThisIs"])
        self.assertNotEqual(view["title"].lower(), "ssh")
        self.assertEqual(view["bindSummary"], "Listens on all IPv4 interfaces")
        self.assertEqual(view["firewallSummary"], "Firewall unavailable")
        self.assertIn("alice", view["ownerSummary"])
        self.assertIn("custom.service", view["unitSummary"])
        self.assertEqual(view["containerSummary"], "No matching published container")
        self.assertEqual(view["registryCaveat"], context.REGISTRY_CAVEAT)
        self.assertEqual(view["connectionSummary"], "2 active connections")
        self.assertEqual(view["attentionHint"], "review")

    def test_bind_explanations_and_attention_are_conservative(self):
        cases = {
            "::": "Listens on all IPv6 interfaces",
            "127.0.0.1": "Listens on localhost only",
            "192.168.1.4": "Listens on a LAN address",
            "100.100.1.2": "Listens on a Tailscale address",
            "fd7a:115c:a1e0::1234": "Listens on a Tailscale address",
            "224.0.0.251": "Listens on an IPv4 multicast address",
            "ff02::fb": "Listens on an IPv6 multicast address",
            "::ffff:192.168.1.4": "Listens on a LAN address",
            "::ffff:100.100.1.2": "Listens on a Tailscale address",
        }
        base = {"firewall": {"verdict": "default-deny", "summary": "Denied by default", "rules": []}, "connections": {"activeCount": 0, "summary": "0 active connections"}, "owners": [], "unit": None, "unitName": None, "container": None, "registry": None, "purpose": "Unknown or application-specific service"}
        for host, expected in cases.items():
            with self.subTest(host=host):
                view = context.describe_listener({"proto": "tcp", "host": host, "port": 9999, "process": "unknown"}, base)
                self.assertEqual(view["bindSummary"], expected)
                self.assertIn(view["attentionHint"], {"low", "review"})
                self.assertLessEqual(max(map(len, (str(value) for value in view.values()))), context.MAX_TEXT)

    def test_bridge_scope_resolves_local_address_to_interface_and_fails_conservative(self):
        raw = json.dumps([
            {"ifname": "docker0", "addr_info": [{"local": "172.17.0.1"}]},
            {"ifname": "eth0", "addr_info": [{"local": "192.168.1.4"}]},
        ])
        addresses = context.parse_ip_addresses(raw)
        self.assertEqual(addresses["172.17.0.1"], ["docker0"])
        base = {"firewall": {}, "connections": {}, "owners": [], "unit": None, "unitName": None,
                "container": None, "registry": None, "purpose": "Unknown or application-specific service"}
        bridge = context.describe_listener({"proto": "tcp", "host": "172.17.0.1", "port": 9999},
                                           {**base, "bindInterfaces": ["docker0"]})
        unresolved = context.describe_listener({"proto": "tcp", "host": "172.18.0.1", "port": 9999},
                                               {**base, "bindInterfaces": []})
        self.assertEqual(bridge["bindSummary"], "Listens on private bridge interface docker0")
        self.assertIn("could not be safely classified", unresolved["bindSummary"])
        self.assertEqual(unresolved["attentionHint"], "review")

    def test_unknown_owner_is_not_claimed_as_owned_by_systemd_unit(self):
        row = {"proto": "tcp", "host": "127.0.0.1", "port": 22, "process": "unknown", "processes": ["unknown"]}
        enrichment = {
            "purpose": "Secure Shell (SSH) remote administration",
            "unitName": "ssh.service",
            "unit": {"description": "OpenSSH server", "activeState": "active", "subState": "running"},
            "connections": {}, "firewall": {}, "owners": [], "container": None, "registry": None,
        }
        view = context.describe_listener(row, enrichment)
        self.assertEqual(view["title"], "OpenSSH server")
        self.assertNotIn("Owned by", view["whatThisIs"])
        self.assertIn("systemd", view["whatThisIs"])

    def test_generic_user_manager_does_not_hide_actual_process_identity(self):
        row = {"proto": "udp", "host": "10.0.0.4", "port": 40000, "process": "ChatGPT", "processes": ["ChatGPT"]}
        enrichment = {"purpose": "Unknown or application-specific service", "unitName": "user@1000.service",
                      "unit": {"description": "User Manager for UID 1000", "activeState": "active", "subState": "running"},
                      "connections": {"activeCount": 0, "summary": "0 active connections"},
                      "firewall": {"verdict": "default-deny", "summary": "Denied by default", "rules": []},
                      "owners": [], "container": None, "registry": None}
        self.assertEqual(context.describe_listener(row, enrichment)["title"], "ChatGPT")


if __name__ == "__main__":
    unittest.main()
