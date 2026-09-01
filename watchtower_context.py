#!/usr/bin/env python3
"""Bounded, privacy-conscious listener context helpers for Watchtower."""
from __future__ import annotations

import ipaddress
import json
import os
import pwd
import re
import socket
import subprocess
from pathlib import Path
from typing import Any

MAX_TEXT = 256
MAX_ITEMS = 128
MAX_INPUT = 1_000_000
COMMAND_TIMEOUT = 5
REGISTRY_CAVEAT = "Registry label only; it does not identify the application actually listening."
_UNIT_RE = re.compile(r"(?:^|/)([A-Za-z0-9_.@:-]{1,200}\.(?:service|socket))(?=$|[\s/])")


def _text(value: object, limit: int = MAX_TEXT) -> str:
    return str(value).replace("\x00", "")[:limit]


def unit_from_ss_cgroup(details: str) -> str | None:
    """Return the most specific service/socket unit in an ss cgroup field."""
    matches = _UNIT_RE.findall(str(details)[:MAX_INPUT])
    return matches[-1] if matches else None


def parse_systemctl_show(raw: str) -> dict[str, dict[str, Any]]:
    """Parse bounded `systemctl show` property blocks keyed by unit Id."""
    result: dict[str, dict[str, Any]] = {}
    for block in str(raw)[:MAX_INPUT].split("\n\n")[:MAX_ITEMS]:
        fields: dict[str, str] = {}
        for line in block.splitlines()[:32]:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            fields[key] = value
        unit = fields.get("Id", "")
        if not _UNIT_RE.fullmatch("/" + unit):
            continue
        try:
            main_pid = max(0, int(fields.get("MainPID", "0")))
        except ValueError:
            main_pid = 0
        result[unit] = {
            "description": _text(fields.get("Description", "")),
            "activeState": _text(fields.get("ActiveState", "unknown"), 32),
            "subState": _text(fields.get("SubState", "unknown"), 32),
            "mainPid": main_pid,
        }
    return result


def parse_services(raw: str) -> dict[tuple[str, int], str]:
    """Parse a bounded /etc/services-style registry."""
    result: dict[tuple[str, int], str] = {}
    for line in str(raw)[:MAX_INPUT].splitlines():
        if len(result) >= MAX_ITEMS:
            break
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2 or "/" not in fields[1]:
            continue
        port_text, proto = fields[1].split("/", 1)
        try:
            port = int(port_text)
        except ValueError:
            continue
        if 0 < port <= 65535 and proto.lower() in {"tcp", "udp"}:
            result[(proto.lower(), port)] = _text(fields[0], 64)
    return result


def registry_label(port: int, proto: str, services_text: str | None = None) -> dict[str, str] | None:
    try:
        port = int(port)
        proto = str(proto).lower()
        label = parse_services(services_text).get((proto, port)) if services_text is not None else socket.getservbyport(port, proto)
    except (OSError, ValueError):
        return None
    return {"label": _text(label, 64), "caveat": REGISTRY_CAVEAT} if label else None


_PORT_DESCRIPTIONS = {
    (22, "tcp"): "Secure Shell (SSH) remote administration",
    (53, "tcp"): "Domain Name System (DNS) name resolution",
    (53, "udp"): "Domain Name System (DNS) name resolution",
    (67, "udp"): "DHCP server address assignment",
    (68, "udp"): "DHCP client address assignment",
    (631, "tcp"): "Internet Printing Protocol (IPP)",
    (5353, "udp"): "multicast DNS (mDNS) service discovery",
    (1716, "tcp"): "KDE Connect device integration",
    (1716, "udp"): "KDE Connect device discovery",
    (5900, "tcp"): "Virtual Network Computing (VNC) remote desktop",
    (41641, "udp"): "Tailscale peer-to-peer networking",
}


def describe_port(port: int, proto: str, container: dict[str, Any] | None = None) -> str:
    identity = " ".join(str((container or {}).get(key, "")) for key in ("name", "image")).lower()
    if int(port) in {6333, 6334} and "qdrant" in identity:
        return "Qdrant vector database service"
    return _PORT_DESCRIPTIONS.get((int(port), str(proto).lower()), "Unknown or application-specific service")


_PUBLISH_RE = re.compile(r"(?:(\[[^]]+\]|[^,\s:]+):)?(\d+)(?:-(\d+))?->(\d+)(?:-(\d+))?/(tcp|udp)\b", re.I)


def parse_docker_ps(raw: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in str(raw)[:MAX_INPUT].splitlines()[:MAX_ITEMS]:
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(item, dict):
            continue
        mappings = []
        for match in _PUBLISH_RE.finditer(str(item.get("Ports", ""))[:4096]):
            host_bind, host_start, host_end, target_start, target_end, proto = match.groups()
            hs, he = int(host_start), int(host_end or host_start)
            ts, te = int(target_start), int(target_end or target_start)
            if all(0 < value <= 65535 for value in (hs, he, ts, te)) and he >= hs and te >= ts:
                mappings.append({"hostBind": (host_bind or "*").strip("[]"), "hostStart": hs, "hostEnd": he, "containerStart": ts, "containerEnd": te, "proto": proto.lower()})
        records.append({"name": _text(item.get("Names", ""), 128), "image": _text(item.get("Image", ""), 256), "status": _text(item.get("Status", "")), "ports": mappings[:MAX_ITEMS]})
    return records


def _docker_bind_matches(published: object, listener: object) -> bool:
    published_text = str(published).split("%", 1)[0].strip("[]")
    listener_text = str(listener).split("%", 1)[0].strip("[]")
    if published_text == "*" or not listener_text:
        return True
    try:
        published_ip = ipaddress.ip_address(published_text)
        listener_ip = ipaddress.ip_address(listener_text)
    except ValueError:
        return published_text == listener_text
    if isinstance(published_ip, ipaddress.IPv6Address) and published_ip.ipv4_mapped is not None:
        published_ip = published_ip.ipv4_mapped
    if isinstance(listener_ip, ipaddress.IPv6Address) and listener_ip.ipv4_mapped is not None:
        listener_ip = listener_ip.ipv4_mapped
    return published_ip == listener_ip or (published_ip.is_unspecified and published_ip.version == listener_ip.version)


def match_container(records: list[dict[str, Any]], port: int, proto: str, host: str | None = None) -> dict[str, Any] | None:
    for record in records[:MAX_ITEMS]:
        for mapping in record.get("ports", [])[:MAX_ITEMS]:
            if (mapping.get("proto") == str(proto).lower()
                    and mapping.get("hostStart", 0) <= int(port) <= mapping.get("hostEnd", -1)
                    and (host is None or _docker_bind_matches(mapping.get("hostBind", "*"), host))):
                return {"name": record.get("name", ""), "image": record.get("image", ""), "status": record.get("status", ""), "containerPort": mapping["containerStart"] + int(port) - mapping["hostStart"]}
    return None


_UFW_RULE_RE = re.compile(r"^(.*?)\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+)$", re.I)
_UFW_TO_RE = re.compile(r"^(?:(\S+)\s+)?(\d+)(?::(\d+))?/(tcp|udp)(?:\s+on\s+(\S+))?$", re.I)


def _ufw_network(value: str) -> tuple[int | None, bool]:
    if value.lower() == "anywhere":
        return None, True
    try:
        return ipaddress.ip_network(value, strict=False).version, True
    except ValueError:
        return None, False


def parse_ufw_status(raw: str) -> dict[str, Any]:
    """Parse bounded `ufw status verbose`; non-status output is unavailable."""
    text = str(raw)[:MAX_INPUT]
    status = re.search(r"^Status:\s*(active|inactive)\s*$", text, re.I | re.M)
    if not status:
        return {"active": None, "defaults": {}, "rules": []}
    defaults: dict[str, str] = {}
    default_line = re.search(r"^Default:\s*(.+)$", text, re.I | re.M)
    if default_line:
        for policy, direction in re.findall(r"(allow|deny|reject|disabled)\s*\((incoming|outgoing|routed)\)", default_line.group(1), re.I):
            defaults[direction.lower()] = policy.lower()
    rules: list[dict[str, Any]] = []
    for line in text.splitlines():
        if len(rules) >= MAX_ITEMS:
            break
        body, _, comment = line.partition("#")
        stripped = body.strip()
        if re.match(r"^(Status|Logging|Default|New profiles|To)\s*:", stripped, re.I) or stripped.startswith("--"):
            continue
        match = _UFW_RULE_RE.match(stripped)
        if not match:
            continue
        destination_text, action, direction, source = match.groups()
        v6 = "(v6)" in destination_text.lower() or "(v6)" in source.lower()
        destination_text = re.sub(r"\s*\(v6\)\s*", " ", destination_text, flags=re.I).strip()
        source = re.sub(r"\s*\(v6\)\s*", " ", source, flags=re.I).strip()
        target = _UFW_TO_RE.fullmatch(destination_text)
        if not target:
            rules.append({"supported": False, "order": len(rules), "raw": _text(body.strip())})
            continue
        destination, start, end, proto, interface = target.groups()
        first, last = int(start), int(end or start)
        if not (0 < first <= last <= 65535):
            continue
        source_family, source_supported = _ufw_network(source)
        destination_family, destination_supported = _ufw_network(destination or "Anywhere")
        families = {family for family in (source_family, destination_family) if family is not None}
        supported = source_supported and destination_supported and len(families) <= 1 and (direction or "in").lower() == "in"
        family = 6 if v6 else (next(iter(families)) if families else 4)
        rules.append({"portStart": first, "portEnd": last, "proto": proto.lower(), "action": action.lower(),
                      "direction": (direction or "in").lower(), "family": family, "interface": _text(interface or "", 64),
                      "destination": _text(destination or "Anywhere"), "source": _text(source),
                      "comment": _text(comment.strip()), "order": len(rules), "supported": supported})
    return {"active": status.group(1).lower() == "active", "defaults": defaults, "rules": rules}


def _ufw_rule_applies(rule: dict[str, Any], host: str | None, interfaces: list[str] | None) -> bool | None:
    if not rule.get("supported", True):
        return None
    address = None
    if host is not None:
        try:
            address = ipaddress.ip_address(str(host).split("%", 1)[0].strip("[]"))
        except ValueError:
            return None
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
    family = rule.get("family")
    if family and address is None:
        return None
    if family and address and family != address.version:
        return False
    interface = str(rule.get("interface", ""))
    if interface:
        if not interfaces:
            return None
        if interface not in interfaces:
            return False
    destination = str(rule.get("destination", "Anywhere"))
    if destination.lower() != "anywhere":
        if address is None:
            return None
        try:
            if address not in ipaddress.ip_network(destination, strict=False):
                return False
        except ValueError:
            return None
    return True


def firewall_verdict(firewall: dict[str, Any], port: int, proto: str, container_published: bool = False,
                     host: str | None = None, interfaces: list[str] | None = None) -> dict[str, Any]:
    if firewall.get("active") is not True:
        return {"verdict": "unknown", "summary": "Firewall status unavailable or inactive", "rules": []}
    candidates = [rule for rule in firewall.get("rules", [])[:MAX_ITEMS]
                  if (not rule.get("supported", True) or
                      (rule.get("proto") == str(proto).lower() and rule.get("portStart", 0) <= int(port) <= rule.get("portEnd", -1)))]
    matches, uncertain = [], False
    for rule in candidates:
        applies = _ufw_rule_applies(rule, host, interfaces)
        if applies is True:
            matches.append(rule)
        elif applies is None:
            uncertain = True
    actions = {rule.get("action") for rule in matches}
    if uncertain:
        verdict, summary = "unknown", "Firewall rules contain unsupported or unresolved family, interface, destination, or source dimensions"
    elif len(actions) > 1:
        verdict, summary = "unknown", "Conflicting ordered firewall rules require manual verification"
    elif matches:
        first = min(matches, key=lambda rule: int(rule.get("order", 0)))
        action = first.get("action")
        if action == "limit":
            verdict, summary = "limited", "Rate-limited by a matching firewall rule"
        elif action == "allow":
            global_allow = str(first.get("source", "")).lower() == "anywhere"
            verdict = "allowed" if global_allow else "limited"
            summary = "Allowed from anywhere" if global_allow else "Limited to specific firewall sources"
        else:
            global_deny = str(first.get("source", "")).lower() == "anywhere"
            if global_deny:
                verdict, summary = "denied", "Denied by a matching firewall rule"
            else:
                verdict, summary = "unknown", "Denied only for a specific source; other sources require separate evaluation"
    elif container_published:
        verdict, summary = "unknown", "Docker publishes this port through forwarding rules that may bypass UFW's incoming default; verify DOCKER-USER policy"
    elif firewall.get("defaults", {}).get("incoming") in {"deny", "reject"}:
        verdict, summary = "default-deny", "No matching rule; incoming traffic is denied by default"
    else:
        verdict, summary = "unknown", "No decisive matching firewall rule"
    return {"verdict": verdict, "summary": summary, "rules": matches[:MAX_ITEMS]}


def parse_ip_addresses(raw: str) -> dict[str, list[str]]:
    """Map local addresses to interface names from bounded `ip -j address` output."""
    try:
        items = json.loads(str(raw)[:MAX_INPUT])
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(items, list):
        return {}
    result: dict[str, list[str]] = {}
    for item in items[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        interface = _text(item.get("ifname", ""), 64)
        if not interface:
            continue
        addr_info = item.get("addr_info", [])
        for address in addr_info[:MAX_ITEMS] if isinstance(addr_info, list) else []:
            if not isinstance(address, dict):
                continue
            local = str(address.get("local", "")).split("%", 1)[0]
            try:
                local = str(ipaddress.ip_address(local))
            except ValueError:
                continue
            if local not in result and len(result) >= MAX_ITEMS:
                continue
            if interface not in result.setdefault(local, []):
                result[local].append(interface)
    return result


def owner_context(pid: int, proc_root: Path | str = "/proc", clock_ticks: int | None = None) -> dict[str, Any] | None:
    """Read identity, executable, and age only (never argv or environment)."""
    try:
        pid = int(pid)
        if pid <= 0:
            return None
        root = Path(proc_root)
        directory = root / str(pid)
        status = (directory / "status").read_text(errors="replace")[:8192]
        uid_match = re.search(r"^Uid:\s*(\d+)", status, re.M)
        if not uid_match:
            return None
        uid = int(uid_match.group(1))
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = str(uid)
        executable_path = os.readlink(directory / "exe")[:MAX_TEXT]
        stat = (directory / "stat").read_text(errors="replace")[:8192]
        close = stat.rfind(")")
        tail = stat[close + 2 :].split() if close >= 0 else []
        start_ticks = int(tail[19])
        uptime = float((root / "uptime").read_text(errors="replace")[:128].split()[0])
        ticks = int(clock_ticks or os.sysconf("SC_CLK_TCK"))
        age = max(0, int(uptime - (start_ticks / ticks)))
        return {"pid": pid, "username": _text(username, 64), "executable": _text(Path(executable_path).name, 128), "executablePath": executable_path, "processAgeSeconds": age}
    except (OSError, ValueError, IndexError, ZeroDivisionError):
        return None


def listener_context_key(row: dict[str, Any]) -> str:
    """Return a deterministic JSON-safe merge key for a listener row."""
    if isinstance(row.get("key"), str) and row["key"]:
        return _text(row["key"], 2048)
    return f"{str(row.get('proto', 'unknown')).lower()}|{_text(row.get('host', 'unknown'), 256)}|{int(row.get('port', 0))}"


def _run(args: list[str], runner: Any) -> str:
    try:
        result = runner(args, text=True, capture_output=True, timeout=COMMAND_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return str(result.stdout)[:MAX_INPUT]


def _unit_metadata(rows: list[dict[str, Any]], runner: Any) -> dict[str, dict[str, Any]]:
    groups: dict[bool, set[str]] = {False: set(), True: set()}
    for row in rows[:MAX_ITEMS]:
        cgroup = str(row.get("cgroup", ""))[:4096]
        unit = unit_from_ss_cgroup(cgroup)
        if unit:
            groups["user.slice" in cgroup].add(unit)
    metadata: dict[str, dict[str, Any]] = {}
    properties = "Id,Description,ActiveState,SubState,MainPID"
    for user, units in groups.items():
        ordered = sorted(units)[:MAX_ITEMS]
        if not ordered:
            continue
        args = ["systemctl"] + (["--user"] if user else []) + ["show", f"--property={properties}"] + ordered
        metadata.update(parse_systemctl_show(_run(args, runner)))
    return metadata


def collect_context(rows: Any, runner: Any = subprocess.run, proc_root: Path | str = "/proc") -> dict[str, dict[str, Any]]:
    """Collect bounded context keyed for deterministic merging with listeners."""
    safe_rows = [row for row in list(rows)[:MAX_ITEMS] if isinstance(row, dict)]
    docker_format = '{"Names":{{json .Names}},"Image":{{json .Image}},"Status":{{json .Status}},"Ports":{{json .Ports}}}'
    containers = parse_docker_ps(_run(["docker", "ps", "--format", docker_format], runner))
    ufw_raw = _run(["sudo", "-n", "ufw", "status", "verbose"], runner)
    firewall = parse_ufw_status(ufw_raw)

    local_interfaces = parse_ip_addresses(_run(["ip", "-j", "address", "show"], runner))
    units = _unit_metadata(safe_rows, runner)
    result: dict[str, dict[str, Any]] = {}
    for row in sorted(safe_rows, key=listener_context_key):
        proto, port = str(row.get("proto", "unknown")).lower(), int(row.get("port", 0))
        host = str(row.get("host", ""))
        host_key = host.split("%", 1)[0].strip("[]")
        bind_interfaces = local_interfaces.get(host_key, [])
        container = match_container(containers, port, proto, host)
        cgroup_unit = unit_from_ss_cgroup(str(row.get("cgroup", "")))
        owners = []
        for owner in row.get("owners", [])[:MAX_ITEMS] if isinstance(row.get("owners"), list) else []:
            if isinstance(owner, dict):
                info = owner_context(owner.get("pid", 0), proc_root=proc_root)
                if info:
                    owners.append(info)
        result[listener_context_key(row)] = {
            "unit": units.get(cgroup_unit) if cgroup_unit else None,
            "unitName": cgroup_unit,
            "container": container,
            "firewall": firewall_verdict(firewall, port, proto, container_published=container is not None,
                                           host=host, interfaces=bind_interfaces),
            "connections": {"summary": "Connection counts are not collected to protect remote peer privacy"},
            "owners": sorted(owners, key=lambda item: item["pid"])[:MAX_ITEMS],
            "registry": registry_label(port, proto),
            "purpose": describe_port(port, proto, container),
            "bindInterfaces": bind_interfaces,
        }
    return result


def _bind_summary(host: object, interfaces: list[str] | None = None) -> tuple[str, bool]:
    value = str(host).split("%", 1)[0].strip("[]")
    if value in {"*", "0.0.0.0", ""}:
        return "Listens on all IPv4 interfaces", True
    if value == "::":
        return "Listens on all IPv6 interfaces", True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "Bind scope could not be classified", True
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback:
        return "Listens on localhost only", False
    if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        return "Listens on a Tailscale address", False
    if address.version == 6 and address in ipaddress.ip_network("fd7a:115c:a1e0::/48"):
        return "Listens on a Tailscale address", False
    if address.is_multicast:
        return f"Listens on an IPv{address.version} multicast address", False
    if address.is_private or address.is_link_local:
        if interfaces is not None:
            bridge_interfaces = [name for name in interfaces if name.lower().startswith(("virbr", "incusbr", "docker", "br-", "veth"))]
            if bridge_interfaces and len(bridge_interfaces) == len(interfaces):
                return f"Listens on private bridge interface {', '.join(bridge_interfaces)}", False
            if not interfaces or bridge_interfaces:
                return "Bind scope could not be safely classified because its interface is unresolved", True
        return "Listens on a LAN address", False
    return "Listens on a public address", True


def describe_listener(row: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, str]:
    """Build bounded UI text without promoting a registry guess to identity."""
    unit = enrichment.get("unit") if isinstance(enrichment.get("unit"), dict) else None
    container = enrichment.get("container") if isinstance(enrichment.get("container"), dict) else None
    owners = enrichment.get("owners") if isinstance(enrichment.get("owners"), list) else []
    registry = enrichment.get("registry") if isinstance(enrichment.get("registry"), dict) else None
    processes = row.get("processes") if isinstance(row.get("processes"), list) else []
    process = next((str(value) for value in processes if str(value) != "unknown"), "")
    if not process and str(row.get("process", "unknown")) != "unknown":
        process = str(row.get("process", ""))
    unit_name = str(enrichment.get("unitName") or "")
    generic_user_unit = unit_name.startswith("user@")
    if container and container.get("name"):
        strong_name = str(container["name"])
    elif unit and unit.get("description") and not generic_user_unit:
        strong_name = str(unit["description"])
    elif owners and isinstance(owners[0], dict) and owners[0].get("executable"):
        strong_name = str(owners[0]["executable"])
    else:
        strong_name = process
    registry_label_text = str(registry.get("label", "")) if registry else ""
    port = int(row.get("port", 0))
    title = strong_name or (f"Port {port} ({registry_label_text} registry label)" if registry_label_text else f"Port {port}")
    purpose = _text(enrichment.get("purpose", "Unknown or application-specific service"))
    if unit and not process and strong_name:
        what = f"Associated with the systemd unit {unit_name or strong_name}; this port is commonly associated with {purpose}."
    elif strong_name and purpose != "Unknown or application-specific service":
        what = f"Owned by {process or strong_name}; this port is commonly associated with {purpose}."
    elif strong_name:
        what = f"A listener identified as {strong_name}."
    elif registry_label_text:
        what = f"An unidentified listener on a port labeled {registry_label_text} in the service registry."
    else:
        what = "An unidentified network listener."
    bind_interfaces = enrichment.get("bindInterfaces")
    interfaces = bind_interfaces if isinstance(bind_interfaces, list) else None
    bind, broad = _bind_summary(row.get("host", "unknown"), interfaces)
    firewall = enrichment.get("firewall") if isinstance(enrichment.get("firewall"), dict) else {}
    connections = enrichment.get("connections") if isinstance(enrichment.get("connections"), dict) else {}
    owner_parts = []
    for owner in owners[:4]:
        if isinstance(owner, dict):
            owner_parts.append(f"{owner.get('username', 'unknown')}: {owner.get('executable', 'unknown')} ({int(owner.get('processAgeSeconds', 0))}s old)")
    owner_summary = "; ".join(owner_parts) or (f"Process: {process}" if process else "Owner unavailable")
    unit_summary = f"{unit_name}: {unit.get('activeState', 'unknown')}/{unit.get('subState', 'unknown')}" if unit and unit_name else "No systemd unit identified"
    container_summary = f"Container {container.get('name', 'unknown')} ({container.get('image', 'unknown')}), {container.get('status', 'status unknown')}" if container else "No matching published container"
    verdict = str(firewall.get("verdict", "unknown"))
    values = {
        "title": title,
        "whatThisIs": what,
        "bindSummary": bind,
        "firewallSummary": str(firewall.get("summary", "Firewall status unknown")),
        "ownerSummary": owner_summary,
        "unitSummary": unit_summary,
        "containerSummary": container_summary,
        "registryLabel": registry_label_text,
        "registryCaveat": str(registry.get("caveat", REGISTRY_CAVEAT) if registry else "No registry label available"),
        "connectionSummary": str(connections.get("summary", "Active connection count unavailable")),
        "attentionHint": "review" if broad and verdict in {"allowed", "limited", "unknown"} else "low",
    }
    return {key: _text(value) for key, value in values.items()}
