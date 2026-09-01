#!/usr/bin/env python3
"""Watchtower: report newly exposed listening sockets for an Omarchy widget."""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import watchtower_context

KEY_RE = re.compile(r"^[a-z0-9]+\|[^\s|]{1,128}\|[0-9]{1,5}\|[^\s|]{1,2048}$", re.I)
EXPOSED_SCOPES = {"all", "lan", "tailscale", "public"}
TRUST_STORE_VERSION = 2


def state_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    return base / "omarchy-watchtower" / "trusted.json"


SCOPE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _endpoint_parts(endpoint: str) -> tuple[str, str] | None:
    endpoint = endpoint.strip()
    bracketed = endpoint.startswith("[")
    if bracketed:
        closing = endpoint.find("]")
        if closing <= 1 or endpoint[closing + 1 : closing + 2] != ":":
            return None
        host = endpoint[1:closing]
        port = endpoint[closing + 2 :]
        if "]" in port or ":" in port:
            return None
    else:
        if endpoint.count(":") != 1:
            return None
        host, port = endpoint.split(":", 1)
        if not host:
            return None

    address_text = host
    if "%" in host:
        address_text, scope = host.rsplit("%", 1)
        if not address_text or not SCOPE_RE.fullmatch(scope):
            return None

    if host == "*":
        if bracketed:
            return None
    else:
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            return None
        if bracketed != isinstance(address, ipaddress.IPv6Address):
            return None
    return host, port


def split_endpoint(endpoint: str) -> tuple[str, int] | None:
    parsed = _endpoint_parts(endpoint)
    if parsed is None:
        return None
    host, port = parsed
    try:
        value = int(port)
    except ValueError:
        return None
    if not 0 <= value <= 65535:
        return None
    return host, value


def valid_peer_endpoint(endpoint: str) -> bool:
    parsed = _endpoint_parts(endpoint)
    if parsed is None:
        return False
    _host, port = parsed
    if port == "*":
        return True
    try:
        value = int(port)
    except ValueError:
        return False
    return 0 <= value <= 65535


def parse_ss_owners(details: str) -> tuple[list[dict[str, Any]], bool]:
    if not details.startswith("users:(") or not details.endswith(")"):
        return [], False
    entries = details[len("users:(") : -1]
    owners: list[dict[str, Any]] = []
    position = 0
    while position < len(entries):
        if entries[position] != "(":
            return [], False
        position += 1
        escaped_wrapper = entries.startswith('\\"', position)
        quote_length = 2 if escaped_wrapper else 1
        if entries[position : position + quote_length] != ('\\"' if escaped_wrapper else '"'):
            return [], False
        position += quote_length
        name_parts: list[str] = []
        closed = False
        while position < len(entries):
            if escaped_wrapper and entries.startswith('\\"', position):
                position += 2
                closed = True
                break
            character = entries[position]
            if not escaped_wrapper and character == '"':
                position += 1
                closed = True
                break
            if character == "\\":
                if position + 1 >= len(entries) or entries[position + 1] not in {'"', "\\"}:
                    return [], False
                name_parts.append(entries[position + 1])
                position += 2
                continue
            name_parts.append(character)
            position += 1
        name = "".join(name_parts)
        if not closed or not name:
            return [], False
        metadata = re.match(r",pid=([0-9]+),fd=([0-9]+)\)", entries[position:])
        if metadata is None:
            return [], False
        position += metadata.end()
        owners.append({"name": name, "pid": int(metadata.group(1)), "fd": int(metadata.group(2))})
        if position == len(entries):
            break
        if entries[position] != ",":
            return [], False
        position += 1
        if position == len(entries):
            return [], False
    return sorted(owners, key=lambda owner: (owner["name"], owner["pid"], owner["fd"])), bool(owners)


def owner_block(details: str) -> str:
    """Extract exactly one complete users:(...) block without accepting a prefix."""
    if details.count("users:(") != 1:
        return ""
    start = details.find("users:(")
    depth = 0
    quoted = False
    escaped = False
    for position in range(start + len("users:"), len(details)):
        character = details[position]
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            continue
        if quoted:
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return details[start : position + 1]
            if depth < 0:
                return ""
    return ""


def resolve_owner_identity(owner: dict[str, Any], socket_uid: int | None) -> dict[str, Any]:
    resolved = dict(owner)
    pid = int(owner["pid"])
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        uid_match = re.search(r"^Uid:\s+([0-9]+)\b", status, re.MULTILINE)
        process_uid = int(uid_match.group(1)) if uid_match else None
        executable = os.readlink(f"/proc/{pid}/exe")
    except (OSError, ValueError):
        return resolved
    if process_uid is None or (socket_uid is not None and process_uid != socket_uid):
        return resolved
    if not executable.startswith("/"):
        return resolved
    resolved.update({"uid": process_uid, "executable": executable})
    return resolved


def parse_ss(raw: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=6)
        if len(parts) < 6:
            raise ValueError(f"malformed ss row {line_number}")
        proto, state = parts[0].lower(), parts[1].upper()
        if proto not in {"tcp", "udp"}:
            raise ValueError(f"malformed ss row {line_number}")
        if state != ("LISTEN" if proto == "tcp" else "UNCONN"):
            raise ValueError(f"malformed ss row {line_number}")
        if not parts[2].isdigit() or not parts[3].isdigit():
            raise ValueError(f"malformed ss row {line_number}")
        endpoint = split_endpoint(parts[4])
        if endpoint is None or not valid_peer_endpoint(parts[5]):
            raise ValueError(f"malformed ss row {line_number}")
        host, port = endpoint
        details = parts[6] if len(parts) == 7 else ""
        owners, ownership_complete = parse_ss_owners(owner_block(details))
        uid_match = re.search(r"(?:^|\s)uid:([0-9]+)(?:\s|$)", details)
        socket_uid = int(uid_match.group(1)) if uid_match else None
        owners = [resolve_owner_identity(owner, socket_uid) for owner in owners]
        processes = sorted({owner["name"] for owner in owners})
        cgroup_match = re.search(r"(?:^|\s)cgroup:([^\s]+)", details)
        rows.append(
            {
                "proto": proto,
                "host": host,
                "port": port,
                "process": ", ".join(processes) if processes else "unknown",
                "processes": processes,
                "owners": owners,
                "ownershipComplete": ownership_complete,
                "cgroup": cgroup_match.group(1) if cgroup_match else "",
            }
        )
    return rows


def classify_bind(host: str) -> str:
    host_parts = host.split("%", 1)
    clean = host_parts[0].strip("[]").lower()
    interface = host_parts[1].lower() if len(host_parts) == 2 else ""
    if interface.startswith(("virbr", "incusbr", "docker", "br-", "veth")):
        return "private"
    if clean in {"", "*", "0.0.0.0", "::"}:
        return "all"
    try:
        address = ipaddress.ip_address(clean)
    except ValueError:
        return "unknown"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback:
        return "loopback"
    if address.is_multicast:
        return "multicast"
    if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        return "tailscale"
    if address.version == 6 and address in ipaddress.ip_network("fd7a:115c:a1e0::/48"):
        return "tailscale"
    if address.version == 4 and (
        address in ipaddress.ip_network("10.0.0.0/8")
        or address in ipaddress.ip_network("172.16.0.0/12")
        or address in ipaddress.ip_network("192.168.0.0/16")
    ):
        return "lan"
    if address.version == 6 and address in ipaddress.ip_network("fc00::/7"):
        return "lan"
    if address.is_private or address.is_link_local:
        return "private"
    return "public"


def canonical_owner_identity(row: dict[str, Any]) -> list[dict[str, Any]] | None:
    owners = row.get("owners")
    if not isinstance(owners, list) or not owners:
        return None
    identities: set[tuple[int, str]] = set()
    for owner in owners:
        if not isinstance(owner, dict):
            return None
        uid = owner.get("uid")
        executable = owner.get("executable")
        if isinstance(uid, bool) or not isinstance(uid, int):
            return None
        if not isinstance(executable, str) or not executable.startswith("/"):
            return None
        identities.add((uid, executable))
    return [{"uid": uid, "executable": executable} for uid, executable in sorted(identities)]


def socket_key(row: dict[str, Any]) -> str:
    proto = quote(str(row["proto"]), safe="")
    host = quote(str(row["host"]), safe="")
    identity = canonical_owner_identity(row)
    encoded = "incomplete" if identity is None else quote(
        json.dumps(identity, ensure_ascii=False, separators=(",", ":"), sort_keys=True), safe=""
    )
    return f"{proto}|{host}|{int(row['port'])}|identity-v3:{encoded}"


def validate_key(key: str) -> str:
    if not KEY_RE.fullmatch(key):
        raise ValueError("invalid socket key")
    port = int(key.split("|")[2])
    if port > 65535:
        raise ValueError("invalid socket port")
    return key


def load_trusted(path: Path | None = None) -> set[str]:
    target = path or state_path()
    try:
        data = json.loads(target.read_text())
        if not isinstance(data, dict) or data.get("version") != TRUST_STORE_VERSION:
            return set()
        values = data.get("trusted", [])
        return {value for value in values if isinstance(value, str) and KEY_RE.fullmatch(value)}
    except (OSError, json.JSONDecodeError):
        return set()


def save_trusted(path: Path, trusted: Iterable[str]) -> None:
    values = sorted({validate_key(value) for value in trusted})
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as temporary:
            temporary_name = temporary.name
            json.dump({"version": TRUST_STORE_VERSION, "trusted": values}, temporary, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def update_trusted(path: Path, keys: str | Iterable[str], should_trust: bool) -> set[str]:
    values = {validate_key(keys)} if isinstance(keys, str) else {validate_key(key) for key in keys}
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        trusted = load_trusted(path)
        trusted.update(values) if should_trust else trusted.difference_update(values)
        save_trusted(path, trusted)
        return trusted


def merge_socket_rows(first: dict[str, Any], second: dict[str, Any], trusted: set[str]) -> dict[str, Any]:
    first_owner_evidence = json.dumps(first["owners"], sort_keys=True, separators=(",", ":"))
    second_owner_evidence = json.dumps(second["owners"], sort_keys=True, separators=(",", ":"))
    evidence_agrees = (
        first["processes"] == second["processes"]
        and first_owner_evidence == second_owner_evidence
        and first["cgroup"] == second["cgroup"]
    )
    processes = sorted(set(first["processes"]) | set(second["processes"]))
    owners_by_value = {
        json.dumps(owner, sort_keys=True, separators=(",", ":")): owner
        for owner in [*first["owners"], *second["owners"]]
    }
    merged = dict(first)
    merged.update(
        {
            "process": ", ".join(processes) if processes else "unknown",
            "processes": processes,
            "owners": [owners_by_value[value] for value in sorted(owners_by_value)],
            "ownershipComplete": (
                first["ownershipComplete"] and second["ownershipComplete"] and evidence_agrees
            ),
            "cgroup": first["cgroup"] if first["cgroup"] == second["cgroup"] else "",
        }
    )
    merged["trustable"] = merged["ownershipComplete"] and canonical_owner_identity(merged) is not None
    merged["trusted"] = merged["trustable"] and merged["key"] in trusted
    return merged


def summarize(rows: Iterable[dict[str, Any]], trusted: set[str]) -> dict[str, Any]:
    unique: dict[str, dict[str, Any]] = {}
    for raw in rows:
        raw_owners = raw.get("processes")
        owners = (
            sorted({str(owner) for owner in raw_owners})
            if isinstance(raw_owners, (list, tuple, set))
            else [str(raw.get("process", "unknown"))]
        )
        raw_owner_metadata = raw.get("owners")
        owner_metadata: list[dict[str, Any]] = []
        if isinstance(raw_owner_metadata, list):
            for owner in raw_owner_metadata:
                normalized = {"name": str(owner["name"]), "pid": int(owner["pid"]), "fd": int(owner["fd"])}
                if isinstance(owner.get("uid"), int) and not isinstance(owner.get("uid"), bool):
                    normalized["uid"] = owner["uid"]
                if isinstance(owner.get("executable"), str):
                    normalized["executable"] = owner["executable"]
                owner_metadata.append(normalized)
        else:
            owner_metadata = [{"name": owner} for owner in owners if owner != "unknown"]
        row = {
            "proto": str(raw.get("proto", "unknown")).lower(),
            "host": str(raw.get("host", "unknown")),
            "port": int(raw.get("port", 0)),
            "process": ", ".join(owners) if owners else "unknown",
            "processes": owners,
            "owners": owner_metadata,
            "ownershipComplete": bool(raw.get("ownershipComplete", True)),
            "cgroup": str(raw.get("cgroup", ""))[:4096],
        }
        key = socket_key(row)
        scope = classify_bind(row["host"])
        transient = False
        trustable = row["ownershipComplete"] and canonical_owner_identity(row) is not None
        row.update(
            {
                "key": key,
                "scope": scope,
                "transient": transient,
                "exposed": scope in EXPOSED_SCOPES and not transient,
                "trustable": trustable,
                "trusted": trustable and key in trusted,
            }
        )
        unique[key] = merge_socket_rows(unique[key], row, trusted) if key in unique else row
    sockets = sorted(
        unique.values(),
        key=lambda row: (
            not (row["exposed"] and not row["trusted"]),
            not row["exposed"],
            row["port"],
            row["proto"],
        ),
    )
    exposed = [row for row in sockets if row["exposed"]]
    untrusted = [row for row in exposed if not row["trusted"]]
    return {
        "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "state": "alert" if untrusted else "guarded" if exposed else "quiet",
        "socketCount": len(sockets),
        "exposedCount": len(exposed),
        "untrustedCount": len(untrusted),
        "sockets": sockets,
    }


def collect_ss() -> str:
    fixture = os.environ.get("WATCHTOWER_SS_FIXTURE")
    if fixture is not None:
        return fixture
    result = subprocess.run(
        ["ss", "-H", "-lntupen"], text=True, capture_output=True, timeout=8, check=False
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "ss failed").strip())
    return result.stdout


def enrich_report(report: dict[str, Any], enrichment: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Merge bounded context and plain-English guidance into report sockets."""
    for row in report.get("sockets", []):
        extra = enrichment.get(str(row.get("key", "")), {})
        if not isinstance(extra, dict):
            extra = {}
        bind_interfaces = extra.get("bindInterfaces")
        if (
            isinstance(bind_interfaces, list)
            and bind_interfaces
            and all(
                str(name).lower().startswith(("virbr", "incusbr", "docker", "br-", "veth"))
                for name in bind_interfaces
            )
        ):
            row["scope"] = "private"
            row["exposed"] = False
        view = watchtower_context.describe_listener(row, extra)
        row.update(extra)
        row.update(
            {
                "friendlyTitle": view.get("title", "Listener"),
                "description": view.get("whatThisIs", ""),
                "bindExplanation": view.get("bindSummary", ""),
                "firewallSummary": view.get("firewallSummary", ""),
                "ownerSummary": view.get("ownerSummary", ""),
                "unitSummary": view.get("unitSummary", ""),
                "containerSummary": view.get("containerSummary", ""),
                "registryCaveat": view.get("registryCaveat", ""),
                "connectionSummary": view.get("connectionSummary", ""),
                "attention": (
                    "Owner information is incomplete; this listener cannot be trusted safely."
                    if not row.get("trustable")
                    else "New listener reachable beyond localhost."
                    if row.get("exposed") and not row.get("trusted")
                    else ""
                ),
                "recommendation": recommendation(row, extra),
            }
        )
    exposed = [row for row in report.get("sockets", []) if row.get("exposed")]
    untrusted = [row for row in exposed if not row.get("trusted")]
    report["exposedCount"] = len(exposed)
    report["untrustedCount"] = len(untrusted)
    report["state"] = "alert" if untrusted else "guarded" if exposed else "quiet"
    return report


def recommendation(row: dict[str, Any], enrichment: dict[str, Any]) -> str:
    firewall = enrichment.get("firewall") if isinstance(enrichment.get("firewall"), dict) else {}
    verdict = str(firewall.get("verdict", "unknown"))
    if not row.get("trustable"):
        return "Do not trust this listener until complete process ownership can be verified."
    if row.get("exposed") and not row.get("trusted"):
        if verdict == "default-deny":
            return "Identify the service before trusting it; UFW currently blocks unmatched inbound traffic."
        if verdict == "limited":
            return "Confirm the service and the listed source restrictions, then trust it only if expected."
        return "Identify the service and restrict or stop it if this exposure is unexpected."
    if row.get("trusted"):
        return "Previously reviewed; re-check it if the service, owner, or firewall policy changes."
    return "Local or non-routable listener; no perimeter action is normally required."


def scan() -> dict[str, Any]:
    report = summarize(parse_ss(collect_ss()), load_trusted())
    if os.environ.get("WATCHTOWER_DISABLE_CONTEXT") == "1":
        return report
    return enrich_report(report, watchtower_context.collect_context(report["sockets"]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch newly exposed listening sockets")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("scan")
    sub.add_parser("baseline")
    trust_parser = sub.add_parser("trust")
    trust_parser.add_argument("key")
    untrust_parser = sub.add_parser("untrust")
    untrust_parser.add_argument("key")
    args = parser.parse_args()
    command = args.command or "scan"
    path = state_path()
    try:
        if command == "baseline":
            rows = parse_ss(collect_ss())
            report = summarize(rows, load_trusted(path))
            trusted = update_trusted(
                path,
                (row["key"] for row in report["sockets"] if row["exposed"] and row["trustable"]),
                True,
            )
            print(json.dumps(summarize(rows, trusted), separators=(",", ":")))
            return 0
        if command in {"trust", "untrust"}:
            update_trusted(path, args.key, command == "trust")
        print(json.dumps(scan(), separators=(",", ":")))
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(json.dumps({"state": "error", "error": str(error), "sockets": []}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
