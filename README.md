# Watchtower for Omarchy

A quiet perimeter alarm in the Omarchy bar.

Watchtower scans the machine's listening TCP and UDP sockets and lights up when
a new process becomes reachable beyond localhost. Each expandable listener card
explains the likely purpose, process owner, systemd unit, Docker container,
network scope, UFW policy, service-registry hint, and
a plain-English recommendation. Mark listeners you recognize as trusted;
Watchtower stays green until something new opens a door.

It does **not** change firewall rules, stop services, inspect packet contents,
send telemetry, or prompt for root. It reads listener output from `ss` plus
bounded context from `systemctl`, Docker, and passwordless `sudo -n ufw` when
available. For process identity it reads UID from `/proc/<pid>/status`, process age
from `/proc/<pid>/stat` and `/proc/uptime`, and the `/proc/<pid>/exe` symlink.
It never reads process command lines or environments, requests only explicit
non-command Docker fields, and does not collect established-connection records
or remote peer addresses. Trusted socket keys are stored under
`$XDG_STATE_HOME/omarchy-watchtower/trusted.json`.

## Install

```bash
omarchy plugin add https://github.com/nixfred/omarchy-watchtower.git --enable
```

For local development, copy the checkout into the plugin directory:

```bash
rsync -a --delete --exclude .git/ "$PWD/" ~/.config/omarchy/plugins/io.github.nixfred.watchtower/
omarchy plugin validate ~/.config/omarchy/plugins/io.github.nixfred.watchtower
omarchy plugin enable io.github.nixfred.watchtower right
```

## Use

- Left click: inspect exposed listeners; use **Details** to expand one card.
- Right click or press `R`: scan immediately.
- **Trust current baseline**: approve every currently exposed listener in one step.
- **Trust**: approve one exact protocol/address/port/UID/executable combination.
- **Untrust**: make an approved listener alert again.
- Settings can include localhost-only listeners and adjust the scan interval.

IPC:

```bash
omarchy-shell io.github.nixfred.watchtower status
omarchy-shell io.github.nixfred.watchtower refresh
omarchy-shell io.github.nixfred.watchtower toggle
```

CLI:

```bash
./watchtower.py scan | jq
./watchtower.py trust 'tcp|0.0.0.0|22|identity-v3:%5B%7B%22executable%22%3A%22%2Fusr%2Fbin%2Fsshd%22%2C%22uid%22%3A0%7D%5D'
./watchtower.py untrust 'tcp|0.0.0.0|22|identity-v3:%5B%7B%22executable%22%3A%22%2Fusr%2Fbin%2Fsshd%22%2C%22uid%22%3A0%7D%5D'
```

Watchtower 1.0 uses the `identity-v3` trust identity and a version-2 trust
store. Older approvals are ignored deliberately; re-baseline after upgrading
so a spoofable legacy process-name approval cannot silently carry forward.

## What counts as exposed?

Wildcard binds, LAN addresses, Tailscale addresses, and public addresses are
reviewable exposures. Loopback, multicast, link-local, and private bridge-only
addresses remain visible when **Show localhost listeners** is enabled but do
not raise the badge.

Watchtower detects listeners, not reachability through a firewall. A firewall
may still block a broadly bound service; the bind is shown because it remains
important security context. Registry names are explicitly labeled as hints,
not proof of which application owns a port. If socket ownership is missing or
ambiguous, Watchtower fails closed and disables trust for that listener.

## Development

```bash
python3 -m unittest discover -s tests -v
omarchy plugin validate .
```

## Remove

```bash
omarchy plugin remove io.github.nixfred.watchtower --yes
```

The trust file is intentionally retained. Remove it separately if desired:

```bash
rm -r "${XDG_STATE_HOME:-$HOME/.local/state}/omarchy-watchtower"
```

MIT licensed.
