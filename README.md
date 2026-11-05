# PiSec Lab: Raspberry Pi IDS and Mini-SIEM

A home network intrusion detection system I built from scratch on a Raspberry Pi. It captures traffic, checks it against detection rules I wrote, raises alerts, and keeps a searchable history in a small SIEM.

I built it to learn how SOC and security analyst work really happens: getting data in, writing and tuning detections, and keeping the whole pipeline running on its own.

**Start here: [v3](v3/README.md) is the current version.**

## Versions

| Version | What it does | Main pieces |
|---|---|---|
| [v1](v1/README.md) | Mac captures PCAPs and ships them to the Pi. Pi runs a Python analyzer with YAML rules. Alerts come back to the Mac as desktop notifications | tcpdump, rsync, Python, LaunchAgents |
| [v2](v2/README.md) | Rewrote the analyzer myself with my own rules, cleaner working folders and a more reliable pipeline | Python, TShark, YAML rules |
| [v3](v3/README.md) | Pi becomes a Wi-Fi gateway. 16 rules, web dashboard with rule creation, firewall control, SQLite mini-SIEM, runs 24/7 with systemd | hostapd, dnsmasq, iptables, FastAPI, SQLite, Tailscale |

## Repo Layout

```text
v1/  v2/  v3/
  README.md   how that version works
  src/        Python code
  rules/      detection rules (YAML)
  images/     screenshots
```

## Skills Practiced

Linux networking, packet capture and analysis, detection engineering, rule tuning, Python, FastAPI, SQLite, systemd, iptables, secure remote access.

All IPs, usernames, hostnames and MAC addresses are anonymized.
