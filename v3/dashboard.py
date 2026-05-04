import json
import os
import re
import shutil
import subprocess
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Query, Body
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

BASE = Path(os.path.expanduser("/home/<USER>/Desktop/IDS_Project"))
ALERTS_FILE = BASE / "ids_alerts" / "alert.jsonl"
FIREWALL_EVENTS_FILE = BASE / "ids_alerts" / "firewall_events.jsonl"
DEBUG_LOG = BASE / "ids_alerts" / "ids_debug.log"
RULES_PATH = BASE / "rules_v3.yaml"
FIREWALL_RULES_PATH = BASE / "firewall_rules.yaml"
FIREWALL_SH = BASE / "firewall.sh"
SIEM_DB = BASE / "siem" / "siem.db"

app = FastAPI(title="Pi Security Dashboard")

ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{3,80}$")
VALID_SEVERITIES = {"low", "medium", "high"}
VALID_IDS_TYPES = {"count_by_src", "count_by_src_dstport", "dns_domain"}
VALID_FIREWALL_ACTIONS = {"ACCEPT", "DROP", "REJECT"}
VALID_FIREWALL_CHAINS = {"INPUT", "FORWARD"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any"}
VALID_INTERFACES = {"wlan1", "eth0", "tailscale0", "wg0", ""}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_suffix(path.suffix + f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    shutil.copy2(path, backup)
    return backup


def read_jsonl(path: Path, limit: int = 500) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []

    events: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        except Exception:
            continue
    return events


def read_debug_tail(limit: int = 40) -> list[str]:
    if not DEBUG_LOG.exists():
        return []
    try:
        return DEBUG_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except Exception:
        return []

def siem_db_exists() -> bool:
    return SIEM_DB.exists()


def connect_siem_db() -> sqlite3.Connection:
    conn = sqlite3.connect(SIEM_DB)
    conn.row_factory = sqlite3.Row
    return conn


def rows_to_dicts(rows) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]

def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = Counter((a.get("severity") or "unknown").lower() for a in events)
    rule_counts = Counter(a.get("rule_id") or a.get("rule_name") or "unknown_rule" for a in events)
    src_counts = Counter(a.get("src_ip") or "unknown" for a in events)
    latest_ts = events[-1].get("ts") if events else None
    return {
        "total": len(events),
        "latest_ts": latest_ts,
        "severity_counts": dict(severity_counts),
        "top_rules": rule_counts.most_common(10),
        "top_sources": src_counts.most_common(10),
    }


def recommended_action(alert: dict[str, Any]) -> str:
    rule = str(alert.get("rule_id") or alert.get("rule_name") or "")
    event_type = str(alert.get("event_type") or "")

    if event_type.startswith("firewall"):
        return "Check whether this firewall action was expected. If not, inspect the source device and rule."
    if rule == "unknown_wifi_device_joined":
        return "Check if this device belongs to you. If not, deauthenticate it and block its MAC address."
    if rule == "large_outbound_flow":
        return "Usually normal during upload, sync, SSH, or speed test. Check whether this device was doing heavy traffic."
    if "dns" in rule:
        return "Check the domain. If you did not expect it, investigate the source device."
    if "scan" in rule or "syn" in rule:
        return "Check if this was your own test. If not, inspect or block the source device."
    if rule == "tcp_reset_spike":
        return "Check for unstable apps, blocked connections, or scanning behavior."
    if rule.startswith("test_"):
        return "This is a test alert. Disable the test rule after confirming the IDS works."
    return "Review the source device, destination ports, and whether this matches expected activity."


def load_yaml_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if data is not None else default
    except Exception:
        return default


def save_yaml_file(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def clean_text(value: Any, default: str = "") -> str:
    return str(value if value is not None else default).strip()


def clean_int(value: Any, default: int, minimum: int = 0, maximum: int = 10_000_000) -> int:
    try:
        number = int(value)
    except Exception:
        number = default
    return max(minimum, min(maximum, number))


def validate_rule_id(rule_id: str):
    if not ID_RE.match(rule_id):
        raise ValueError("Rule ID must be 3–80 characters and use only letters, numbers, underscore, or hyphen.")


def load_ids_config() -> dict[str, Any]:
    cfg = load_yaml_file(RULES_PATH, {})
    if isinstance(cfg, list):
        cfg = {"rules": cfg}
    if not isinstance(cfg, dict):
        cfg = {}
    cfg.setdefault("internal_networks", ["10.0.0.0/24"])
    cfg.setdefault("trusted_devices", [])
    cfg.setdefault("ignore_ips", ["10.0.0.1"])
    cfg.setdefault("rules", [])
    return cfg


def existing_ids_rule_ids(cfg: dict[str, Any]) -> set[str]:
    return {str(rule.get("id")) for rule in cfg.get("rules", []) if isinstance(rule, dict) and rule.get("id")}


def build_ids_rule(payload: dict[str, Any]) -> dict[str, Any]:
    rule_id = clean_text(payload.get("id"))
    validate_rule_id(rule_id)

    rule_type = clean_text(payload.get("type"))
    if rule_type not in VALID_IDS_TYPES:
        raise ValueError("Invalid IDS rule type.")

    severity = clean_text(payload.get("severity"), "low").lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError("Severity must be low, medium, or high.")

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": clean_text(payload.get("name"), rule_id),
        "type": rule_type,
        "severity": severity,
        "enabled": bool(payload.get("enabled", True)),
        "cooldown_seconds": clean_int(payload.get("cooldown_seconds"), 900, 0, 86400),
        "message": clean_text(payload.get("message"), "Custom IDS rule triggered."),
    }

    src_scope = clean_text(payload.get("src_scope"), "any").lower()
    if src_scope in {"internal", "external", "any"}:
        rule["src_scope"] = src_scope

    trusted_multiplier = clean_int(payload.get("trusted_device_multiplier"), 1, 1, 100)
    if trusted_multiplier > 1:
        rule["trusted_device_multiplier"] = trusted_multiplier

    if rule_type == "dns_domain":
        raw_domains = clean_text(payload.get("domains"))
        domains = []
        for part in re.split(r"[,\n]", raw_domains):
            domain = part.strip().lower().strip(".")
            if domain:
                domains.append(domain)
        if not domains:
            raise ValueError("DNS domain rules need at least one domain.")
        rule["match"] = {
            "domains": sorted(set(domains)),
            "match_subdomains": bool(payload.get("match_subdomains", True)),
        }
        return rule

    display_filter = clean_text(payload.get("filter"))
    if not display_filter:
        raise ValueError("Count rules need a tshark display filter.")

    threshold = clean_int(payload.get("threshold"), 1, 1, 10_000_000)
    window_seconds = clean_int(payload.get("window_seconds"), 300, 1, 86400)

    rule["filter"] = display_filter
    rule["threshold"] = threshold
    rule["window_seconds"] = window_seconds

    min_unique_dst_ips = clean_int(payload.get("min_unique_dst_ips"), 0, 0, 1_000_000)
    min_unique_dst_ports = clean_int(payload.get("min_unique_dst_ports"), 0, 0, 65535)
    if min_unique_dst_ips > 0:
        rule["min_unique_dst_ips"] = min_unique_dst_ips
    if min_unique_dst_ports > 0:
        rule["min_unique_dst_ports"] = min_unique_dst_ports

    return rule


def append_ids_rule(rule: dict[str, Any]) -> Path | None:
    cfg = load_ids_config()
    if rule["id"] in existing_ids_rule_ids(cfg):
        raise ValueError(f"An IDS rule with id '{rule['id']}' already exists.")
    backup = backup_file(RULES_PATH)
    cfg["rules"].append(rule)
    save_yaml_file(RULES_PATH, cfg)
    return backup


def load_firewall_config() -> dict[str, Any]:
    cfg = load_yaml_file(FIREWALL_RULES_PATH, {})
    if not isinstance(cfg, dict):
        cfg = {}
    cfg.setdefault("firewall_rules", [])
    return cfg


def existing_firewall_rule_ids(cfg: dict[str, Any]) -> set[str]:
    return {str(rule.get("id")) for rule in cfg.get("firewall_rules", []) if isinstance(rule, dict) and rule.get("id")}


def build_firewall_rule(payload: dict[str, Any]) -> dict[str, Any]:
    rule_id = clean_text(payload.get("id"))
    validate_rule_id(rule_id)

    action = clean_text(payload.get("action"), "DROP").upper()
    if action not in VALID_FIREWALL_ACTIONS:
        raise ValueError("Firewall action must be ACCEPT, DROP, or REJECT.")

    chain = clean_text(payload.get("chain"), "INPUT").upper()
    if chain not in VALID_FIREWALL_CHAINS:
        raise ValueError("Firewall chain must be INPUT or FORWARD.")

    protocol = clean_text(payload.get("protocol"), "tcp").lower()
    if protocol not in VALID_PROTOCOLS:
        raise ValueError("Protocol must be tcp, udp, icmp, or any.")

    interface_in = clean_text(payload.get("interface_in"))
    interface_out = clean_text(payload.get("interface_out"))
    if interface_in not in VALID_INTERFACES or interface_out not in VALID_INTERFACES:
        raise ValueError("Invalid interface. Use wlan1, eth0, tailscale0, wg0, or blank.")

    src_ip = clean_text(payload.get("src_ip"))
    src_mac = clean_text(payload.get("src_mac")).lower()
    dst_port_raw = clean_text(payload.get("dst_port"))

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": clean_text(payload.get("name"), rule_id),
        "enabled": bool(payload.get("enabled", True)),
        "chain": chain,
        "action": action,
        "protocol": protocol,
        "message": clean_text(payload.get("message"), "Custom firewall rule."),
    }

    if interface_in:
        rule["interface_in"] = interface_in
    if interface_out:
        rule["interface_out"] = interface_out
    if src_ip:
        rule["src_ip"] = src_ip
    if src_mac:
        if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", src_mac):
            raise ValueError("Source MAC must look like aa:bb:cc:dd:ee:ff.")
        rule["src_mac"] = src_mac
    if dst_port_raw:
        dst_port = clean_int(dst_port_raw, 0, 1, 65535)
        rule["dst_port"] = dst_port

    return rule


def firewall_rule_to_iptables(rule: dict[str, Any]) -> str:
    cmd = ["iptables", "-A", rule["chain"]]

    if rule.get("interface_in"):
        cmd += ["-i", str(rule["interface_in"])]
    if rule.get("interface_out") and rule["chain"] == "FORWARD":
        cmd += ["-o", str(rule["interface_out"])]
    if rule.get("protocol") and rule["protocol"] != "any":
        cmd += ["-p", str(rule["protocol"])]
    if rule.get("src_ip"):
        cmd += ["-s", str(rule["src_ip"])]
    if rule.get("src_mac"):
        cmd += ["-m", "mac", "--mac-source", str(rule["src_mac"])]
    if rule.get("dst_port") and rule.get("protocol") in {"tcp", "udp"}:
        cmd += ["--dport", str(rule["dst_port"])]
    cmd += ["-j", rule["action"]]
    return " ".join(cmd)


def generate_firewall_script() -> str:
    cfg = load_firewall_config()
    rules = [r for r in cfg.get("firewall_rules", []) if isinstance(r, dict) and r.get("enabled", True)]

    lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        "",
        "LAN_IF=\"wlan1\"",
        "WAN_IF=\"eth0\"",
        "TAILSCALE_IF=\"tailscale0\"",
        "LAN_NET=\"10.0.0.0/24\"",
        "",
        "sysctl -w net.ipv4.ip_forward=1 >/dev/null",
        "",
        "# Baseline NAT: <WIFI_SSID> -> school/internet side",
        "iptables -t nat -C POSTROUTING -s \"$LAN_NET\" -o \"$WAN_IF\" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s \"$LAN_NET\" -o \"$WAN_IF\" -j MASQUERADE",
        "",
        "# Baseline safety rules",
        "iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT",
        "",
        "# Allow Wi-Fi clients to use Pi DNS",
        "iptables -C INPUT -i \"$LAN_IF\" -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i \"$LAN_IF\" -p udp --dport 53 -j ACCEPT",
        "iptables -C INPUT -i \"$LAN_IF\" -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i \"$LAN_IF\" -p tcp --dport 53 -j ACCEPT",
        "",
        "# Block DNS and dashboard from school side",
        "iptables -C INPUT -i \"$WAN_IF\" -p udp --dport 53 -j DROP 2>/dev/null || iptables -I INPUT 1 -i \"$WAN_IF\" -p udp --dport 53 -j DROP",
        "iptables -C INPUT -i \"$WAN_IF\" -p tcp --dport 53 -j DROP 2>/dev/null || iptables -I INPUT 1 -i \"$WAN_IF\" -p tcp --dport 53 -j DROP",
        "iptables -C INPUT -i \"$WAN_IF\" -p tcp --dport 8000 -j DROP 2>/dev/null || iptables -I INPUT 1 -i \"$WAN_IF\" -p tcp --dport 8000 -j DROP",
        "",
        "# Allow dashboard and SSH from Wi-Fi and Tailscale",
        "iptables -C INPUT -i \"$LAN_IF\" -p tcp --dport 8000 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i \"$LAN_IF\" -p tcp --dport 8000 -j ACCEPT",
        "iptables -C INPUT -i \"$TAILSCALE_IF\" -p tcp --dport 8000 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i \"$TAILSCALE_IF\" -p tcp --dport 8000 -j ACCEPT",
        "iptables -C INPUT -i \"$LAN_IF\" -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i \"$LAN_IF\" -p tcp --dport 22 -j ACCEPT",
        "iptables -C INPUT -i \"$TAILSCALE_IF\" -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i \"$TAILSCALE_IF\" -p tcp --dport 22 -j ACCEPT",
        "",
        "# Allow Wi-Fi clients to reach internet through eth0",
        "iptables -C FORWARD -i \"$LAN_IF\" -o \"$WAN_IF\" -s \"$LAN_NET\" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i \"$LAN_IF\" -o \"$WAN_IF\" -s \"$LAN_NET\" -j ACCEPT",
        "",
        "# Custom firewall rules generated from firewall_rules.yaml",
    ]

    for rule in rules:
        lines.append(f"# {rule.get('id', 'custom_rule')}: {rule.get('message', '')}")
        lines.append(firewall_rule_to_iptables(rule))

    lines += [
        "",
        "echo \"[OK] Firewall rules applied.\"",
    ]

    script = "\n".join(lines) + "\n"
    FIREWALL_SH.write_text(script, encoding="utf-8")
    FIREWALL_SH.chmod(0o755)
    return script


def append_firewall_rule(rule: dict[str, Any]) -> Path | None:
    cfg = load_firewall_config()
    if rule["id"] in existing_firewall_rule_ids(cfg):
        raise ValueError(f"A firewall rule with id '{rule['id']}' already exists.")
    backup = backup_file(FIREWALL_RULES_PATH)
    cfg["firewall_rules"].append(rule)
    save_yaml_file(FIREWALL_RULES_PATH, cfg)
    generate_firewall_script()
    return backup


def append_firewall_event(event: dict[str, Any]):
    FIREWALL_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with FIREWALL_EVENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def restart_service(service_name: str) -> dict[str, Any]:
    if service_name not in {"ids-watch.service", "ids-firewall.service"}:
        return {"ok": False, "message": "Unsupported service."}
    res = subprocess.run(["sudo", "systemctl", "restart", service_name], capture_output=True, text=True)
    return {
        "ok": res.returncode == 0,
        "service": service_name,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
        "returncode": res.returncode,
    }


@app.get("/api/alerts")
def api_alerts(
    limit: int = Query(300, ge=1, le=3000),
    severity: str | None = None,
    src_ip: str | None = None,
    rule_id: str | None = None,
    event_source: str | None = None,
):
    ids_alerts = read_jsonl(ALERTS_FILE, limit=limit)
    firewall_events = read_jsonl(FIREWALL_EVENTS_FILE, limit=limit)

    for a in ids_alerts:
        a.setdefault("event_source", "ids")
    for e in firewall_events:
        e.setdefault("event_source", "firewall")
        e.setdefault("severity", "medium" if e.get("action") in {"DROP", "REJECT"} else "low")
        e.setdefault("rule_id", e.get("rule_name", "firewall_event"))
        e.setdefault("message", e.get("reason") or e.get("message") or "Firewall event")

    events = ids_alerts + firewall_events
    events.sort(key=lambda x: str(x.get("ts", "")))

    if event_source:
        events = [a for a in events if str(a.get("event_source") or "") == event_source]
    if severity:
        events = [a for a in events if (a.get("severity") or "").lower() == severity.lower()]
    if src_ip:
        events = [a for a in events if str(a.get("src_ip") or "") == src_ip]
    if rule_id:
        events = [a for a in events if str(a.get("rule_id") or "") == rule_id]

    for event in events:
        event["recommended_action"] = recommended_action(event)

    return JSONResponse({"alerts": events[-limit:], "summary": summarize_events(events)})


@app.get("/api/stats")
def api_stats(limit: int = Query(1000, ge=1, le=5000)):
    ids_alerts = read_jsonl(ALERTS_FILE, limit=limit)
    firewall_events = read_jsonl(FIREWALL_EVENTS_FILE, limit=limit)
    for a in ids_alerts:
        a.setdefault("event_source", "ids")
    for e in firewall_events:
        e.setdefault("event_source", "firewall")
        e.setdefault("severity", "medium" if e.get("action") in {"DROP", "REJECT"} else "low")
        e.setdefault("rule_id", e.get("rule_name", "firewall_event"))
    events = ids_alerts + firewall_events
    events.sort(key=lambda x: str(x.get("ts", "")))
    summary = summarize_events(events)
    summary["ids_alerts"] = len(ids_alerts)
    summary["firewall_events"] = len(firewall_events)
    summary["trusted_device_alerts"] = sum(1 for a in ids_alerts if a.get("trusted_device") is True)
    summary["internal_alerts"] = sum(1 for a in ids_alerts if a.get("src_scope") == "internal")
    summary["debug_tail"] = read_debug_tail(30)
    summary["server_time"] = datetime.now().astimezone().isoformat()
    return JSONResponse(summary)


@app.get("/api/debug")
def api_debug(limit: int = Query(80, ge=1, le=500)):
    return JSONResponse({"lines": read_debug_tail(limit)})


@app.get("/api/rules/ids")
def api_get_ids_rules():
    return JSONResponse(load_ids_config())


@app.post("/api/rules/ids/preview")
def api_preview_ids_rule(payload: dict[str, Any] = Body(...)):
    try:
        rule = build_ids_rule(payload)
        return JSONResponse({"ok": True, "rule": rule, "yaml": yaml.safe_dump([rule], sort_keys=False)})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/api/rules/ids/save")
def api_save_ids_rule(payload: dict[str, Any] = Body(...)):
    try:
        rule = build_ids_rule(payload)
        backup = append_ids_rule(rule)
        restart = bool(payload.get("restart_service", False))
        restart_result = restart_service("ids-watch.service") if restart else {"ok": None, "message": "Restart not requested."}
        return JSONResponse({"ok": True, "rule": rule, "backup": str(backup) if backup else None, "restart": restart_result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.get("/api/rules/firewall")
def api_get_firewall_rules():
    return JSONResponse(load_firewall_config())


@app.post("/api/rules/firewall/preview")
def api_preview_firewall_rule(payload: dict[str, Any] = Body(...)):
    try:
        rule = build_firewall_rule(payload)
        command = firewall_rule_to_iptables(rule)
        return JSONResponse({"ok": True, "rule": rule, "iptables": command})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


@app.post("/api/rules/firewall/save")
def api_save_firewall_rule(payload: dict[str, Any] = Body(...)):
    try:
        rule = build_firewall_rule(payload)
        backup = append_firewall_rule(rule)
        append_firewall_event({
            "ts": now_iso(),
            "event_type": "firewall_rule_created",
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "action": rule["action"],
            "severity": "low",
            "message": f"Firewall rule created: {rule['name']}",
        })
        restart = bool(payload.get("restart_service", False))
        restart_result = restart_service("ids-firewall.service") if restart else {"ok": None, "message": "Restart not requested."}
        return JSONResponse({"ok": True, "rule": rule, "backup": str(backup) if backup else None, "firewall_sh": str(FIREWALL_SH), "restart": restart_result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

@app.get("/api/siem/summary")
def api_siem_summary():
    if not siem_db_exists():
        return JSONResponse({
            "ok": False,
            "error": f"SIEM database not found: {SIEM_DB}",
            "security_events": 0,
            "network_flows": 0,
            "dns_queries": 0,
            "devices": 0,
            "processed_pcaps": 0,
            "top_sources": [],
            "top_dns": [],
            "top_rules": [],
        })

    conn = connect_siem_db()
    try:
        summary = {"ok": True}

        for table in [
            "security_events",
            "network_flows",
            "dns_queries",
            "devices",
            "processed_pcaps",
        ]:
            summary[table] = conn.execute(
                f"SELECT COUNT(*) AS c FROM {table}"
            ).fetchone()["c"]

        summary["top_sources"] = rows_to_dicts(conn.execute(
            """
            SELECT src_ip, COUNT(*) AS flow_count, COALESCE(SUM(bytes), 0) AS total_bytes
            FROM network_flows
            WHERE src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY flow_count DESC
            LIMIT 10
            """
        ).fetchall())

        summary["top_dns"] = rows_to_dicts(conn.execute(
            """
            SELECT query, COUNT(*) AS count
            FROM dns_queries
            WHERE query IS NOT NULL AND query != ''
            GROUP BY query
            ORDER BY count DESC
            LIMIT 10
            """
        ).fetchall())

        summary["top_rules"] = rows_to_dicts(conn.execute(
            """
            SELECT rule_id, COUNT(*) AS count
            FROM security_events
            WHERE rule_id IS NOT NULL AND rule_id != ''
            GROUP BY rule_id
            ORDER BY count DESC
            LIMIT 10
            """
        ).fetchall())

        return JSONResponse(summary)
    finally:
        conn.close()


@app.get("/api/siem/events")
def api_siem_events(
    limit: int = Query(100, ge=1, le=1000),
    source: str | None = None,
    severity: str | None = None,
    src_ip: str | None = None,
    rule_id: str | None = None,
):
    if not siem_db_exists():
        return JSONResponse({
            "ok": False,
            "events": [],
            "error": f"SIEM database not found: {SIEM_DB}",
        })

    query = "SELECT * FROM security_events WHERE 1=1"
    params: list[Any] = []

    if source:
        query += " AND event_source = ?"
        params.append(source)

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)

    if rule_id:
        query += " AND rule_id = ?"
        params.append(rule_id)

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    conn = connect_siem_db()
    try:
        events = rows_to_dicts(conn.execute(query, params).fetchall())
        return JSONResponse({"ok": True, "events": events})
    finally:
        conn.close()


@app.get("/api/siem/flows")
def api_siem_flows(
    limit: int = Query(100, ge=1, le=1000),
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: str | None = None,
    protocol: str | None = None,
):
    if not siem_db_exists():
        return JSONResponse({
            "ok": False,
            "flows": [],
            "error": f"SIEM database not found: {SIEM_DB}",
        })

    query = "SELECT * FROM network_flows WHERE 1=1"
    params: list[Any] = []

    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)

    if dst_ip:
        query += " AND dst_ip = ?"
        params.append(dst_ip)

    if dst_port:
        query += " AND dst_port = ?"
        params.append(dst_port)

    if protocol:
        query += " AND protocol = ?"
        params.append(protocol)

    query += " ORDER BY last_seen DESC LIMIT ?"
    params.append(limit)

    conn = connect_siem_db()
    try:
        flows = rows_to_dicts(conn.execute(query, params).fetchall())
        return JSONResponse({"ok": True, "flows": flows})
    finally:
        conn.close()


@app.get("/api/siem/dns")
def api_siem_dns(
    limit: int = Query(100, ge=1, le=1000),
    src_ip: str | None = None,
    query_text: str | None = None,
):
    if not siem_db_exists():
        return JSONResponse({
            "ok": False,
            "dns": [],
            "error": f"SIEM database not found: {SIEM_DB}",
        })

    query = "SELECT * FROM dns_queries WHERE 1=1"
    params: list[Any] = []

    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)

    if query_text:
        query += " AND query LIKE ?"
        params.append(f"%{query_text}%")

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    conn = connect_siem_db()
    try:
        dns_rows = rows_to_dicts(conn.execute(query, params).fetchall())
        return JSONResponse({"ok": True, "dns": dns_rows})
    finally:
        conn.close()


@app.get("/api/siem/devices")
def api_siem_devices():
    if not siem_db_exists():
        return JSONResponse({
            "ok": False,
            "devices": [],
            "error": f"SIEM database not found: {SIEM_DB}",
        })

    conn = connect_siem_db()
    try:
        devices = rows_to_dicts(conn.execute(
            """
            SELECT *
            FROM devices
            ORDER BY last_seen DESC
            LIMIT 200
            """
        ).fetchall())

        return JSONResponse({"ok": True, "devices": devices})
    finally:
        conn.close()

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


DASHBOARD_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Pi Security Dashboard</title>
  <style>
    body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: #f5f5f5; color: #111; }
    header { background: #fff; border-bottom: 1px solid #d0d0d0; padding: 16px 20px; }
    h1 { margin: 0; font-size: 24px; }
    .subtitle { margin-top: 4px; color: #555; font-size: 14px; }
    nav { background: #fff; border-bottom: 1px solid #d0d0d0; padding: 0 20px; display: flex; gap: 8px; }
    nav button { border: 0; border-right: 1px solid #ddd; border-left: 1px solid #ddd; padding: 12px 18px; background: #fff; cursor: pointer; font-size: 14px; }
    nav button.active { background: #e9e9e9; font-weight: bold; }
    main { padding: 18px 20px; }
    .page { display: none; }
    .page.active { display: block; }
    .summary { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin-bottom: 16px; }
    .box, .section { background: #fff; border: 1px solid #d0d0d0; padding: 14px; margin-bottom: 16px; }
    .box-title { font-size: 13px; color: #555; margin-bottom: 8px; }
    .box-value { font-size: 28px; font-weight: bold; }
    .time-value { font-size: 17px; font-weight: bold; line-height: 1.4; }
    h2 { margin: 0 0 12px 0; font-size: 18px; }
    h3 { margin: 16px 0 10px; font-size: 16px; }
    .layout { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; }
    .filters { display: grid; grid-template-columns: 150px 130px 1fr 1fr auto; gap: 8px; margin-bottom: 12px; }
    .form-grid { display: grid; grid-template-columns: repeat(2, minmax(220px, 1fr)); gap: 10px; }
    .form-row { display: flex; flex-direction: column; gap: 4px; }
    .form-row.full { grid-column: 1 / -1; }
    label { font-size: 13px; color: #333; font-weight: bold; }
    select, input, textarea, button { padding: 8px; border: 1px solid #aaa; background: #fff; color: #111; font-size: 14px; }
    textarea { min-height: 74px; font-family: Arial, Helvetica, sans-serif; }
    button { cursor: pointer; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #f0f0f0; font-weight: bold; }
    .table-wrap { max-height: 620px; overflow: auto; border: 1px solid #ddd; }
    .severity { font-weight: bold; text-transform: uppercase; }
    .severity.high { color: #9b0000; }
    .severity.medium { color: #8a5a00; }
    .severity.low { color: #004b8d; }
    .small { font-size: 12px; color: #555; }
    .list-item { display: flex; justify-content: space-between; border-bottom: 1px solid #ddd; padding: 7px 0; font-size: 14px; }
    .details { line-height: 1.5; font-size: 14px; }
    .details-row { margin-bottom: 8px; }
    pre { white-space: pre-wrap; word-break: break-word; background: #f0f0f0; border: 1px solid #ddd; padding: 10px; max-height: 280px; overflow: auto; font-size: 12px; }
    .status { margin-top: 10px; padding: 10px; border: 1px solid #d0d0d0; background: #f8f8f8; white-space: pre-wrap; }
    .radio-row { display: flex; gap: 16px; margin-bottom: 12px; }
    .hidden { display: none; }
    @media (max-width: 1150px) { .summary { grid-template-columns: repeat(3, 1fr); } }
    @media (max-width: 950px) { .layout { grid-template-columns: 1fr; } .summary { grid-template-columns: repeat(2, 1fr); } .filters, .form-grid { grid-template-columns: 1fr; } }
    @media (max-width: 520px) { .summary { grid-template-columns: 1fr; } main { padding: 10px; } header { padding: 12px; } nav { padding: 0 10px; overflow-x: auto; } }
  </style>
</head>
<body>
  <header>
    <h1>Pi Security Dashboard</h1>
    <div class="subtitle">Alerts, rule creation, and future SIEM for your Raspberry Pi security gateway</div>
  </header>

  <nav>
    <button id="tabAlerts" class="active" onclick="showPage('alerts')">Alerts</button>
    <button id="tabCreate" onclick="showPage('create')">Create Rule</button>
    <button id="tabSiem" onclick="showPage('siem')">SIEM</button>
  </nav>

  <main>
    <section id="pageAlerts" class="page active">
      <section class="summary">
        <div class="box"><div class="box-title">Total events</div><div class="box-value" id="totalAlerts">0</div></div>
        <div class="box"><div class="box-title">High</div><div class="box-value" id="highAlerts">0</div></div>
        <div class="box"><div class="box-title">Medium</div><div class="box-value" id="mediumAlerts">0</div></div>
        <div class="box"><div class="box-title">Low</div><div class="box-value" id="lowAlerts">0</div></div>
        <div class="box"><div class="box-title">Latest event</div><div class="box-value" id="latestAlert" style="font-size:16px;">—</div></div>
        <div class="box"><div class="box-title">Current dashboard time</div><div class="time-value" id="serverTime">Loading...</div><div class="small" id="lastRefresh">Last refreshed: —</div></div>
      </section>

      <div class="layout">
        <section class="section">
          <h2>Alerts and Firewall Events</h2>
          <div class="filters">
            <select id="severityFilter" onchange="loadDashboard()"><option value="">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
            <select id="sourceFilter" onchange="loadDashboard()"><option value="">All sources</option><option value="ids">IDS</option><option value="firewall">Firewall</option></select>
            <input id="srcFilter" placeholder="Filter source IP" oninput="debouncedLoad()" />
            <input id="ruleFilter" placeholder="Filter rule ID" oninput="debouncedLoad()" />
            <button onclick="loadDashboard()">Refresh</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Rule</th><th>Device/IP</th><th>Count/Action</th><th>Meaning</th><th>Next step</th></tr></thead>
              <tbody id="alertsTable"></tbody>
            </table>
          </div>
        </section>

        <aside>
          <section class="section"><h2>Top source IPs</h2><div id="topSources"></div></section>
          <section class="section"><h2>Top rules</h2><div id="topRules"></div></section>
          <section class="section"><h2>Selected event details</h2><div id="selectedAlert" class="details">Click an event row to see details here.</div></section>
          <section class="section"><h2>Debug log</h2><pre id="debugLog">No debug lines.</pre></section>
        </aside>
      </div>
    </section>

    <section id="pageCreate" class="page">
      <section class="section">
        <h2>Create Rule</h2>
        <div class="radio-row">
          <label><input type="radio" name="ruleMode" value="ids" checked onchange="toggleRuleForm()"> IDS Rule</label>
          <label><input type="radio" name="ruleMode" value="firewall" onchange="toggleRuleForm()"> Firewall Rule</label>
        </div>
        <p class="small">The dashboard validates your input first. It does not accept raw shell commands from the form.</p>
      </section>

      <section id="idsFormSection" class="section">
        <h2>New IDS Rule</h2>
        <div class="form-grid">
          <div class="form-row"><label>Rule ID</label><input id="ids_id" placeholder="custom_syn_rule"></div>
          <div class="form-row"><label>Name</label><input id="ids_name" placeholder="Custom SYN rule"></div>
          <div class="form-row"><label>Type</label><select id="ids_type" onchange="toggleIdsType()"><option value="count_by_src">count_by_src</option><option value="count_by_src_dstport">count_by_src_dstport</option><option value="dns_domain">dns_domain</option></select></div>
          <div class="form-row"><label>Severity</label><select id="ids_severity"><option value="low">low</option><option value="medium">medium</option><option value="high">high</option></select></div>
          <div class="form-row"><label>Threshold</label><input id="ids_threshold" type="number" value="100"></div>
          <div class="form-row"><label>Window seconds</label><input id="ids_window" type="number" value="300"></div>
          <div class="form-row"><label>Cooldown seconds</label><input id="ids_cooldown" type="number" value="900"></div>
          <div class="form-row"><label>Source scope</label><select id="ids_src_scope"><option value="any">any</option><option value="internal">internal</option><option value="external">external</option></select></div>
          <div class="form-row"><label>Trusted device multiplier</label><input id="ids_trusted_multiplier" type="number" value="1"></div>
          <div class="form-row"><label>Min unique destination ports</label><input id="ids_min_ports" type="number" value="0"></div>
          <div class="form-row full" id="idsFilterRow"><label>Tshark display filter</label><input id="ids_filter" placeholder="tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src"></div>
          <div class="form-row full hidden" id="idsDomainsRow"><label>Domains, comma or line separated</label><textarea id="ids_domains" placeholder="ngrok.io&#10;duckdns.org"></textarea></div>
          <div class="form-row full"><label>Message</label><textarea id="ids_message" placeholder="Explain what this alert means."></textarea></div>
          <div class="form-row"><label><input id="ids_enabled" type="checkbox" checked> Enabled</label></div>
          <div class="form-row"><label><input id="ids_restart" type="checkbox"> Restart ids-watch.service after save</label></div>
        </div>
        <p><button onclick="previewIdsRule()">Preview IDS Rule</button> <button onclick="saveIdsRule()">Save IDS Rule</button></p>
        <pre id="idsPreview">Preview will appear here.</pre>
        <div id="idsStatus" class="status">No action yet.</div>
      </section>

      <section id="firewallFormSection" class="section hidden">
        <h2>New Firewall Rule</h2>
        <div class="form-grid">
          <div class="form-row"><label>Rule ID</label><input id="fw_id" placeholder="block_unknown_mac"></div>
          <div class="form-row"><label>Name</label><input id="fw_name" placeholder="Block unknown device"></div>
          <div class="form-row"><label>Chain</label><select id="fw_chain"><option value="INPUT">INPUT - traffic to Pi</option><option value="FORWARD">FORWARD - traffic through Pi</option></select></div>
          <div class="form-row"><label>Action</label><select id="fw_action"><option value="DROP">DROP</option><option value="REJECT">REJECT</option><option value="ACCEPT">ACCEPT</option></select></div>
          <div class="form-row"><label>Protocol</label><select id="fw_protocol"><option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option><option value="any">any</option></select></div>
          <div class="form-row"><label>Interface in</label><select id="fw_interface_in"><option value="wlan1">wlan1</option><option value="eth0">eth0</option><option value="tailscale0">tailscale0</option><option value="wg0">wg0</option><option value="">blank</option></select></div>
          <div class="form-row"><label>Interface out</label><select id="fw_interface_out"><option value="">blank</option><option value="eth0">eth0</option><option value="wlan1">wlan1</option><option value="tailscale0">tailscale0</option><option value="wg0">wg0</option></select></div>
          <div class="form-row"><label>Destination port</label><input id="fw_dst_port" type="number" placeholder="8000"></div>
          <div class="form-row"><label>Source IP</label><input id="fw_src_ip" placeholder="10.0.0.44"></div>
          <div class="form-row"><label>Source MAC</label><input id="fw_src_mac" placeholder="aa:bb:cc:dd:ee:ff"></div>
          <div class="form-row full"><label>Message</label><textarea id="fw_message" placeholder="Why this firewall rule exists."></textarea></div>
          <div class="form-row"><label><input id="fw_enabled" type="checkbox" checked> Enabled</label></div>
          <div class="form-row"><label><input id="fw_restart" type="checkbox"> Restart ids-firewall.service after save</label></div>
        </div>
        <p><button onclick="previewFirewallRule()">Preview Firewall Rule</button> <button onclick="saveFirewallRule()">Save Firewall Rule</button></p>
        <pre id="fwPreview">Preview will appear here.</pre>
        <div id="fwStatus" class="status">No action yet.</div>
      </section>
    </section>

    
    <section id="pageSiem" class="page">
        <section class="summary">
            <div class="box">
            <div class="box-title">Security events</div>
            <div class="box-value" id="siemSecurityEvents">0</div>
            </div>

            <div class="box">
            <div class="box-title">Network flows</div>
            <div class="box-value" id="siemNetworkFlows">0</div>
            </div>

            <div class="box">
            <div class="box-title">DNS queries</div>
            <div class="box-value" id="siemDnsQueries">0</div>
            </div>

            <div class="box">
            <div class="box-title">Devices</div>
            <div class="box-value" id="siemDevices">0</div>
            </div>

            <div class="box">
            <div class="box-title">Processed PCAPs</div>
            <div class="box-value" id="siemPcaps">0</div>
            </div>
        </section>

        <div id="siemError" class="status">SIEM database status will appear here.</div>

        <div class="layout">
            <section class="section">
            <h2>SIEM Security Events</h2>

            <div class="filters">
                <select id="siemEventSource" onchange="loadSiemEvents()">
                <option value="">All sources</option>
                <option value="ids">IDS</option>
                <option value="firewall">Firewall</option>
                </select>

                <select id="siemEventSeverity" onchange="loadSiemEvents()">
                <option value="">All severities</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                </select>

                <input id="siemEventSrcIp" placeholder="Source IP" oninput="debouncedLoadSiemEvents()" />
                <input id="siemEventRule" placeholder="Rule ID" oninput="debouncedLoadSiemEvents()" />
                <button onclick="loadSiemEvents()">Search</button>
            </div>

            <div class="table-wrap">
                <table>
                <thead>
                    <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Source IP</th>
                    <th>Action</th>
                    <th>Message</th>
                    </tr>
                </thead>
                <tbody id="siemEventsTable"></tbody>
                </table>
            </div>
            </section>

            <aside>
            <section class="section">
                <h2>Top flow sources</h2>
                <div id="siemTopSources"></div>
            </section>

            <section class="section">
                <h2>Top DNS queries</h2>
                <div id="siemTopDns"></div>
            </section>

            <section class="section">
                <h2>Top SIEM rules</h2>
                <div id="siemTopRules"></div>
            </section>
            </aside>
        </div>

        <section class="section">
            <h2>Network Flows</h2>

            <div class="filters">
            <input id="siemFlowSrcIp" placeholder="Source IP" oninput="debouncedLoadSiemFlows()" />
            <input id="siemFlowDstIp" placeholder="Destination IP" oninput="debouncedLoadSiemFlows()" />
            <input id="siemFlowDstPort" placeholder="Destination port" oninput="debouncedLoadSiemFlows()" />
            <select id="siemFlowProtocol" onchange="loadSiemFlows()">
                <option value="">Any protocol</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
            </select>
            <button onclick="loadSiemFlows()">Search</button>
            </div>

            <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>Last seen</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Packets</th>
                    <th>Bytes</th>
                    <th>PCAP</th>
                </tr>
                </thead>
                <tbody id="siemFlowsTable"></tbody>
            </table>
            </div>
        </section>

        <section class="section">
            <h2>DNS Queries</h2>

            <div class="filters">
            <input id="siemDnsSrcIp" placeholder="Source IP" oninput="debouncedLoadSiemDns()" />
            <input id="siemDnsQuery" placeholder="Domain contains" oninput="debouncedLoadSiemDns()" />
            <button onclick="loadSiemDns()">Search</button>
            </div>

            <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>Time</th>
                    <th>Source IP</th>
                    <th>DNS server</th>
                    <th>Query</th>
                    <th>Rcode</th>
                    <th>PCAP</th>
                </tr>
                </thead>
                <tbody id="siemDnsTable"></tbody>
            </table>
            </div>
        </section>

        <section class="section">
            <h2>Devices</h2>

            <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>Hostname</th>
                    <th>Trusted</th>
                    <th>Last seen</th>
                    <th>Source</th>
                </tr>
                </thead>
                <tbody id="siemDevicesTable"></tbody>
            </table>
            </div>
        </section>
        </section>
  </main>

  <script>
    let debounceTimer = null;
    let currentAlerts = [];
    let dashboardClockDate = new Date();
    let dashboardClockTimer = null;

    function escapeHtml(value) { return String(value ?? "").replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
    function formatTime(ts) { if (!ts) return "—"; const d = new Date(ts); return Number.isNaN(d.getTime()) ? ts : d.toLocaleString(); }
    function showPage(name) {
        for (const page of ['alerts','create','siem']) {
            document.getElementById('page' + page.charAt(0).toUpperCase() + page.slice(1)).classList.toggle('active', page === name);
            document.getElementById('tab' + page.charAt(0).toUpperCase() + page.slice(1)).classList.toggle('active', page === name);
        }

        if (name === 'siem') {
            loadSiem();
        }
    }
    function updateDashboardClockDisplay() { const el = document.getElementById('serverTime'); if (el) el.textContent = dashboardClockDate.toLocaleString(); }
    function startDashboardClock() { updateDashboardClockDisplay(); clearInterval(dashboardClockTimer); dashboardClockTimer = setInterval(() => { dashboardClockDate = new Date(dashboardClockDate.getTime() + 1000); updateDashboardClockDisplay(); }, 1000); }
    function syncDashboardClock(serverTime) { const parsed = new Date(serverTime); if (!Number.isNaN(parsed.getTime())) { dashboardClockDate = parsed; updateDashboardClockDisplay(); } }

    function renderList(id, items) {
      const el = document.getElementById(id);
      if (!items || items.length === 0) { el.innerHTML = '<div class="small">No data.</div>'; return; }
      el.innerHTML = items.map(([name, count]) => `<div class="list-item"><span>${escapeHtml(name)}</span><strong>${escapeHtml(count)}</strong></div>`).join('');
    }

    function showDetails(index) {
      const a = currentAlerts[index]; if (!a) return;
      const dstIps = Array.isArray(a.sample_dst_ips) ? a.sample_dst_ips.join(', ') : '—';
      const dstPorts = Array.isArray(a.sample_dst_ports) ? a.sample_dst_ports.join(', ') : (a.dst_port || '—');
      document.getElementById('selectedAlert').innerHTML = `
        <div class="details-row"><strong>Event source:</strong> ${escapeHtml(a.event_source || 'ids')}</div>
        <div class="details-row"><strong>Rule:</strong> ${escapeHtml(a.rule_id || '—')}</div>
        <div class="details-row"><strong>Name:</strong> ${escapeHtml(a.rule_name || '—')}</div>
        <div class="details-row"><strong>Severity:</strong> ${escapeHtml(a.severity || '—')}</div>
        <div class="details-row"><strong>Time:</strong> ${escapeHtml(formatTime(a.ts))}</div>
        <div class="details-row"><strong>Source IP:</strong> ${escapeHtml(a.src_ip || '—')}</div>
        <div class="details-row"><strong>Action:</strong> ${escapeHtml(a.action || '—')}</div>
        <div class="details-row"><strong>Trusted device:</strong> ${a.trusted_device ? 'Yes' : 'No'}</div>
        <div class="details-row"><strong>Count:</strong> ${escapeHtml(a.count ?? '—')}</div>
        <div class="details-row"><strong>Threshold:</strong> ${escapeHtml(a.threshold ?? '—')}</div>
        <div class="details-row"><strong>Window:</strong> ${escapeHtml(a.window_seconds ?? '—')} seconds</div>
        <div class="details-row"><strong>Destination ports:</strong> ${escapeHtml(dstPorts)}</div>
        <div class="details-row"><strong>Sample destination IPs:</strong> ${escapeHtml(dstIps)}</div>
        <div class="details-row"><strong>PCAP:</strong> ${escapeHtml(a.pcap || '—')}</div>
        <div class="details-row"><strong>Meaning:</strong> ${escapeHtml(a.message || '—')}</div>
        <div class="details-row"><strong>Recommended next step:</strong> ${escapeHtml(a.recommended_action || 'Review this event.')}</div>`;
    }

    function renderAlerts(alerts) {
      const tbody = document.getElementById('alertsTable');
      if (!alerts.length) { tbody.innerHTML = '<tr><td colspan="8">No events found.</td></tr>'; return; }
      const reversed = alerts.slice().reverse(); currentAlerts = reversed;
      tbody.innerHTML = reversed.map((a, index) => {
        const sev = String(a.severity || 'unknown').toLowerCase();
        const countOrAction = a.action || (a.count !== undefined ? `${a.count}/${a.threshold ?? ''}` : '—');
        return `<tr onclick="showDetails(${index})" style="cursor:pointer;">
          <td>${escapeHtml(formatTime(a.ts))}<div class="small">${escapeHtml(a.pcap || '')}</div></td>
          <td>${escapeHtml(a.event_source || 'ids')}</td>
          <td><span class="severity ${escapeHtml(sev)}">${escapeHtml(sev)}</span></td>
          <td>${escapeHtml(a.rule_id || '')}<div class="small">${escapeHtml(a.rule_name || '')}</div></td>
          <td>${escapeHtml(a.src_ip || '—')}<div class="small">${a.trusted_device ? 'trusted' : ''}</div></td>
          <td>${escapeHtml(countOrAction)}</td>
          <td>${escapeHtml(a.message || '')}</td>
          <td>${escapeHtml(a.recommended_action || '')}</td>
        </tr>`;
      }).join('');
    }

    async function loadDashboard() {
      const severity = document.getElementById('severityFilter').value;
      const eventSource = document.getElementById('sourceFilter').value;
      const src = document.getElementById('srcFilter').value.trim();
      const rule = document.getElementById('ruleFilter').value.trim();
      const params = new URLSearchParams({ limit: '350' });
      if (severity) params.set('severity', severity);
      if (eventSource) params.set('event_source', eventSource);
      if (src) params.set('src_ip', src);
      if (rule) params.set('rule_id', rule);
      try {
        const [alertsResp, statsResp] = await Promise.all([fetch('/api/alerts?' + params.toString()), fetch('/api/stats?limit=1000')]);
        const alertsData = await alertsResp.json(); const statsData = await statsResp.json();
        const alerts = alertsData.alerts || []; const severityCounts = statsData.severity_counts || {};
        document.getElementById('totalAlerts').textContent = statsData.total ?? alerts.length;
        document.getElementById('highAlerts').textContent = severityCounts.high || 0;
        document.getElementById('mediumAlerts').textContent = severityCounts.medium || 0;
        document.getElementById('lowAlerts').textContent = severityCounts.low || 0;
        document.getElementById('latestAlert').textContent = formatTime(statsData.latest_ts);
        syncDashboardClock(statsData.server_time);
        document.getElementById('lastRefresh').textContent = 'Last refreshed: ' + formatTime(statsData.server_time || new Date());
        renderAlerts(alerts); renderList('topSources', statsData.top_sources || []); renderList('topRules', statsData.top_rules || []);
        document.getElementById('debugLog').textContent = (statsData.debug_tail || []).join('\n') || 'No debug lines.';
      } catch (err) {
        document.getElementById('alertsTable').innerHTML = '<tr><td colspan="8">Dashboard error. Check terminal output.</td></tr>';
        document.getElementById('lastRefresh').textContent = 'Last refreshed: failed'; console.error(err);
      }
    }
    function debouncedLoad() { clearTimeout(debounceTimer); debounceTimer = setTimeout(loadDashboard, 300); }

    function toggleRuleForm() {
      const mode = document.querySelector('input[name="ruleMode"]:checked').value;
      document.getElementById('idsFormSection').classList.toggle('hidden', mode !== 'ids');
      document.getElementById('firewallFormSection').classList.toggle('hidden', mode !== 'firewall');
    }
    function toggleIdsType() {
      const t = document.getElementById('ids_type').value;
      document.getElementById('idsFilterRow').classList.toggle('hidden', t === 'dns_domain');
      document.getElementById('idsDomainsRow').classList.toggle('hidden', t !== 'dns_domain');
    }

    function idsPayload() {
      return {
        id: document.getElementById('ids_id').value, name: document.getElementById('ids_name').value,
        type: document.getElementById('ids_type').value, severity: document.getElementById('ids_severity').value,
        threshold: document.getElementById('ids_threshold').value, window_seconds: document.getElementById('ids_window').value,
        cooldown_seconds: document.getElementById('ids_cooldown').value, src_scope: document.getElementById('ids_src_scope').value,
        trusted_device_multiplier: document.getElementById('ids_trusted_multiplier').value,
        min_unique_dst_ports: document.getElementById('ids_min_ports').value,
        filter: document.getElementById('ids_filter').value, domains: document.getElementById('ids_domains').value,
        message: document.getElementById('ids_message').value, enabled: document.getElementById('ids_enabled').checked,
        restart_service: document.getElementById('ids_restart').checked, match_subdomains: true
      };
    }
    function firewallPayload() {
      return {
        id: document.getElementById('fw_id').value, name: document.getElementById('fw_name').value,
        chain: document.getElementById('fw_chain').value, action: document.getElementById('fw_action').value,
        protocol: document.getElementById('fw_protocol').value, interface_in: document.getElementById('fw_interface_in').value,
        interface_out: document.getElementById('fw_interface_out').value, dst_port: document.getElementById('fw_dst_port').value,
        src_ip: document.getElementById('fw_src_ip').value, src_mac: document.getElementById('fw_src_mac').value,
        message: document.getElementById('fw_message').value, enabled: document.getElementById('fw_enabled').checked,
        restart_service: document.getElementById('fw_restart').checked
      };
    }
    async function postJson(url, payload) {
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await res.json();
      if (!res.ok || data.ok === false) throw new Error(data.error || JSON.stringify(data));
      return data;
    }
    async function previewIdsRule() {
      try { const data = await postJson('/api/rules/ids/preview', idsPayload()); document.getElementById('idsPreview').textContent = data.yaml; document.getElementById('idsStatus').textContent = 'Preview generated.'; }
      catch (err) { document.getElementById('idsStatus').textContent = 'Error: ' + err.message; }
    }
    async function saveIdsRule() {
      try { const data = await postJson('/api/rules/ids/save', idsPayload()); document.getElementById('idsStatus').textContent = 'Saved IDS rule. Backup: ' + (data.backup || 'none') + '\nRestart: ' + JSON.stringify(data.restart); document.getElementById('idsPreview').textContent = JSON.stringify(data.rule, null, 2); }
      catch (err) { document.getElementById('idsStatus').textContent = 'Error: ' + err.message; }
    }
    async function previewFirewallRule() {
      try { const data = await postJson('/api/rules/firewall/preview', firewallPayload()); document.getElementById('fwPreview').textContent = data.iptables; document.getElementById('fwStatus').textContent = 'Preview generated.'; }
      catch (err) { document.getElementById('fwStatus').textContent = 'Error: ' + err.message; }
    }
    async function saveFirewallRule() {
      try { const data = await postJson('/api/rules/firewall/save', firewallPayload()); document.getElementById('fwStatus').textContent = 'Saved firewall rule. Backup: ' + (data.backup || 'none') + '\nfirewall.sh: ' + data.firewall_sh + '\nRestart: ' + JSON.stringify(data.restart); document.getElementById('fwPreview').textContent = JSON.stringify(data.rule, null, 2); loadDashboard(); }
      catch (err) { document.getElementById('fwStatus').textContent = 'Error: ' + err.message; }
    }
    let siemEventTimer = null;
    let siemFlowTimer = null;
    let siemDnsTimer = null;

    function formatBytes(value) {
    let n = Number(value || 0);

    if (n >= 1073741824) {
        return (n / 1073741824).toFixed(2) + ' GB';
    }

    if (n >= 1048576) {
        return (n / 1048576).toFixed(2) + ' MB';
    }

    if (n >= 1024) {
        return (n / 1024).toFixed(2) + ' KB';
    }

    return n + ' B';
    }

    async function getJson(url) {
    const res = await fetch(url);
    const data = await res.json();

    if (!res.ok || data.ok === false) {
        throw new Error(data.error || JSON.stringify(data));
    }

    return data;
    }

    function renderSimpleList(id, rows, nameKey, valueKey, formatter) {
    const el = document.getElementById(id);

    if (!rows || rows.length === 0) {
        el.innerHTML = '<div class="small">No data.</div>';
        return;
    }

    el.innerHTML = rows.map(row => {
        const name = row[nameKey] || 'unknown';
        const value = formatter ? formatter(row[valueKey], row) : row[valueKey];

        return `
        <div class="list-item">
            <span>${escapeHtml(name)}</span>
            <strong>${escapeHtml(value)}</strong>
        </div>
        `;
    }).join('');
    }

    async function loadSiem() {
    await loadSiemSummary();
    await loadSiemEvents();
    await loadSiemFlows();
    await loadSiemDns();
    await loadSiemDevices();
    }

    async function loadSiemSummary() {
    try {
        const data = await getJson('/api/siem/summary');

        document.getElementById('siemError').textContent = 'SIEM database loaded successfully.';

        document.getElementById('siemSecurityEvents').textContent = data.security_events || 0;
        document.getElementById('siemNetworkFlows').textContent = data.network_flows || 0;
        document.getElementById('siemDnsQueries').textContent = data.dns_queries || 0;
        document.getElementById('siemDevices').textContent = data.devices || 0;
        document.getElementById('siemPcaps').textContent = data.processed_pcaps || 0;

        renderSimpleList(
        'siemTopSources',
        data.top_sources || [],
        'src_ip',
        'flow_count',
        (value, row) => `${value} flows / ${formatBytes(row.total_bytes)}`
        );

        renderSimpleList(
        'siemTopDns',
        data.top_dns || [],
        'query',
        'count'
        );

        renderSimpleList(
        'siemTopRules',
        data.top_rules || [],
        'rule_id',
        'count'
        );
    } catch (err) {
        document.getElementById('siemError').textContent = 'SIEM error: ' + err.message;
    }
    }

    async function loadSiemEvents() {
    const params = new URLSearchParams({ limit: '200' });

    const source = document.getElementById('siemEventSource').value;
    const severity = document.getElementById('siemEventSeverity').value;
    const srcIp = document.getElementById('siemEventSrcIp').value.trim();
    const ruleId = document.getElementById('siemEventRule').value.trim();

    if (source) params.set('source', source);
    if (severity) params.set('severity', severity);
    if (srcIp) params.set('src_ip', srcIp);
    if (ruleId) params.set('rule_id', ruleId);

    try {
        const data = await getJson('/api/siem/events?' + params.toString());
        const rows = data.events || [];

        document.getElementById('siemEventsTable').innerHTML = rows.map(e => `
        <tr>
            <td>${escapeHtml(e.ts || '')}</td>
            <td>${escapeHtml(e.event_source || '')}</td>
            <td>${escapeHtml(e.severity || '')}</td>
            <td>${escapeHtml(e.rule_id || '')}</td>
            <td>${escapeHtml(e.src_ip || '')}</td>
            <td>${escapeHtml(e.action || '')}</td>
            <td>${escapeHtml(e.message || '')}</td>
        </tr>
        `).join('') || '<tr><td colspan="7">No SIEM events.</td></tr>';
    } catch (err) {
        document.getElementById('siemEventsTable').innerHTML =
        '<tr><td colspan="7">SIEM events error: ' + escapeHtml(err.message) + '</td></tr>';
    }
    }

    async function loadSiemFlows() {
    const params = new URLSearchParams({ limit: '200' });

    const srcIp = document.getElementById('siemFlowSrcIp').value.trim();
    const dstIp = document.getElementById('siemFlowDstIp').value.trim();
    const dstPort = document.getElementById('siemFlowDstPort').value.trim();
    const protocol = document.getElementById('siemFlowProtocol').value;

    if (srcIp) params.set('src_ip', srcIp);
    if (dstIp) params.set('dst_ip', dstIp);
    if (dstPort) params.set('dst_port', dstPort);
    if (protocol) params.set('protocol', protocol);

    try {
        const data = await getJson('/api/siem/flows?' + params.toString());
        const rows = data.flows || [];

        document.getElementById('siemFlowsTable').innerHTML = rows.map(f => `
        <tr>
            <td>${escapeHtml(f.last_seen || '')}</td>
            <td>${escapeHtml(f.src_ip || '')}:${escapeHtml(f.src_port || '')}</td>
            <td>${escapeHtml(f.dst_ip || '')}:${escapeHtml(f.dst_port || '')}</td>
            <td>${escapeHtml(f.protocol || '')}</td>
            <td>${escapeHtml(f.packets || 0)}</td>
            <td>${escapeHtml(formatBytes(f.bytes || 0))}</td>
            <td>${escapeHtml(f.pcap || '')}</td>
        </tr>
        `).join('') || '<tr><td colspan="7">No flows.</td></tr>';
    } catch (err) {
        document.getElementById('siemFlowsTable').innerHTML =
        '<tr><td colspan="7">SIEM flows error: ' + escapeHtml(err.message) + '</td></tr>';
    }
    }

    async function loadSiemDns() {
    const params = new URLSearchParams({ limit: '200' });

    const srcIp = document.getElementById('siemDnsSrcIp').value.trim();
    const query = document.getElementById('siemDnsQuery').value.trim();

    if (srcIp) params.set('src_ip', srcIp);
    if (query) params.set('query_text', query);

    try {
        const data = await getJson('/api/siem/dns?' + params.toString());
        const rows = data.dns || [];

        document.getElementById('siemDnsTable').innerHTML = rows.map(d => `
        <tr>
            <td>${escapeHtml(d.ts || '')}</td>
            <td>${escapeHtml(d.src_ip || '')}</td>
            <td>${escapeHtml(d.dst_ip || '')}</td>
            <td>${escapeHtml(d.query || '')}</td>
            <td>${escapeHtml(d.rcode || '')}</td>
            <td>${escapeHtml(d.pcap || '')}</td>
        </tr>
        `).join('') || '<tr><td colspan="6">No DNS queries.</td></tr>';
    } catch (err) {
        document.getElementById('siemDnsTable').innerHTML =
        '<tr><td colspan="6">SIEM DNS error: ' + escapeHtml(err.message) + '</td></tr>';
    }
    }

    async function loadSiemDevices() {
    try {
        const data = await getJson('/api/siem/devices');
        const rows = data.devices || [];

        document.getElementById('siemDevicesTable').innerHTML = rows.map(d => `
        <tr>
            <td>${escapeHtml(d.ip || '')}</td>
            <td>${escapeHtml(d.mac || '')}</td>
            <td>${escapeHtml(d.hostname || '')}</td>
            <td>${escapeHtml(d.trusted || 0)}</td>
            <td>${escapeHtml(d.last_seen || '')}</td>
            <td>${escapeHtml(d.source || '')}</td>
        </tr>
        `).join('') || '<tr><td colspan="6">No devices.</td></tr>';
    } catch (err) {
        document.getElementById('siemDevicesTable').innerHTML =
        '<tr><td colspan="6">SIEM devices error: ' + escapeHtml(err.message) + '</td></tr>';
    }
    }

    function debouncedLoadSiemEvents() {
    clearTimeout(siemEventTimer);
    siemEventTimer = setTimeout(loadSiemEvents, 300);
    }

    function debouncedLoadSiemFlows() {
    clearTimeout(siemFlowTimer);
    siemFlowTimer = setTimeout(loadSiemFlows, 300);
    }

    function debouncedLoadSiemDns() {
    clearTimeout(siemDnsTimer);
    siemDnsTimer = setTimeout(loadSiemDns, 300);
    }
    startDashboardClock(); toggleIdsType(); loadDashboard(); setInterval(loadDashboard, 5000);
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
