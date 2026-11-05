import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

BASE = os.path.expanduser("~/Desktop/IDS_Project")
PCAPS_IN = os.path.join(BASE, "pcaps_in")
PCAPS_WORK = os.path.join(BASE, "pcaps_work")
PCAPS_ARCHIVE = os.path.join(BASE, "pcaps_archive")
ALERTS_FILE = os.path.join(BASE, "ids_alerts", "alert.jsonl")
RULES_PATH = os.path.join(BASE, "rules_v3.yaml")
DEBUG_LOG = os.path.join(BASE, "ids_alerts", "ids_debug.log")

DEFAULT_COOLDOWN_SECONDS = 300
DEFAULT_WINDOW_SECONDS = 300
MAX_STATE_AGE_SECONDS = 3600

IGNORE_IPS: set[str] = set()
TRUSTED_DEVICES: set[str] = set()
INTERNAL_NETWORKS: list[ipaddress._BaseNetwork] = []
ALERT_STATE: dict[str, float] = {}

# Rolling event state: key to deque[(ts, event_dict)]
ROLLING_STATE: dict[str, deque[tuple[float, dict[str, Any]]]] = defaultdict(deque)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_epoch() -> float:
    return time.time()


def debug_log(message: str):
    os.makedirs(os.path.dirname(DEBUG_LOG), exist_ok=True)
    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{now_iso()}] {message}\n")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def ensure_dirs():
    os.makedirs(PCAPS_IN, exist_ok=True)
    os.makedirs(PCAPS_WORK, exist_ok=True)
    os.makedirs(PCAPS_ARCHIVE, exist_ok=True)
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)


def wait_until_stable(path: str, stable_checks: int = 5, interval: float = 0.2, max_wait: float = 20.0) -> bool:
    start = time.time()
    last_size = -1
    stable = 0
    while True:
        if time.time() - start > max_wait:
            debug_log(f"Timed out waiting for stable file: {path}")
            return False
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            debug_log(f"File disappeared before stability check completed: {path}")
            return False
        if size == last_size:
            stable += 1
            if stable >= stable_checks:
                return True
        else:
            stable = 0
            last_size = size
        time.sleep(interval)


def append_alert(alert: dict[str, Any]):
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def is_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_internal_ip(ip: str) -> bool:
    if not ip or not is_ip(ip):
        return False
    addr = ipaddress.ip_address(ip)
    return any(addr in network for network in INTERNAL_NETWORKS)


def is_trusted_device(ip: str) -> bool:
    return bool(ip) and ip in TRUSTED_DEVICES


def is_ignored_ip(ip: str) -> bool:
    return bool(ip) and ip in IGNORE_IPS


def src_scope_allowed(rule: dict[str, Any], src_ip: str) -> bool:
    scope = str(rule.get("src_scope", "any")).lower().strip()
    if scope in ("", "any", "all"):
        return True
    if scope == "internal":
        return is_internal_ip(src_ip)
    if scope == "external":
        return is_ip(src_ip) and not is_internal_ip(src_ip)
    debug_log(f"Unknown src_scope={scope!r} in rule {rule.get('id')!r}; treating as any")
    return True


def effective_threshold(rule: dict[str, Any], src_ip: str) -> int:
    base = parse_int(rule.get("threshold"), 0)
    if base <= 0:
        return 0
    if is_trusted_device(src_ip):
        multiplier = parse_int(rule.get("trusted_device_multiplier"), 1)
        if multiplier > 1:
            return base * multiplier
    return base


def parse_networks(values: list[Any]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for raw in values or []:
        try:
            networks.append(ipaddress.ip_network(str(raw), strict=False))
        except ValueError:
            debug_log(f"Invalid internal network ignored: {raw!r}")
    return networks


def build_alert_key(rule_id: str, fields: dict[str, Any]) -> str:
    stable = {
        "rule_id": rule_id,
        "src_ip": fields.get("src_ip"),
        "dst_ip": fields.get("dst_ip"),
        "dst_port": fields.get("dst_port"),
        "indicator": fields.get("indicator"),
        "proto": fields.get("proto"),
    }
    raw = json.dumps(stable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def should_emit(rule: dict[str, Any], extra: dict[str, Any]) -> bool:
    cooldown = parse_int(rule.get("cooldown_seconds"), DEFAULT_COOLDOWN_SECONDS)
    if cooldown <= 0:
        return True
    alert_key = build_alert_key(rule.get("id", "unknown_rule"), extra)
    now = now_epoch()
    last_seen = ALERT_STATE.get(alert_key)
    if last_seen is not None and now - last_seen < cooldown:
        return False
    ALERT_STATE[alert_key] = now
    return True


def emit_alert(rule: dict[str, Any], pcap_name: str, extra: dict[str, Any]):
    if not should_emit(rule, extra):
        return
    cooldown = parse_int(rule.get("cooldown_seconds"), DEFAULT_COOLDOWN_SECONDS)
    alert = {
        "ts": now_iso(),
        "rule_id": rule.get("id", "unknown_rule"),
        "rule_name": rule.get("name", "Unnamed rule"),
        "severity": rule.get("severity", "low"),
        "message": rule.get("message", ""),
        "cooldown_seconds": cooldown,
        "pcap": pcap_name,
        **extra,
    }
    append_alert(alert)


def tshark_fields(pcap_path: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    cmd = ["tshark", "-r", pcap_path, "-Y", display_filter, "-T", "fields"]
    for fld in fields:
        cmd += ["-e", fld]
    cmd += ["-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=f"]
    res = run(cmd)
    if res.returncode != 0:
        debug_log(
            "tshark failed | "
            f"pcap={pcap_path} filter={display_filter!r} rc={res.returncode} stderr={res.stderr.strip()!r}"
        )
        return []
    rows: list[list[str]] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if line:
            rows.append(line.split("\t"))
    return rows


def load_rules() -> list[dict[str, Any]]:
    global IGNORE_IPS, TRUSTED_DEVICES, INTERNAL_NETWORKS
    if not os.path.exists(RULES_PATH):
        append_alert({
            "ts": now_iso(),
            "rule_id": "rules_missing",
            "rule_name": "rules.yaml missing",
            "severity": "low",
            "message": f"Expected rules at {RULES_PATH}",
        })
        IGNORE_IPS = set()
        TRUSTED_DEVICES = set()
        INTERNAL_NETWORKS = []
        return []

    with open(RULES_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    if isinstance(cfg, list):
        IGNORE_IPS = set()
        TRUSTED_DEVICES = set()
        INTERNAL_NETWORKS = []
        rules = cfg
    else:
        IGNORE_IPS = set(str(x) for x in (cfg.get("ignore_ips", []) or []))
        TRUSTED_DEVICES = set(str(x) for x in (cfg.get("trusted_devices", []) or []))
        INTERNAL_NETWORKS = parse_networks(cfg.get("internal_networks", []) or [])
        rules = cfg.get("rules", []) or []

    enabled: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            debug_log(f"Skipping non-dict rule entry: {rule!r}")
            continue
        if not rule.get("enabled", True):
            continue
        if "id" not in rule or "type" not in rule:
            debug_log(f"Skipping malformed rule without id/type: {rule!r}")
            continue
        enabled.append(rule)
    return enabled


def prune_old_events(key: str, window_seconds: int):
    now = now_epoch()
    dq = ROLLING_STATE[key]
    keep_age = max(window_seconds, 1)
    while dq and now - dq[0][0] > keep_age:
        dq.popleft()


def add_rolling_events(rule: dict[str, Any], group_key: str, events: list[dict[str, Any]]):
    window = parse_int(rule.get("window_seconds"), DEFAULT_WINDOW_SECONDS)
    if window <= 0:
        window = DEFAULT_WINDOW_SECONDS
    state_key = f"{rule.get('id', 'unknown_rule')}|{group_key}"
    now = now_epoch()
    dq = ROLLING_STATE[state_key]
    for event in events:
        dq.append((now, event))
    prune_old_events(state_key, window)


def get_rolling_events(rule: dict[str, Any], group_key: str) -> list[dict[str, Any]]:
    window = parse_int(rule.get("window_seconds"), DEFAULT_WINDOW_SECONDS)
    if window <= 0:
        window = DEFAULT_WINDOW_SECONDS
    state_key = f"{rule.get('id', 'unknown_rule')}|{group_key}"
    prune_old_events(state_key, window)
    return [event for _, event in ROLLING_STATE[state_key]]


def cleanup_global_state():
    # Keeps memory bounded if the watcher runs for a long time.
    now = now_epoch()
    for key in list(ROLLING_STATE.keys()):
        dq = ROLLING_STATE[key]
        while dq and now - dq[0][0] > MAX_STATE_AGE_SECONDS:
            dq.popleft()
        if not dq:
            del ROLLING_STATE[key]
    for key, last_seen in list(ALERT_STATE.items()):
        if now - last_seen > MAX_STATE_AGE_SECONDS:
            del ALERT_STATE[key]


def eval_dns_domain(rule: dict[str, Any], pcap_path: str, pcap_name: str):
    match = rule.get("match", {})
    domains = [str(d).lower().strip(".") for d in match.get("domains", []) if str(d).strip()]
    domains_set = set(domains)
    match_sub = bool(match.get("match_subdomains", True))
    if not domains_set:
        return

    rows = tshark_fields(pcap_path, "dns && dns.qry.name && ip.src && ip.dst", ["ip.src", "ip.dst", "dns.qry.name"])
    seen_hits: set[tuple[str, str]] = set()
    for row in rows:
        src = row[0].strip() if len(row) > 0 else ""
        dst = row[1].strip() if len(row) > 1 else ""
        qname = row[2].strip() if len(row) > 2 else ""
        if not src or not qname or is_ignored_ip(src) or is_ignored_ip(dst):
            continue
        if not src_scope_allowed(rule, src):
            continue
        q = qname.lower().strip(".")
        hit = (q in domains_set) or (match_sub and any(q.endswith("." + d) for d in domains_set))
        if not hit:
            continue
        hit_key = (src, q)
        if hit_key in seen_hits:
            continue
        seen_hits.add(hit_key)
        emit_alert(rule, pcap_name, {
            "src_ip": src,
            "dst_ip": dst,
            "indicator": q,
            "proto": "dns",
            "src_scope": "internal" if is_internal_ip(src) else "external",
            "trusted_device": is_trusted_device(src),
        })


def row_to_event(row: list[str]) -> dict[str, Any]:
    src = row[0].strip() if len(row) > 0 else ""
    dst = row[1].strip() if len(row) > 1 else ""
    tcp_dport = row[2].strip() if len(row) > 2 else ""
    udp_dport = row[3].strip() if len(row) > 3 else ""
    ip_proto = row[4].strip() if len(row) > 4 else ""
    dport = tcp_dport or udp_dport
    if tcp_dport:
        proto = "tcp"
    elif udp_dport:
        proto = "udp"
    else:
        proto = ip_proto or "unknown"
    return {"src_ip": src, "dst_ip": dst, "dst_port": dport, "proto": proto}


def evaluate_rolling(rule: dict[str, Any], pcap_name: str, group_key: str, src_ip: str, events: list[dict[str, Any]], dst_port: str | None = None):
    if not events:
        return
    add_rolling_events(rule, group_key, events)
    rolling_events = get_rolling_events(rule, group_key)
    threshold = effective_threshold(rule, src_ip)
    if threshold <= 0 or len(rolling_events) < threshold:
        return

    unique_dst_ips = sorted({e.get("dst_ip") for e in rolling_events if e.get("dst_ip")})
    unique_dst_ports = sorted({str(e.get("dst_port")) for e in rolling_events if e.get("dst_port")})

    min_unique_dst_ips = parse_int(rule.get("min_unique_dst_ips"), 0)
    min_unique_dst_ports = parse_int(rule.get("min_unique_dst_ports"), 0)
    if min_unique_dst_ips and len(unique_dst_ips) < min_unique_dst_ips:
        return
    if min_unique_dst_ports and len(unique_dst_ports) < min_unique_dst_ports:
        return

    extra: dict[str, Any] = {
        "src_ip": src_ip,
        "count": len(rolling_events),
        "threshold": threshold,
        "base_threshold": parse_int(rule.get("threshold"), 0),
        "window_seconds": parse_int(rule.get("window_seconds"), DEFAULT_WINDOW_SECONDS),
        "filter": str(rule.get("filter", "")).strip(),
        "unique_dst_ips": len(unique_dst_ips),
        "sample_dst_ips": unique_dst_ips[:5],
        "unique_dst_ports": len(unique_dst_ports),
        "sample_dst_ports": unique_dst_ports[:10],
        "src_scope": "internal" if is_internal_ip(src_ip) else "external",
        "trusted_device": is_trusted_device(src_ip),
    }
    if dst_port is not None:
        extra["dst_port"] = int(dst_port) if str(dst_port).isdigit() else dst_port
        proto_values = {e.get("proto") for e in rolling_events if e.get("proto")}
        extra["proto"] = sorted(proto_values)[0] if proto_values else "unknown"
    emit_alert(rule, pcap_name, extra)


def eval_count_by_src(rule: dict[str, Any], pcap_path: str, pcap_name: str):
    display_filter = str(rule.get("filter", "")).strip()
    if not display_filter or parse_int(rule.get("threshold"), 0) <= 0:
        return
    rows = tshark_fields(pcap_path, display_filter, ["ip.src", "ip.dst", "tcp.dstport", "udp.dstport", "ip.proto"])
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        event = row_to_event(row)
        src = event.get("src_ip", "")
        if not src or is_ignored_ip(src):
            continue
        if not src_scope_allowed(rule, src):
            continue
        grouped[src].append(event)
    for src, events in grouped.items():
        evaluate_rolling(rule, pcap_name, src, src, events)


def eval_count_by_src_dstport(rule: dict[str, Any], pcap_path: str, pcap_name: str):
    display_filter = str(rule.get("filter", "")).strip()
    if not display_filter or parse_int(rule.get("threshold"), 0) <= 0:
        return
    rows = tshark_fields(pcap_path, display_filter, ["ip.src", "ip.dst", "tcp.dstport", "udp.dstport", "ip.proto"])
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        event = row_to_event(row)
        src = event.get("src_ip", "")
        dport = str(event.get("dst_port") or "")
        if not src or not dport or is_ignored_ip(src):
            continue
        if not src_scope_allowed(rule, src):
            continue
        grouped[(src, dport)].append(event)
    for (src, dport), events in grouped.items():
        evaluate_rolling(rule, pcap_name, f"{src}|{dport}", src, events, dst_port=dport)


RULE_DISPATCH = {
    "dns_domain": eval_dns_domain,
    "count_by_src": eval_count_by_src,
    "count_by_src_dstport": eval_count_by_src_dstport,
}


def analyze_pcap(pcap_path: str):
    cleanup_global_state()
    pcap_name = os.path.basename(pcap_path)
    rules = load_rules()
    if not rules:
        debug_log(f"No enabled rules loaded for {pcap_name}")
        return
    for rule in rules:
        fn = RULE_DISPATCH.get(str(rule.get("type", "")))
        if not fn:
            debug_log(f"Skipping unknown rule type {rule.get('type')!r} for rule {rule.get('id')!r}")
            continue
        try:
            fn(rule, pcap_path, pcap_name)
        except Exception as exc:
            emit_alert(
                {"id": "rule_error", "name": "Rule evaluation error", "severity": "low", "message": "A rule failed during analysis.", "cooldown_seconds": 0},
                pcap_name,
                {"error": str(exc), "failed_rule": rule.get("id")},
            )
            debug_log(f"Rule {rule.get('id')!r} failed on {pcap_name}: {exc}")


class Handler(FileSystemEventHandler):
    def _handle_path(self, path: str):
        if not path.endswith(".pcap"):
            return
        if not wait_until_stable(path):
            return
        work_path = os.path.join(PCAPS_WORK, os.path.basename(path))
        try:
            shutil.move(path, work_path)
        except FileNotFoundError:
            return
        except Exception as exc:
            debug_log(f"Failed to move {path} to work dir: {exc}")
            return
        try:
            analyze_pcap(work_path)
        finally:
            archive_path = os.path.join(PCAPS_ARCHIVE, os.path.basename(work_path))
            try:
                shutil.move(work_path, archive_path)
            except FileNotFoundError:
                pass
            except Exception as exc:
                debug_log(f"Failed to archive {work_path}: {exc}")

    def on_created(self, event):
        if not event.is_directory:
            self._handle_path(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle_path(event.dest_path)


def main():
    ensure_dirs()
    obs = Observer()
    obs.schedule(Handler(), PCAPS_IN, recursive=False)
    obs.start()
    print(f"[IDS V3] Watching: {PCAPS_IN}")
    print(f"[IDS V3] Rules:    {RULES_PATH}")
    print(f"[IDS V3] Alerts:   {ALERTS_FILE}")
    print(f"[IDS V3] Debug:    {DEBUG_LOG}")
    try:
        while True:
            time.sleep(1)
    finally:
        obs.stop()
        obs.join()


if __name__ == "__main__":
    main()
