#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import time
import hashlib
from collections import defaultdict
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
RULES_PATH = os.path.join(BASE, "rules.yaml")
DEBUG_LOG = os.path.join(BASE, "ids_alerts", "ids_debug.log")

IGNORE_IPS: set[str] = set()
ALERT_STATE: dict[str, float] = {}
DEFAULT_COOLDOWN_SECONDS = 300


# ===== Helpers =====
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_epoch() -> float:
    return time.time()


def debug_log(message: str):
    os.makedirs(os.path.dirname(DEBUG_LOG), exist_ok=True)
    line = f"[{now_iso()}] {message}\n"
    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(line)


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def is_ignored_ip(ip: str) -> bool:
    return bool(ip) and ip in IGNORE_IPS


def ensure_dirs():
    os.makedirs(PCAPS_IN, exist_ok=True)
    os.makedirs(PCAPS_WORK, exist_ok=True)
    os.makedirs(PCAPS_ARCHIVE, exist_ok=True)
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)


def wait_until_stable(
    path: str,
    stable_checks: int = 5,
    interval: float = 0.2,
    max_wait: float = 20.0,
) -> bool:
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
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def parse_threshold(rule: dict[str, Any]) -> int:
    try:
        return int(rule.get("threshold", 0))
    except (TypeError, ValueError):
        return 0


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
    cooldown = rule.get("cooldown_seconds", DEFAULT_COOLDOWN_SECONDS)
    try:
        cooldown = int(cooldown)
    except (TypeError, ValueError):
        cooldown = DEFAULT_COOLDOWN_SECONDS

    if cooldown <= 0:
        return True

    alert_key = build_alert_key(rule.get("id", "unknown_rule"), extra)
    last_seen = ALERT_STATE.get(alert_key)
    now = now_epoch()

    if last_seen is not None and now - last_seen < cooldown:
        return False

    ALERT_STATE[alert_key] = now
    return True


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
        if not line:
            continue
        rows.append(line.split("\t"))
    return rows


# ===== Rule loading =====
def load_rules() -> list[dict[str, Any]]:
    global IGNORE_IPS

    if not os.path.exists(RULES_PATH):
        append_alert(
            {
                "ts": now_iso(),
                "rule_id": "rules_missing",
                "rule_name": "rules.yaml missing",
                "severity": "low",
                "message": f"Expected rules at {RULES_PATH}",
            }
        )
        IGNORE_IPS = set()
        return []

    with open(RULES_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    if isinstance(cfg, list):
        IGNORE_IPS = set()
        rules = cfg
    else:
        IGNORE_IPS = set(cfg.get("ignore_ips", []) or [])
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


# ===== Alerts =====
def emit_alert(rule: dict[str, Any], pcap_name: str, extra: dict[str, Any]):
    if not should_emit(rule, extra):
        return

    alert = {
        "ts": now_iso(),
        "rule_id": rule.get("id", "unknown_rule"),
        "rule_name": rule.get("name", "Unnamed rule"),
        "severity": rule.get("severity", "low"),
        "message": rule.get("message", ""),
        "cooldown_seconds": int(rule.get("cooldown_seconds", DEFAULT_COOLDOWN_SECONDS)),
        "pcap": pcap_name,
        **extra,
    }
    append_alert(alert)


# ===== Rule evaluation =====
def eval_dns_domain(rule: dict[str, Any], pcap_path: str, pcap_name: str):
    match = rule.get("match", {})
    domains = [d.lower().strip(".") for d in match.get("domains", []) if str(d).strip()]
    domains_set = set(domains)
    match_sub = bool(match.get("match_subdomains", True))

    if not domains_set:
        return

    rows = tshark_fields(
        pcap_path,
        "dns && dns.qry.name && ip.src && ip.dst",
        ["ip.src", "ip.dst", "dns.qry.name"],
    )

    seen_hits: set[tuple[str, str]] = set()
    for row in rows:
        src = row[0].strip() if len(row) > 0 else ""
        dst = row[1].strip() if len(row) > 1 else ""
        qname = row[2].strip() if len(row) > 2 else ""

        if is_ignored_ip(src) or is_ignored_ip(dst):
            continue
        if not qname:
            continue

        q = qname.lower().strip(".")
        hit = (q in domains_set) or (match_sub and any(q.endswith("." + d) for d in domains_set))
        if not hit:
            continue

        hit_key = (src, q)
        if hit_key in seen_hits:
            continue
        seen_hits.add(hit_key)

        emit_alert(
            rule,
            pcap_name,
            {
                "src_ip": src,
                "dst_ip": dst,
                "indicator": q,
                "proto": "dns",
            },
        )


def eval_count_by_src(rule: dict[str, Any], pcap_path: str, pcap_name: str):
    display_filter = str(rule.get("filter", "")).strip()
    threshold = parse_threshold(rule)
    if not display_filter or threshold <= 0:
        return

    rows = tshark_fields(pcap_path, display_filter, ["ip.src"])
    counts: dict[str, int] = defaultdict(int)

    for row in rows:
        src = row[0].strip() if row and row[0] else ""
        if not src or is_ignored_ip(src):
            continue
        counts[src] += 1

    for src, count in counts.items():
        if count >= threshold:
            emit_alert(
                rule,
                pcap_name,
                {
                    "src_ip": src,
                    "count": count,
                    "threshold": threshold,
                    "filter": display_filter,
                },
            )


def eval_count_by_src_dstport(rule: dict[str, Any], pcap_path: str, pcap_name: str):
    display_filter = str(rule.get("filter", "")).strip()
    threshold = parse_threshold(rule)
    if not display_filter or threshold <= 0:
        return

    rows = tshark_fields(
        pcap_path,
        display_filter,
        ["ip.src", "ip.dst", "tcp.dstport", "udp.dstport", "ip.proto"],
    )

    counts: dict[tuple[str, str], int] = defaultdict(int)
    sample_dsts: dict[tuple[str, str], set[str]] = defaultdict(set)
    proto_seen: dict[tuple[str, str], str] = {}

    for row in rows:
        src = row[0].strip() if len(row) > 0 else ""
        dst = row[1].strip() if len(row) > 1 else ""
        tcp_dport = row[2].strip() if len(row) > 2 else ""
        udp_dport = row[3].strip() if len(row) > 3 else ""
        ip_proto = row[4].strip() if len(row) > 4 else ""

        dport = tcp_dport or udp_dport
        if not src or not dport or is_ignored_ip(src):
            continue

        key = (src, dport)
        counts[key] += 1
        if dst:
            sample_dsts[key].add(dst)
        if tcp_dport:
            proto_seen[key] = "tcp"
        elif udp_dport:
            proto_seen[key] = "udp"
        elif ip_proto:
            proto_seen[key] = ip_proto

    for (src, dport), count in counts.items():
        if count < threshold:
            continue

        dsts = sorted(sample_dsts.get((src, dport), set()))
        emit_alert(
            rule,
            pcap_name,
            {
                "src_ip": src,
                "dst_port": int(dport) if dport.isdigit() else dport,
                "count": count,
                "threshold": threshold,
                "filter": display_filter,
                "proto": proto_seen.get((src, dport), "unknown"),
                "unique_dst_ips": len(dsts),
                "sample_dst_ips": dsts[:5],
            },
        )


RULE_DISPATCH = {
    "dns_domain": eval_dns_domain,
    "count_by_src": eval_count_by_src,
    "count_by_src_dstport": eval_count_by_src_dstport,
}


# ===== PCAP analysis =====
def analyze_pcap(pcap_path: str):
    pcap_name = os.path.basename(pcap_path)
    rules = load_rules()

    if not rules:
        debug_log(f"No enabled rules loaded for {pcap_name}")
        return

    for rule in rules:
        rtype = rule.get("type", "")
        fn = RULE_DISPATCH.get(rtype)
        if not fn:
            debug_log(f"Skipping unknown rule type {rtype!r} for rule {rule.get('id')!r}")
            continue

        try:
            fn(rule, pcap_path, pcap_name)
        except Exception as exc:
            emit_alert(
                {
                    "id": "rule_error",
                    "name": "Rule evaluation error",
                    "severity": "low",
                    "message": "A rule failed during analysis.",
                    "cooldown_seconds": 0,
                },
                pcap_name,
                {"error": str(exc), "failed_rule": rule.get("id")},
            )
            debug_log(f"Rule {rule.get('id')!r} failed on {pcap_name}: {exc}")


# ===== Watcher =====
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
        if event.is_directory:
            return
        self._handle_path(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._handle_path(event.dest_path)


def main():
    ensure_dirs()
    obs = Observer()
    obs.schedule(Handler(), PCAPS_IN, recursive=False)
    obs.start()
    print(f"[IDS] Watching: {PCAPS_IN}")
    print(f"[IDS] Rules:    {RULES_PATH}")
    print(f"[IDS] Alerts:   {ALERTS_FILE}")
    print(f"[IDS] Debug:    {DEBUG_LOG}")

    try:
        while True:
            time.sleep(1)
    finally:
        obs.stop()
        obs.join()


if __name__ == "__main__":
    main()
