#!/usr/bin/env python3
import json
import os
import time
import shutil
import subprocess
from datetime import datetime, timezone

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

BASE = os.path.expanduser("~/Desktop/IDS_Project")
PCAPS_IN = os.path.join(BASE, "pcaps_in")
PCAPS_WORK = os.path.join(BASE, "pcaps_work")
PCAPS_ARCHIVE = os.path.join(BASE, "pcaps_archive")
ALERTS_FILE = os.path.join(BASE, "ids_alerts", "alert.jsonl")
RULES_PATH = os.path.join(BASE, "rules.yaml")
IGNORE_IPS: set[str] = set()

# Helpers
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)

def is_ignored_ips(ip:str):
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
    max_wait: float = 20.0
) -> bool:
    """
    Wait until the file size stops changing for stable_checks * interval seconds.
    Returns False if it times out or disappears.
    """
    start = time.time()
    last_size = -1
    stable = 0

    while True:
        if time.time() - start > max_wait:
            return False

        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            return False

        if size == last_size:
            stable += 1
            if stable >= stable_checks:
                return True
        else:
            stable = 0
            last_size = size

        time.sleep(interval)


def append_alert(alert: dict):
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def tshark_fields(pcap_path: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    """
    Run tshark and return rows as list of lists (tab-separated fields).
    """
    cmd = ["tshark", "-r", pcap_path, "-Y", display_filter, "-T", "fields"]
    for fld in fields:
        cmd += ["-e", fld]
    cmd += ["-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=f"]

    res = run(cmd)
    if res.returncode != 0:
        # Keep pipeline alive even if tshark errors
        return []

    rows = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(line.split("\t"))
    return rows


#Rule loading
def load_rules() -> list[dict]:
    global IGNORE_IPS
    if not os.path.exists(RULES_PATH):
        append_alert({
            "ts": now_iso(),
            "rule_id": "rules_missing",
            "rule_name": "rules.yaml missing",
            "severity": "low",
            "message": f"Expected rules at {RULES_PATH}",
        })
        IGNORE_IPS=set()
        return []

    with open(RULES_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if isinstance(cfg, list):
        IGNORE_IPS=set()
        rules=cfg
    else:
        IGNORE_IPS=set(cfg.get("ignore_ips",[]) or [])
        rules=cfg.get("rules",[]) or []

    enabled = [r for r in rules if r.get("enabled", True)]
    return enabled


# Alerts
def emit_alert(rule: dict, pcap_name: str, extra: dict):
    alert = {
        "ts": now_iso(),
        "rule_id": rule.get("id", "unknown_rule"),
        "rule_name": rule.get("name", "Unnamed rule"),
        "severity": rule.get("severity", "low"),
        "pcap": pcap_name,
        **extra,
    }
    append_alert(alert)


#Rule evaluation
def eval_dns_domain(rule: dict, pcap_path: str, pcap_name: str):
    match = rule.get("match", {})
    domains = [d.lower().strip(".") for d in match.get("domains", [])]
    domains_set = set(domains)
    match_sub = bool(match.get("match_subdomains", True))

    if not domains_set:
        return

    rows = tshark_fields(
        pcap_path,
        "dns && dns.qry.name && ip.src && ip.dst",
        ["ip.src", "ip.dst", "dns.qry.name"]
    )

    for row in rows:
        src = row[0] if len(row) > 0 else ""
        dst = row[1] if len(row) > 1 else ""
        qname = row[2] if len(row) > 2 else ""
        
        if is_ignored_ips(src) or is_ignored_ips(dst):
            continue
        
        q = qname.lower().strip(".")

        hit = (q in domains_set) or (match_sub and any(q.endswith("." + d) for d in domains_set))
        if hit:
            emit_alert(rule, pcap_name, {
                "src_ip": src,
                "dst_ip": dst,
                "indicator": q,
                "proto": "dns",
            })


def eval_count_by_src(rule: dict, pcap_path: str, pcap_name: str):
    display_filter = rule.get("filter", "")
    threshold = int(rule.get("threshold", 0))
    if not display_filter or threshold <= 0:
        return

    rows = tshark_fields(pcap_path, display_filter, ["ip.src"])
    counts: dict[str, int] = {}

    for row in rows:
        src = row[0].strip() if row and row[0] else ""
        if not src or is_ignored_ips(src):
            continue
        counts[src] = counts.get(src, 0) + 1

    for src, c in counts.items():
        if c >= threshold:
            emit_alert(rule, pcap_name, {
                "src_ip": src,
                "count": c,
                "threshold": threshold,
                "filter": display_filter,
            })


def eval_count_by_src_dstport(rule: dict, pcap_path: str, pcap_name: str):
    display_filter = rule.get("filter", "")
    threshold = int(rule.get("threshold", 0))
    if not display_filter or threshold <= 0:
        return

    rows = tshark_fields(pcap_path, display_filter, ["ip.src", "ip.dst", "tcp.dstport"])
    counts: dict[tuple[str, str], int] = {}  # (src, dstport) -> count

    for row in rows:
        src = row[0].strip() if len(row) > 0 else ""
        dport = row[2].strip() if len(row) > 2 else ""
        if not src or not dport or is_ignored_ips(src):
            continue
        key = (src, dport)
        counts[key] = counts.get(key, 0) + 1

    for (src, dport), c in counts.items():
        if c >= threshold:
            emit_alert(rule, pcap_name, {
                "src_ip": src,
                "dst_port": int(dport) if dport.isdigit() else dport,
                "count": c,
                "threshold": threshold,
                "filter": display_filter,
            })


RULE_DISPATCH = {
    "dns_domain": eval_dns_domain,
    "count_by_src": eval_count_by_src,
    "count_by_src_dstport": eval_count_by_src_dstport,
}


#PCAP analysis
def analyze_pcap(pcap_path: str):
    pcap_name = os.path.basename(pcap_path)
    rules = load_rules()

    for rule in rules:
        rtype = rule.get("type", "")
        fn = RULE_DISPATCH.get(rtype)
        if not fn:
            continue  # unknown rule will ignore safely

        try:
            fn(rule, pcap_path, pcap_name)
        except Exception as e:
            emit_alert(
                {"id": "rule_error", "name": "Rule evaluation error", "severity": "low"},
                pcap_name,
                {"error": str(e), "failed_rule": rule.get("id")}
            )


# Watcher
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

        try:
            analyze_pcap(work_path)
        finally:
            shutil.move(work_path, os.path.join(PCAPS_ARCHIVE, os.path.basename(work_path)))

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

    try:
        while True:
            time.sleep(1)
    finally:
        obs.stop()
        obs.join()


if __name__ == "__main__":
    main()
