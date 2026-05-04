import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE = Path("/home/<USER>/Desktop/IDS_Project")
ALERTS_FILE = BASE / "ids_alerts" / "alert.jsonl"
FIREWALL_EVENTS_FILE = BASE / "ids_alerts" / "firewall_events.jsonl"
PCAPS_ARCHIVE = BASE / "pcaps_archive"
SIEM_DIR = BASE / "siem"
SIEM_DB = SIEM_DIR / "siem.db"
DNSMASQ_LEASES = Path("/var/lib/misc/dnsmasq.leases")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def epoch_to_iso(value: str) -> str:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except Exception:
        return now_iso()


def stable_hash(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def tshark_fields(pcap_path: Path, display_filter: str, fields: list[str]) -> list[list[str]]:
    cmd = ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "fields"]
    for field in fields:
        cmd += ["-e", field]
    cmd += ["-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=f"]

    res = run(cmd)
    if res.returncode != 0:
        print(f"[WARN] tshark failed for {pcap_path.name}: {res.stderr.strip()}")
        return []

    rows: list[list[str]] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if line:
            rows.append(line.split("\t"))
    return rows


def connect_db() -> sqlite3.Connection:
    SIEM_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(SIEM_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection):
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_hash TEXT UNIQUE,
            ts TEXT,
            event_source TEXT,
            event_type TEXT,
            severity TEXT,
            rule_id TEXT,
            rule_name TEXT,
            action TEXT,
            src_ip TEXT,
            src_mac TEXT,
            src_hostname TEXT,
            dst_ip TEXT,
            dst_port TEXT,
            protocol TEXT,
            message TEXT,
            pcap TEXT,
            raw_json TEXT
        );

        CREATE TABLE IF NOT EXISTS network_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_hash TEXT UNIQUE,
            pcap TEXT,
            first_seen TEXT,
            last_seen TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port TEXT,
            dst_port TEXT,
            protocol TEXT,
            packets INTEGER,
            bytes INTEGER
        );

        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_hash TEXT UNIQUE,
            pcap TEXT,
            ts TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            query TEXT,
            rcode TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key TEXT UNIQUE,
            ip TEXT,
            mac TEXT,
            hostname TEXT,
            trusted INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            source TEXT
        );

        CREATE TABLE IF NOT EXISTS processed_pcaps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pcap TEXT UNIQUE,
            processed_at TEXT,
            flow_count INTEGER DEFAULT 0,
            dns_count INTEGER DEFAULT 0,
            size_bytes INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts);
        CREATE INDEX IF NOT EXISTS idx_security_events_src_ip ON security_events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_security_events_rule ON security_events(rule_id);
        CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON network_flows(src_ip);
        CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON network_flows(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_dns_src_ip ON dns_queries(src_ip);
        CREATE INDEX IF NOT EXISTS idx_dns_query ON dns_queries(query);
        """
    )
    conn.commit()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
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


def insert_security_event(conn: sqlite3.Connection, event: dict[str, Any], event_source: str) -> bool:
    normalized = dict(event)
    normalized.setdefault("event_source", event_source)
    normalized.setdefault("event_type", "ids_alert" if event_source == "ids" else "firewall_event")

    if event_source == "firewall":
        normalized.setdefault("severity", "medium" if normalized.get("action") in {"DROP", "REJECT"} else "low")
        normalized.setdefault("rule_id", normalized.get("rule_name", "firewall_event"))

    event_hash = stable_hash(normalized)

    values = {
        "event_hash": event_hash,
        "ts": normalized.get("ts") or now_iso(),
        "event_source": normalized.get("event_source"),
        "event_type": normalized.get("event_type"),
        "severity": normalized.get("severity"),
        "rule_id": normalized.get("rule_id"),
        "rule_name": normalized.get("rule_name"),
        "action": normalized.get("action"),
        "src_ip": normalized.get("src_ip"),
        "src_mac": normalized.get("src_mac"),
        "src_hostname": normalized.get("hostname") or normalized.get("src_hostname"),
        "dst_ip": normalized.get("dst_ip"),
        "dst_port": str(normalized.get("dst_port")) if normalized.get("dst_port") is not None else None,
        "protocol": normalized.get("proto") or normalized.get("protocol"),
        "message": normalized.get("message") or normalized.get("reason"),
        "pcap": normalized.get("pcap"),
        "raw_json": json.dumps(normalized, ensure_ascii=False),
    }

    cur = conn.execute(
        """
        INSERT OR IGNORE INTO security_events (
            event_hash, ts, event_source, event_type, severity, rule_id, rule_name,
            action, src_ip, src_mac, src_hostname, dst_ip, dst_port, protocol,
            message, pcap, raw_json
        ) VALUES (
            :event_hash, :ts, :event_source, :event_type, :severity, :rule_id, :rule_name,
            :action, :src_ip, :src_mac, :src_hostname, :dst_ip, :dst_port, :protocol,
            :message, :pcap, :raw_json
        )
        """,
        values,
    )
    return cur.rowcount > 0


def upsert_device(conn: sqlite3.Connection, ip: str | None, mac: str | None, hostname: str | None, source: str):
    ip = (ip or "").strip()
    mac = (mac or "").strip().lower()
    hostname = (hostname or "").strip()

    if not ip and not mac:
        return

    device_key = mac if mac else ip
    ts = now_iso()

    conn.execute(
        """
        INSERT INTO devices (device_key, ip, mac, hostname, first_seen, last_seen, source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_key) DO UPDATE SET
            ip=COALESCE(excluded.ip, devices.ip),
            mac=COALESCE(excluded.mac, devices.mac),
            hostname=CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
            last_seen=excluded.last_seen,
            source=excluded.source
        """,
        (device_key, ip or None, mac or None, hostname, ts, ts, source),
    )


def import_jsonl_events(conn: sqlite3.Connection) -> dict[str, int]:
    added_ids = 0
    added_firewall = 0

    for event in read_jsonl(ALERTS_FILE):
        if insert_security_event(conn, event, "ids"):
            added_ids += 1
        upsert_device(conn, event.get("src_ip"), event.get("src_mac"), event.get("hostname"), "ids_alert")

    for event in read_jsonl(FIREWALL_EVENTS_FILE):
        if insert_security_event(conn, event, "firewall"):
            added_firewall += 1
        upsert_device(conn, event.get("src_ip"), event.get("src_mac"), event.get("hostname"), "firewall_event")

    conn.commit()
    return {"ids_events_added": added_ids, "firewall_events_added": added_firewall}


def import_dnsmasq_leases(conn: sqlite3.Connection) -> int:
    if not DNSMASQ_LEASES.exists():
        return 0

    count = 0
    for line in DNSMASQ_LEASES.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        _expiry, mac, ip, hostname = parts[:4]
        upsert_device(conn, ip, mac, hostname, "dnsmasq_leases")
        count += 1
    conn.commit()
    return count


def pcap_already_processed(conn: sqlite3.Connection, pcap_name: str) -> bool:
    cur = conn.execute("SELECT 1 FROM processed_pcaps WHERE pcap = ?", (pcap_name,))
    return cur.fetchone() is not None

def pcap_can_be_read(pcap: Path) -> bool:
    """
    Safety check before deleting anything.
    If tshark cannot read the PCAP, do not mark/delete it.
    """
    res = run([
        "tshark",
        "-r", str(pcap),
        "-c", "1",
        "-T", "fields",
        "-e", "frame.number",
    ])

    if res.returncode != 0:
        print(f"[WARN] PCAP not readable, skipping delete: {pcap.name}")
        print(f"[WARN] tshark error: {res.stderr.strip()}")
        return False

    return True

def mark_pcap_processed(conn: sqlite3.Connection, pcap: Path, flow_count: int, dns_count: int):
    size_bytes = pcap.stat().st_size if pcap.exists() else 0
    conn.execute(
        """
        INSERT OR REPLACE INTO processed_pcaps (pcap, processed_at, flow_count, dns_count, size_bytes)
        VALUES (?, ?, ?, ?, ?)
        """,
        (pcap.name, now_iso(), flow_count, dns_count, size_bytes),
    )
    conn.commit()


def import_flows_from_pcap(conn: sqlite3.Connection, pcap: Path) -> int:
    rows = tshark_fields(
        pcap,
        "ip && (tcp || udp) && ip.src && ip.dst",
        [
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "ip.proto",
            "frame.len",
        ],
    )

    flows: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}

    for row in rows:
        ts_raw = row[0].strip() if len(row) > 0 else ""
        src_ip = row[1].strip() if len(row) > 1 else ""
        dst_ip = row[2].strip() if len(row) > 2 else ""
        tcp_sport = row[3].strip() if len(row) > 3 else ""
        tcp_dport = row[4].strip() if len(row) > 4 else ""
        udp_sport = row[5].strip() if len(row) > 5 else ""
        udp_dport = row[6].strip() if len(row) > 6 else ""
        ip_proto = row[7].strip() if len(row) > 7 else ""
        frame_len = row[8].strip() if len(row) > 8 else "0"

        if not src_ip or not dst_ip:
            continue

        if tcp_sport or tcp_dport:
            proto = "tcp"
            src_port = tcp_sport
            dst_port = tcp_dport
        elif udp_sport or udp_dport:
            proto = "udp"
            src_port = udp_sport
            dst_port = udp_dport
        else:
            proto = ip_proto or "ip"
            src_port = ""
            dst_port = ""

        try:
            ts_float = float(ts_raw)
        except Exception:
            ts_float = time.time()

        try:
            byte_count = int(frame_len)
        except Exception:
            byte_count = 0

        key = (src_ip, dst_ip, src_port, dst_port, proto)
        if key not in flows:
            flows[key] = {
                "first_seen_epoch": ts_float,
                "last_seen_epoch": ts_float,
                "packets": 0,
                "bytes": 0,
            }

        flow = flows[key]
        flow["first_seen_epoch"] = min(flow["first_seen_epoch"], ts_float)
        flow["last_seen_epoch"] = max(flow["last_seen_epoch"], ts_float)
        flow["packets"] += 1
        flow["bytes"] += byte_count

    inserted = 0
    for (src_ip, dst_ip, src_port, dst_port, proto), values in flows.items():
        flow_hash = stable_hash({
            "pcap": pcap.name,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
        })
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO network_flows (
                flow_hash, pcap, first_seen, last_seen, src_ip, dst_ip,
                src_port, dst_port, protocol, packets, bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow_hash,
                pcap.name,
                epoch_to_iso(str(values["first_seen_epoch"])),
                epoch_to_iso(str(values["last_seen_epoch"])),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto,
                values["packets"],
                values["bytes"],
            ),
        )
        inserted += cur.rowcount
        upsert_device(conn, src_ip, None, None, "pcap_flow")

    conn.commit()
    return inserted


def import_dns_from_pcap(conn: sqlite3.Connection, pcap: Path) -> int:
    rows = tshark_fields(
        pcap,
        "dns && dns.qry.name && ip.src && ip.dst",
        ["frame.time_epoch", "ip.src", "ip.dst", "dns.qry.name", "dns.flags.rcode"],
    )

    inserted = 0
    for row in rows:
        ts_raw = row[0].strip() if len(row) > 0 else ""
        src_ip = row[1].strip() if len(row) > 1 else ""
        dst_ip = row[2].strip() if len(row) > 2 else ""
        query = row[3].strip().lower().strip(".") if len(row) > 3 else ""
        rcode = row[4].strip() if len(row) > 4 else ""

        if not src_ip or not query:
            continue

        query_hash = stable_hash({
            "pcap": pcap.name,
            "ts": ts_raw,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "query": query,
            "rcode": rcode,
        })

        cur = conn.execute(
            """
            INSERT OR IGNORE INTO dns_queries (query_hash, pcap, ts, src_ip, dst_ip, query, rcode)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (query_hash, pcap.name, epoch_to_iso(ts_raw), src_ip, dst_ip, query, rcode),
        )
        inserted += cur.rowcount
        upsert_device(conn, src_ip, None, None, "dns_query")

    conn.commit()
    return inserted


def import_pcaps(
    conn: sqlite3.Connection,
    limit: int | None = None,
    force: bool = False,
    delete_after_import: bool = False,
    min_age_seconds: int = 60,
) -> dict[str, int]:
    if not PCAPS_ARCHIVE.exists():
        return {
            "pcaps_seen": 0,
            "pcaps_processed": 0,
            "flows_added": 0,
            "dns_added": 0,
            "deleted_pcaps": 0,
            "skipped_too_new": 0,
            "skipped_unreadable": 0,
        }

    pcaps = sorted(PCAPS_ARCHIVE.glob("*.pcap"))

    if limit is not None:
        pcaps = pcaps[-limit:]

    pcaps_seen = len(pcaps)
    pcaps_processed = 0
    flows_added = 0
    dns_added = 0
    deleted_pcaps = 0
    skipped_too_new = 0
    skipped_unreadable = 0

    for pcap in pcaps:
        try:
            age_seconds = time.time() - pcap.stat().st_mtime
        except FileNotFoundError:
            continue

        if age_seconds < min_age_seconds:
            print(f"[SIEM] Skipping new PCAP, not old enough yet: {pcap.name}")
            skipped_too_new += 1
            continue

        already_processed = pcap_already_processed(conn, pcap.name)

        if already_processed and not force:
            print(f"[SIEM] Already processed: {pcap.name}")

            if delete_after_import:
                try:
                    pcap.unlink()
                    deleted_pcaps += 1
                    print(f"[SIEM] Deleted already-processed PCAP: {pcap.name}")
                except Exception as exc:
                    print(f"[WARN] Could not delete already-processed PCAP {pcap.name}: {exc}")

            continue

        if not pcap_can_be_read(pcap):
            skipped_unreadable += 1
            continue

        print(f"[SIEM] Processing {pcap.name}")

        flow_count = import_flows_from_pcap(conn, pcap)
        dns_count = import_dns_from_pcap(conn, pcap)

        
        mark_pcap_processed(conn, pcap, flow_count, dns_count)

        pcaps_processed += 1
        flows_added += flow_count
        dns_added += dns_count

        if delete_after_import:
            try:
                pcap.unlink()
                deleted_pcaps += 1
                print(f"[SIEM] Deleted processed PCAP: {pcap.name}")
            except Exception as exc:
                print(f"[WARN] Could not delete processed PCAP {pcap.name}: {exc}")

    return {
        "pcaps_seen": pcaps_seen,
        "pcaps_processed": pcaps_processed,
        "flows_added": flows_added,
        "dns_added": dns_added,
        "deleted_pcaps": deleted_pcaps,
        "skipped_too_new": skipped_too_new,
        "skipped_unreadable": skipped_unreadable,
    }


def print_summary(conn: sqlite3.Connection):
    queries = {
        "security_events": "SELECT COUNT(*) FROM security_events",
        "network_flows": "SELECT COUNT(*) FROM network_flows",
        "dns_queries": "SELECT COUNT(*) FROM dns_queries",
        "devices": "SELECT COUNT(*) FROM devices",
        "processed_pcaps": "SELECT COUNT(*) FROM processed_pcaps",
    }

    print("\n[SIEM] Database summary")
    for name, query in queries.items():
        count = conn.execute(query).fetchone()[0]
        print(f"  {name}: {count}")

    print("\n[SIEM] Top source IPs by flow count")
    for row in conn.execute(
        """
        SELECT src_ip, COUNT(*) AS c, SUM(bytes) AS total_bytes
        FROM network_flows
        GROUP BY src_ip
        ORDER BY c DESC
        LIMIT 10
        """
    ):
        print(f"  {row['src_ip']}: {row['c']} flows, {row['total_bytes'] or 0} bytes")


def main():
    parser = argparse.ArgumentParser(description="Build/update mini SIEM metadata database.")
    parser.add_argument("--skip-pcaps", action="store_true", help="Only import alert/firewall JSONL and leases; skip archived PCAPs.")
    parser.add_argument("--limit-pcaps", type=int, default=None, help="Only process the most recent N archived PCAP files.")
    parser.add_argument("--force", action="store_true", help="Re-process PCAPs even if they are already marked processed.")
    parser.add_argument(
    "--delete-after-import",
    action="store_true",
    help="Delete each archived PCAP after its metadata is successfully stored in siem.db."
    )
    parser.add_argument(
        "--min-age-seconds",
        type=int,
        default=60,
        help="Skip PCAPs newer than this many seconds to avoid deleting files still being moved."
    )
    
    args = parser.parse_args()

    conn = connect_db()
    init_db(conn)

    event_stats = import_jsonl_events(conn)
    lease_count = import_dnsmasq_leases(conn)

    print(f"[SIEM] IDS events added: {event_stats['ids_events_added']}")
    print(f"[SIEM] Firewall events added: {event_stats['firewall_events_added']}")
    print(f"[SIEM] Device leases imported: {lease_count}")

    if not args.skip_pcaps:
        pcap_stats = import_pcaps(
            conn,
            limit=args.limit_pcaps,
            force=args.force,
            delete_after_import=args.delete_after_import,
            min_age_seconds=args.min_age_seconds,
        )
        print(f"[SIEM] PCAPs seen: {pcap_stats['pcaps_seen']}")
        print(f"[SIEM] PCAPs processed: {pcap_stats['pcaps_processed']}")
        print(f"[SIEM] Flows added: {pcap_stats['flows_added']}")
        print(f"[SIEM] DNS queries added: {pcap_stats['dns_added']}")
        print(f"[SIEM] PCAPs deleted: {pcap_stats['deleted_pcaps']}")
        print(f"[SIEM] PCAPs skipped because too new: {pcap_stats['skipped_too_new']}")
        print(f"[SIEM] PCAPs skipped because unreadable: {pcap_stats['skipped_unreadable']}")

    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
