#!/usr/bin/env python3
import json, os, subprocess, socket

ALERTS_PATH = os.path.expanduser("~/ids_alerts/alert.jsonl")
STATE_PATH  = os.path.expanduser("~/.ids_alerts_state.json")
HISTORY_PATH = os.path.expanduser("~/ids_alerts/notifications_history.jsonl")
def load_state():
    if not os.path.exists(STATE_PATH):
        return {"offset": 0}
    try:
        return json.load(open(STATE_PATH, "r", encoding="utf-8"))
    except Exception:
        return {"offset": 0}

def save_state(state):
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f)

def ip_to_name(ip: str):
    # if it fails, return the IP
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name
    except Exception:
        return ip

def notify(title: str, subtitle: str, body: str):
    # notification pop-up
    def esc(s): return s.replace("\\", "\\\\").replace('"', '\\"')
    script = f'display notification "{esc(body)}" with title "{esc(title)}" subtitle "{esc(subtitle)}"'
    subprocess.run(["osascript", "-e", script], check=False)

def format_alert(a: dict):
    # easy to read
    sev = (a.get("severity") or "low").upper()
    rule = a.get("rule_name") or a.get("rule_id") or "IDS Alert"
    src_ip = a.get("src_ip", "")
    dst_ip = a.get("dst_ip", "")
    dst_port = a.get("dst_port", "")
    domain = a.get("indicator", "")
    pcap = a.get("pcap", "")

    src_name = ip_to_name(src_ip) if src_ip else ""
    dst_name = ip_to_name(dst_ip) if dst_ip else ""

    title = f"{sev} • {rule}"

    parts = []
    if src_name:
        parts.append(f"src: {src_name}")
    elif src_ip:
        parts.append(f"src: {src_ip}")

    if domain:
        parts.append(f"dns: {domain}")

    if dst_port:
        parts.append(f"port: {dst_port}")

    if dst_name:
        parts.append(f"dst: {dst_name}")
    elif dst_ip:
        parts.append(f"dst: {dst_ip}")

    subtitle = " | ".join(parts)[:250] if parts else "IDS event"

    # including pcap and any counters and thresholds
    extra = []
    if "count" in a and "threshold" in a:
        extra.append(f"count {a['count']} ≥ {a['threshold']}")
    if a.get("filter"):
        extra.append(f"filter: {a['filter']}")
    if pcap:
        extra.append(f"pcap: {pcap}")

    body = " • ".join(extra)[:800] if extra else "See alert.jsonl for details"
    return title, subtitle, body

def append_history(alert: dict):
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    with open(HISTORY_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")

def main():
    state = load_state()
    offset = int(state.get("offset", 0))

    if not os.path.exists(ALERTS_PATH):
        return

    with open(ALERTS_PATH, "rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if offset > end:
            offset = 0  
        f.seek(offset)

        new_bytes = f.read()
        state["offset"] = end

    if not new_bytes:
        save_state(state)
        return

    text = new_bytes.decode("utf-8", errors="replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    # show up to the last 5 alerts each run 
    for ln in lines[-5:]:
        try:
            a = json.loads(ln)
        except Exception:
            continue
        title, subtitle, body = format_alert(a)
        notify(title, subtitle, body)
        append_history(a)

    save_state(state)

if __name__ == "__main__":
    main()
