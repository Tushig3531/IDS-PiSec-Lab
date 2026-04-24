# IDS Project v1 

This README documents my first working version of a lightweight IDS pipeline built with a Mac and a Raspberry Pi. It captures PCAPs on a schedule, ships them to a Pi, analyzes them with `tshark` based on custom rules, writes alerts in JSON Lines, then pulls alerts back to the Mac and shows notifications.

All IP addresses, usernames, and personal paths below are anonymized.

---

## Architecture Overview

- Mac
  - Captures PCAP files on an interval
  - Ships PCAPs to Raspberry Pi automatically (LaunchAgent + rsync)
  - Pulls alerts from Raspberry Pi automatically (LaunchAgent + rsync)
  - Generates local notifications for new alerts

- Raspberry Pi
  - Receives PCAPs into an input folder
  - Moves PCAPs into a work folder to avoid double-processing
  - Runs analysis using `tshark` and rule definitions (YAML)
  - Writes alerts to `alert.jsonl`
  - Archives processed PCAPs

---

## Raspberry Pi Setup

### 1) Create folders
On the Raspberry Pi:

```bash
mkdir -p ~/Desktop/IDS_Project/pcaps_in \
         ~/Desktop/IDS_Project/pcaps_work \
         ~/Desktop/IDS_Project/pcaps_archive \
         ~/Desktop/IDS_Project/ids_alerts

touch ~/Desktop/IDS_Project/ids_alerts/alert.jsonl
```
Folder purpose:
- pcaps_in: where rsync drops incoming PCAPs
- pcaps_work: analyzer moves PCAPs here while processing (prevents double-processing)
- pcaps_archive: processed PCAPs stored for later review
- ids_alerts/alert.jsonl: alert output

### 2) Why alert.jsonl
jsonl is JSON Lines: one JSON object per line. It is append-only, stream-friendly, easy to parse, and works well with log/SIEM pipelines.

---

## SSH Setup (Mac to Raspberry Pi)
Create an SSH key on the Mac:
```bash
ssh-keygen -t ed25519
```
Copy the public key to the Raspberry Pi:
```bash
ssh-copy-id -i ~/.ssh/<KEYNAME>.pub <PI_USER>@<PI_IP>
```
Test:
```bash
ssh <PI_USER>@<PI_IP> "echo ok"
```

---

## Mac Setup (Capture and Ship)
### 1) Capture PCAPs locally

Create the output folder:
```bash
mkdir -p "$HOME/pcaps_out"
```

Command I used to capture pcaps:
```bash
sudo tcpdump -i any -n -s 96 -w "$HOME/pcaps_out/cap_%Y%m%d_%H%M%S.pcap" -G 60 -W 5
```
Explanation:
- -i any: capture on all interfaces
- -n: no DNS resolution
- -s 96: snap length (capture first 96 bytes)
- -G 60: rotate every 60 seconds
- -W 5: keep last N rotated files 

### 2) Ship PCAPs to the Raspberry Pi with rsync

I have made a script: **$HOME/bin/ship-pcaps.sh**
```bash
#!/bin/bash
set -euo pipefail

SRC="$HOME/pcaps_out/"
DEST="<PI_USER>@<PI_IP>:/home/<PI_USER>/Desktop/IDS_Project/pcaps_in/"
NEWEST="$(ls -t "$SRC"/*.pcap 2>/dev/null | head -n 1 || true)"

if [[ -n "${NEWEST:-}" ]]; then
  rsync -az --remove-source-files --exclude "$(basename "$NEWEST")" \
    "$SRC"/ "$DEST"
else
  rsync -az --remove-source-files "$SRC"/ "$DEST"
fi
```
So, the purpose of this script is to send the latest PCAP from HOME to the PI, and, immediately after it is sent successfully, delete the PCAP to prevent duplicate processing or misconfiguration.

Code explanation:
- rsync -a: archive mode
- rsync -z: compress during transfer
- --remove-source-files: delete local PCAPs only after successful copy
- Excludes the newest PCAP so it does not ship a file still being written

---

## macOS Automation (LaunchAgent)

Because, I didn't want to manually run the script all the time, I have created automation in the LaunchAgent: ~/Library/LaunchAgents/com.example.shippcaps.plist
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.example.shippcaps</string>

    <key>ProgramArguments</key>
    <array>
      <string>/bin/bash</string>
      <string>-lc</string>
      <string>$HOME/bin/ship-pcaps.sh</string>
    </array>

    <key>StartInterval</key>
    <integer>30</integer>

    <key>RunAtLoad</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/tmp/shippcaps.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/shippcaps.err</string>
  </dict>
</plist>
```
This will run the script every 30 seconds internval and sends the errors and outputs into tmp. And the validate, I tested with this command:
```bash
plutil -lint ~/Library/LaunchAgents/com.example.shippcaps.plist
```
- plutil: Property List Utility, Apple’s tool for plist 
- -lint: validation check and checks the plist format
This command basically checks whether launchd can read it: if it can, it returns OK; if not, it prints an error.

Then, loaded it with these commands:
```bash
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.example.shippcaps.plist 2>/dev/null || true
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.shippcaps.plist
launchctl enable gui/$(id -u)/com.example.shippcaps
launchctl kickstart -k gui/$(id -u)/com.example.shippcaps
```
- launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.tushig.shippcaps.plist 2>/dev/null || true
- - launchctl: control tool for launchd, this is MacOS’s service manager
- - bootout: unload and remove the job from launchd, basically it resets
- - gui/$(id -u): the domain to manage
- - - gui/ : means logged in desktop session
- - - $ (id -u) : expands to our numeric user id
- - - So this targets our user’s LaunchAgent, not system services.
- - 2>/dev/null : hide error messages so it will not spam error messages if it wasn’t loaded
- - || true: even if bootout fails it pretends successful and continues
- launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.tushig.shippcaps.plist
- - bootstrap: load the plist 
- launchctl enable gui/$(id -u)/com.tushig.shippcaps
- - Launchd jobs can be loaded but disabled
- - So the enable flips it to “allowed to run”
- launchctl kickstart -k gui/$(id -u)/com.tushig.shippcaps
- - kickstart: start now
- - -k : kill any running instance first, then start fresh

---

## IDS Analyzer (Raspberry Pi)

Then I have made a Python analyzer that watches pcaps_in for .pcap files, waits until the file is stable, moves it to pcaps_work, runs tshark field extraction, evaluates rules from rules.yaml, appends alerts to ids_alerts/alert.jsonl, then moves the PCAP to pcaps_archive.

Codes:
- Python file from here: [Python](ids_watch.py)
- YAML rule from here: [Rules](rules.yaml)

**Disclaimer**
The rules are generated by the OpenAI, later on the Version 2 of my IDS, I will create my own rule for the system.

---

## Alert Pull and Notification (Mac)

Because I wanted to have the alert on my PC, I have made these:

### 1) Pull alerts from Raspberry Pi
- $HOME/bin/pull-alerts.sh

```bash
#!/bin/bash
set -euo pipefail
PI_USER="<PI_USER>"
PI_IP="<PI_IP>"
PI_ALERTS="/home/<PI_USER>/Desktop/IDS_Project/ids_alerts/alert.jsonl"
mkdir -p "$HOME/ids_alerts"
rsync -az "${PI_USER}@${PI_IP}:${PI_ALERTS}" "$HOME/ids_alerts/alert.jsonl"
```
This pulls the alert.jsonl from Raspberry PI back to the computer, and place them in /ids_alerts

### 2) Notification Python
Because it’s a notification, I didn’t want to include raw information. So I created this Python file, which provides enough details about the alert in a clear, verbose format:
You can see the code from here: [Notification Python](notify-alerts.py)

### 3) Pull and Notify
- $HOME/bin/pull-and-notify.sh
```bash
#!/bin/bash
set -euo pipefail
"$HOME/bin/pull-alerts.sh"
"$HOME/bin/notify-alerts.py"
```
This makes pull-alert.sh and notify-alert.py to execute at the same time from one script. 

### 4) Automate pull + notify (LaunchAgent)
- ~/Library/LaunchAgents/com.example.pullnotify.plist
Instead of executing the script manually, I have created another process which will run the script without interaction. 
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.example.pullnotify</string>

    <key>ProgramArguments</key>
    <array>
      <string>/bin/bash</string>
      <string>-lc</string>
      <string>$HOME/bin/pull-and-notify.sh</string>
    </array>

    <key>StartInterval</key>
    <integer>15</integer>

    <key>RunAtLoad</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/tmp/pullnotify.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/pullnotify.err</string>
  </dict>
</plist>
```
And validates and loads with:
```bash
plutil -lint ~/Library/LaunchAgents/com.example.pullnotify.plist

launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.example.pullnotify.plist 2>/dev/null || true
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.pullnotify.plist
launchctl enable gui/$(id -u)/com.example.pullnotify
launchctl kickstart -k gui/$(id -u)/com.example.pullnotify
```

---

## Testing
Tested detection by scanning my own host from a separate machine (authorized test). The pipeline successfully:
- captured the traffic
- shipped PCAPs to the Pi
- analyzed PCAPs
- generated alert entries
- pulled alerts back to the Mac
- displayed notifications
![Notification Test](<Notification.png>)

- I tested my system by scanning ports (**Nmap**) from my friend’s computer, and this is the result:
```text
{"ts": "2026-02-23T03:47:19.331937+00:00", "rule_id": "tcp_volume_spike", "rule_name": "Network: high TCP packet count per src", "severity": "medium", "pcap": "cap_20260222_214601.pcap", "src_ip": "<Tester's IP>", "count": 798, "threshold": 700, "filter": "tcp && ip.src"}
```



--- 

## Roadmap
- Reduce false positives
- Build and Improve rule quality and coverage
- Add statistics and reporting
- Build a UI for viewing alerts and trends
- Expand toward SIEM-like features