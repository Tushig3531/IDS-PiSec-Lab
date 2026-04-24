# IDS Project v2

This README documents my second version of a lightweight IDS pipeline built with a Mac and a Raspberry Pi. In this version, I expanded the system by developing the Python analyzer myself, building a structured working environment, and writing my own detection rules instead of relying on generated ones.

All IP addresses, usernames, and personal paths below are anonymized.

---

## What’s new in v2

- Built a custom Python-based IDS analyzer
- Designed a clean and structured working environment for processing PCAPs
- Developed and refined my own rule system (rules.yaml)
- Improved pipeline reliability and workflow control
- Focused on better detection logic and reduced dependency on external/generated rules

---

## Architecture Overview

- Mac
  - Captures PCAP files on an interval
  - Ships PCAPs to Raspberry Pi automatically (LaunchAgent + rsync)
  - Pulls alerts from Raspberry Pi automatically
  - Displays alerts via local notification system

- Raspberry Pi
  - Receives PCAPs into an input folder
  - Processes them using a custom Python IDS engine
  - Applies user-defined detection rules
  - Writes structured alerts into JSON Lines format
  - Archives processed PCAPs

---

## Custom IDS Engine (Python)
In this version, I fully developed the IDS analyzer in Python instead of relying on generated logic.

Core features:
- Watches incoming PCAP directory in real time
- Detects when files are stable before processing
- Moves PCAPs into a working directory to prevent duplication
- Uses tshark for packet field extraction
- Applies custom rule logic defined in rules.yaml
- Generates structured alerts in alert.jsonl
- Archives processed PCAPs

This gave me full control over:
- detection behavior
- rule tuning
- alert structure


---

## Working Environment Design
I designed a structured processing pipeline:
- pcaps_in : incoming PCAPs
- pcaps_work : active processing
- pcaps_archive : processed storage
- ids_alerts : alert output
This separation ensures:
- no duplicate processing
- safe file handling
- clear workflow stages

---

## Custom Rule System
In this version, I created my own rule definitions instead of using generated ones.
Rules are defined in a YAML file and include:
- traffic thresholds
- filtering logic using tshark expressions
- grouping logic (per source IP, per port, etc.)
- severity levels
- alert metadata

---

## Automation
Automation remains fully handled through macOS LaunchAgents:
- PCAP capture and shipping
- Alert pulling
- Notification triggering
All processes run without manual interaction.

---

## Testing
System was tested using controlled traffic (authorized testing):
- Generated network activity 
- Verified:
    - PCAP capture
    - transfer to Pi
    - rule triggering
    - alert generation
    - alert retrieval
    - notification display
Example:
```json
{
  "ts": "2026-02-23T03:47:19.331937+00:00",
  "rule_id": "tcp_volume_spike",
  "severity": "medium",
  "src_ip": "<Test IP>",
  "count": 798,
  "threshold": 700
}
```

## Environment Helper Functions
To make my working environment faster and easier to use, I also created two helper functions: connect and send.
```bash
connect
```
The connect function is used for quick SSH connection between my Mac and Raspberry Pi. Instead of typing the full SSH command each time, I can use a short command to connect from one machine to the other.

Purpose:

- connect from Mac to Raspberry Pi faster
- reduce repeated typing
- make testing and troubleshooting easier
- support smoother back-and-forth workflow between devices

```bash
send
```
The send function is used to transfer files from one machine to another. Instead of manually typing long scp or rsync commands, I can send files with a simple command.

Purpose:

- sends files between Mac and Raspberry Pi
- move scripts, PCAPs, rules, and logs more easily
- improve development speed
- reduce mistakes from typing long file paths

Together, these functions improved my workflow by making the environment easier to control, test, and maintain.

## How to Run the System
### 1) Start PCAP capture on Mac
```bash
sudo tcpdump -i any -n -s 96 -w "$HOME/pcaps_out/cap_%Y%m%d_%H%M%S.pcap" -G 60 -W 
```

### 2) Start shipping PCAPs to Raspberry Pi
```bash 
launchctl kickstart -k gui/$(id -u)/com.example.shippcaps
```

### 3) Start the IDS analyzer on Raspberry Pi
```bash
cd ~/Desktop/IDS_Project
python3 ids_watch.py
```

### 4) Start pulling alerts back to Mac
```bash 
launchctl kickstart -k gui/$(id -u)/com.example.pullnotify
```

### 5) Check generated alerts
On Raspberry Pi:
```bash
tail -f ~/Desktop/IDS_Project/ids_alerts/alert.jsonl
```

On Mac:
```bash
tail -f ~/ids_alerts/alert.jsonl
```

### 6) Stop the system
Stop packet capture:
```bash
Ctrl + C
```
Unload Mac automation:
```bash
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.example.shippcaps.plist
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.example.pullnotify.plist
```
Stop analyzer:
```bash
Ctrl + C
```

## Roadmap
- Improve rule accuracy and reduce false positives
- Add more advanced detection logic
- Expand rule coverage (DNS, lateral movement, anomalies)
- Build visualization dashboard (Mac + iOS)
- Integrate with SIEM-like workflows
- Add statistical analysis and trend tracking
- Expand monitoring to include my iPhone
- Correlate alerts across Mac, Raspberry Pi, and iPhone
- Build mobile-aware detection rules
- Develop a unified alert dashboard for all devices

