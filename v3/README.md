# IDS Project v3

This README documents version 3 of my lightweight IDS/SIEM and firewall project built with a Raspberry Pi security gateway.

In version 2, the project focused on building a custom Python IDS analyzer, processing PCAPs, creating my own YAML-based detection rules, and generating structured alerts.

In version 3, I expanded the project into a more complete security monitoring system. The Raspberry Pi now acts as a small network gateway that can create its own Wi-Fi network, route device traffic, capture packets, analyze traffic with IDS rules, show alerts in a web dashboard, create rules from the dashboard, and store cleaned metadata in a SQLite-based mini-SIEM.

All IP addresses, usernames, hostnames, MAC addresses, SSIDs, and personal paths are anonymized or generalized.

---

## What’s New in v3

- Converted the Raspberry Pi into a Wi-Fi security gateway
- Created a Pi-hosted Wi-Fi network for monitored devices
- Added automated PCAP movement from capture folder to IDS input
- Improved IDS workflow with systemd services and timers
- Built a FastAPI dashboard for alerts and rule creation
- Added IDS rule creation directly from the dashboard
- Added basic firewall rule creation from the dashboard
- Generated firewall rules safely instead of allowing raw shell commands
- Added a SQLite-based mini-SIEM
- Extracted metadata from archived PCAPs into the SIEM database
- Stored flows, DNS queries, devices, security events, and processed PCAP records
- Added automatic PCAP cleanup after successful SIEM import
- Added Tailscale access for private dashboard access
- Improved the overall workflow from packet capture to long-term metadata storage

---

## Architecture Overview

```text
Client Devices --> Raspberry Pi Wi-Fi Network --> Raspberry Pi Gateway --> Packet Capture --> IDS Analyzer --> Alerts and Dashboard --> SIEM Metadata Database
```

The Raspberry Pi now works as:
- Wi-Fi access point
- DHCP/DNS gateway
- Traffic capture point
- IDS sensor
- Alert generator
- Dashboard server
- Basic firewall controller
- Mini-SIEM metadata collector

---

## Main Components

### Raspberry Pi Gateway

The Raspberry Pi creates a dedicated Wi-Fi network for monitored devices.

Core services:
- hostapd for Wi-Fi access point mode
- dnsmasq for DHCP/DNS
- Linux routing for traffic forwarding
- tcpdump for packet capture
- iptables for routing and basic firewall control

The goal is to route device traffic through the Pi so the traffic can be captured, analyzed, and monitored.

---

## PCAP Capture Workflow

Traffic is captured from the Pi Wi-Fi interface using tcpdump.

The capture process creates rotating PCAP files.

```text
Wi-Fi traffic --> tcpdump --> pcaps_capture/
```
A separate mover script moves only completed PCAPs into the IDS input folder.

```text
pcaps_capture/ --> move-completed-pcaps.sh --> pcaps_in/
```
This prevents the IDS from analyzing PCAP files while they are still being written.

---

## IDS Processing Workflow

The IDS watcher monitors the incoming PCAP folder.

```text
pcaps_in/ --> ids_watch_v3.py --> rules_v3.yaml --> alert.jsonl --> pcaps_archive/
```
The IDS analyzer:
- Watches for new PCAP files
- Uses tshark to extract packet fields
- Applies custom YAML-based detection rules
- Generates structured JSON alerts
- Moves processed PCAPs to archive
- Writes debug logs for troubleshooting

---

## Custom IDS Rule System

Rules are stored in: rules_v3.yaml

The rule system supports:
- Rule ID
- Rule name
- Rule type
- Severity
- Enabled/disabled status
- Tshark display filter
- Threshold
- Time window
- Cooldown period
- Source scope
- Trusted device multiplier
- Unique destination IP threshold
- Unique destination port threshold
- Alert message

Supported rule types include:
- dns_domain
- count_by_src
- count_by_src_dstport

This makes the IDS flexible and easier to tune.

--- 

## Detection Coverage

The IDS can detect behaviors such as:
- SSH scanning
- RDP scanning
- SMB scanning
- Telnet probing
- Docker API probing
- ADB probing
- Router/admin page probing
- Internal port scanning
- External sensitive-port scanning
- SYN spikes
- ICMP spikes
- Dynamic DNS lookups
- Tunneling or remote-access domain lookups
- DNS failure spikes
- Large outbound traffic
- TCP reset spikes
- Unknown device activity

--- 

## Trusted Device Logic

Trusted devices can be handled with different thresholds.

This helps reduce false positives from normal activity on known devices.

Idea:
trusted device = monitored with more tolerant thresholds
unknown device = monitored more aggressively

This was useful because normal behavior such as uploads, sync traffic, SSH, or testing can otherwise trigger noisy alerts.

---

## Alert Output

Alerts are written in JSON Lines format: ids_alerts/alert.jsonl

Alert structure:
```json
{
  "ts": "2026-01-01T00:00:00+00:00",
  "rule_id": "example_rule",
  "rule_name": "Example Rule",
  "severity": "medium",
  "message": "Example alert message.",
  "src_ip": "<client_ip>",
  "count": 100,
  "threshold": 50,
  "pcap": "example.pcap"
}
```

---

## Dashboard
Version 3 adds a FastAPI-based web dashboard.

The dashboard includes:
- Alert overview
- High / medium / low alert counts
- Latest alert display
- Alert table
- Top source IPs
- Top rules
- Selected alert details
- Debug log view
- IDS rule creation
- Basic firewall rule creation
- SIEM metadata view

Dashboard sections:
- Alerts
- Create Rule
- SIEM

The dashboard runs on the Raspberry Pi and can be accessed from trusted/private network paths.

---

## IDS Rule Creation from Dashboard
The dashboard can create IDS rules through a form.

The user fills in fields such as:
- Rule ID
- Name
- Type
- Severity
- Filter
- Threshold
- Window seconds
- Cooldown seconds
- Source scope
- Trusted device multiplier
- Message
- Enabled status

The backend validates the input and appends the rule to: rules_v3.yaml

This allows new IDS logic to be added without manually editing the YAML file every time.

---

## Basic Firewall Rule Creation
Version 3 also adds basic firewall rule creation from the dashboard.

The dashboard does not accept raw shell commands. Instead, it accepts safe form fields and generates controlled iptables rules.

Firewall rule fields include:
- Rule ID
- Name
- Chain
- Action
- Protocol
- Input interface
- Output interface
- Source IP
- Source MAC
- Destination port
- Message
- Enabled status

The workflow is:
```text
Dashboard form --> Validate input --> Save rule --> Generate firewall script --> Apply firewall service
```
This helped me understand firewall rule order, especially the difference between appending a rule and inserting a rule before broader allow rules.

---

## Mini-SIEM
Version 3 adds a SQLite-based mini-SIEM.

The SIEM database stores cleaned metadata instead of keeping raw PCAP files.
Database: siem/siem.db

Tables include:
- security_events
- network_flows
- dns_queries
- devices
- processed_pcaps

This allows the system to keep useful searchable security history without filling storage with raw PCAPs.

---

## SIEM Metadata Workflow

Archived PCAPs are processed into metadata.
```text
pcaps_archive/ --> pcap_to_siem.py --> siem.db --> delete processed PCAP
```

The SIEM collector extracts:
- IDS alerts
- Firewall events
- Network flows
- DNS queries
- Device information
- Processed PCAP records

After a PCAP is successfully imported into the database, it can be deleted to save storage.

---

## Automation
The project uses systemd services and timers for automation.

Main services/timers:
- move-pcaps.timer
- ids-watch.service
- ids-dashboard.service
- siem-ingest.timer
- siem-ingest.service

Their purpose:
- Move completed PCAPs
- Run the IDS watcher
- Run the dashboard
- Import archived PCAPs into the SIEM database
- Delete processed PCAPs after successful import

This makes the pipeline more reliable and closer to a real security monitoring system.

---

## Tailscale / Private Access

The dashboard can be accessed through a private network path using Tailscale.

This allows dashboard access without exposing the service publicly to the internet.

The goal is:
```text
Trusted device --> Private tunnel --> Raspberry Pi dashboard
```

---

## Current Workflow

The current version works like this:

1. Raspberry Pi creates Wi-Fi network
2. Client devices connect through the Pi
3. tcpdump captures traffic
4. Completed PCAPs move into IDS input folder
5. IDS watcher analyzes PCAPs
6. Alerts are written to alert.jsonl
7. Dashboard displays alerts
8. Dashboard can create IDS rules
9. Dashboard can create basic firewall rules
10. Processed PCAPs move to archive
11. SIEM ingest extracts metadata
12. Metadata is stored in SQLite
13. Successfully processed PCAPs are deleted
14. SIEM tab displays searchable metadata

---

## Running

### Start the main services:
```bash
sudo systemctl restart ids-firewall.service
sudo systemctl restart move-pcaps.timer
sudo systemctl restart ids-watch.service
sudo systemctl restart siem-ingest.timer
sudo systemctl restart ids-dashboard.service
```

### Start packet capture:
```bash
sudo tcpdump -i <wifi_interface> -n -s 96 -w /path/to/project/pcaps_capture/cap_%Y%m%d_%H%M%S.pcap -G 60
```

### Force one PCAP move:
```bash
sudo systemctl start move-pcaps.service
```

### Force one SIEM ingest:
```bash
sudo systemctl start siem-ingest.service
```

### Check alerts:
```bash
tail -f /path/to/project/ids_alerts/alert.jsonl
```

### Check SIEM database:
```bash
sqlite3 /path/to/project/siem/siem.db ".tables"
```

---

## What I Learned

This version helped me understand the full security monitoring pipeline:

- Linux networking
- Wi-Fi access point setup
- Packet capture
- PCAP handling
- Detection engineering
- Rule tuning
- Alert generation
- Dashboard development
- SIEM metadata design
- SQLite storage
- Systemd automation
- Firewall rule logic
- Storage management
- Troubleshooting services and timers

The biggest lesson was that building an IDS/SIEM from scratch is not only about writing detection rules. It also requires reliable file handling, automation, logging, storage control, rule validation, and a dashboard that makes alerts understandable.

---

## Roadmap

### Next improvements:
Improve firewall alerting with LOG rules and a firewall log watcher
- Add stronger unknown-device detection
- Add better device identity mapping
- Add more SIEM search filters
- Add timeline view for alerts and flows
- Add better dashboard controls for enabling/disabling rules
- Add PCAP retention policy configuration
- Continue reducing false positives

---

## Project Status

Version 3 is a working personal IDS/SIEM gateway prototype.

It is not a production security product, but it is a hands-on project for learning cybersecurity, Linux networking, detection engineering, firewalling, packet analysis, automation, and SIEM design.
