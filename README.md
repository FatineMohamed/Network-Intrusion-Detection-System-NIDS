# 🛡️ Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System capable of detecting common network attacks through packet inspection and alerting. The project uses Scapy for packet capture, SQLite for alert storage, and Flask for a web-based monitoring dashboard.

## Features

- SYN Flood Detection
- UDP Flood Detection
- Port Scan Detection
- Real-Time Packet Monitoring
- Alert Storage with SQLite
- Web Dashboard with Flask
- Attack Simulation using Kali Linux
- Historical Alert Tracking

---

## Architecture

```text
Kali Linux Attacker
        │
        ▼
┌─────────────────┐
│   Scapy Sniffer │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Detection Engine│
│                 │
│ • SYN Flood     │
│ • UDP Flood     │
│ • Port Scan     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ SQLite Database │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Flask Dashboard │
└─────────────────┘
```

---

## Technologies Used

- Python
- Scapy
- Flask
- SQLite
- HTML/CSS
- Kali Linux
- Nmap
- Hping3

---

## Detection Logic

### SYN Flood Detection

Tracks incoming TCP SYN packets from each source IP.

An alert is generated when the number of SYN packets exceeds a defined threshold within a specified time window.

### UDP Flood Detection

Monitors incoming UDP packets and counts traffic per source IP.

An alert is generated when UDP traffic exceeds the configured threshold.

### Port Scan Detection

Tracks unique destination ports contacted by a source IP.

An alert is generated when a host attempts connections to multiple ports within a short period of time.

---

## Dashboard

The Flask dashboard displays:

- Alert ID
- Timestamp
- Source IP
- Attack Type
- Packet Count

Attack types are color-coded for easier analysis:

- 🔴 SYN Flood
- 🟠 UDP Flood
- 🟡 Port Scan

---

## Attack Simulation

### SYN Flood

```bash
sudo hping3 -S --flood -p 80 <target-ip>
```

### UDP Flood

```bash
sudo hping3 --udp --flood -p 80 <target-ip>
```

### Port Scan

```bash
nmap -Pn -p 1-100 <target-ip>
```

---

## Project Structure

```text
NIDS/
│
├── app.py
├── detector.py
├── database.py
├── config.py
├── requirements.txt
│
├── templates/
│   ├── dashboard.html
│   └── alerts.html
│
├── static/
│   └── style.css
│
└── README.md
```

---

## Sample Alerts

| Attack Type | Source IP | Count |
|------------|-----------|--------|
| SYN Flood | 192.168.32.132 | 100 |
| UDP Flood | 192.168.32.132 | 100 |
| Port Scan | 192.168.32.132 | 100 |

---

## Skills Demonstrated

- Network Security
- Packet Analysis
- Intrusion Detection
- Python Development
- Flask Web Development
- SQLite Database Management
- Linux Administration
- Security Monitoring
- Cybersecurity Lab Design

---

## Future Improvements

- Email Notifications
- Real-Time Dashboard Updates
- GeoIP Enrichment
- Threat Intelligence Integration
- Alert Severity Levels
- Export Alerts to CSV
- Docker Deployment

---

## Author

Mohamed Fatine

GitHub:
https://github.com/FatineMohamed
