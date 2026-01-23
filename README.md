# File Integrity & Authentication Log Security Monitor

A Python-based security monitoring tool that analyzes Linux authentication logs to detect suspicious activity such as brute-force attacks, account lockout risks, credential compromise, and abnormal login behavior.
Designed as a **blue-team / SOC-style detection engine** with risk scoring, alert deduplication, and **MITRE ATT&CK** mapping.

## Features
### Detection Capabilities

- Brute-force detection (X failures in Y minutes)
- Account lockout risk detection
- Successful login after failures (credential compromise)
- IP change between failures and success
- Time-window correlation
- Alert deduplication & cooldowns

## Risk Scoring Engine

- Aggregates multiple detections
- Assigns weighted risk scores
- Categorizes risk levels:
    - LOW
    - MEDIUM
    - HIGH
    - CRITICAL

### MITRE ATT&CK Mapping
Each alert is tagged with relevant MITRE techniques:
- T1110 – Brute Force
- T1110.001 – Password Guessing
- T1078 – Valid Accounts
- T1021 – Remote Services

## Output & Reporting
- Console alerts
- JSON export for SIEM ingestion
- Clean, structured event normalization

## Project Structure
```
file-integrity-monitor/
│
├── analyzer.py                # Main orchestration logic
├── logs/
│   └── auth.log               # Sample authentication logs
│
├── parser/
│   └── auth_parser.py         # Log parsing & normalization
│
├── detectors/
│   ├── brute_force.py
│   ├── account_lockout.py
│   ├── credential_compromise.py
│   └── ip_change.py
│
├── risk/
│   └── risk_engine.py         # Risk scoring logic
│
├── alerts/
│   └── alert_manager.py       # Deduplication & cooldowns
│
├── exporters/
│   └── json_exporter.py       # JSON output
│
├── output/
│   └── events.json
│
└── README.md
```
## Architecture Overview
### High-Level Flow
```
auth.log
   │
   ▼
Log Parser
   │
   ▼
Normalized Events
   │
   ▼
Detection Engines
   │
   ▼
Risk Scoring Engine
   │
   ▼
Alert Deduplication & Cooldowns
   │
   ├── Console Alerts
   └── JSON Export (SIEM-ready)
```

## Mermaid Architecture Diagram (GitHub-Rendered)
```
flowchart TD
    A[auth.log] --> B[Auth Log Parser]
    B --> C[Normalized Events]

    C --> D1[Brute Force Detector]
    C --> D2[Account Lockout Detector]
    C --> D3[Credential Compromise Detector]
    C --> D4[IP Change Detector]

    D1 --> E[Risk Scoring Engine]
    D2 --> E
    D3 --> E
    D4 --> E

    E --> F[Alert Deduplication & Cooldowns]

    F --> G[Console Alerts]
    F --> H[JSON Export]
```

## Sample Output
=== RISK SUMMARY ===
Entity: 192.168.1.50
Risk Score: 30
Risk Level: LOW
Detections:
 - Brute Force Attack (+30)
----------------------------------------
Entity: admin
Risk Score: 180
Risk Level: CRITICAL
Detections:
 - Account Lockout Risk (+40)
 - Possible Credential Compromise (+60)
 - Credential Compromise (IP Change) (+80)
----------------------------------------

## Technologies Used

- Python 3
- Regular Expressions (re)
- Datetime with timezone awareness
- JSON for structured export
- MITRE ATT&CK Framework

## Learning Objectives Demonstrated
- Log parsing & normalization
- Detection engineering fundamentals
- Time-based correlation
- Risk-based alerting
- SOC-style alert hygiene (deduplication & cooldowns)
- Security framework mapping (MITRE ATT&CK)

## Future Enhancements
- GeoIP enrichment
- Threat intelligence feeds
- Dashboard visualization
- Real-time log streaming

🧑‍💻 Author

Edison Encinas
Cybersecurity Enthusiast | Blue Team 
(Project built for learning, portfolio, and skill demonstration purposes)