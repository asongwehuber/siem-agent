# SIEM Agent

## Overview

The SIEM Agent is the intermediary component of the SIEM Project. It receives logs from multiple endpoints, verifies their authenticity, normalizes and parses the events, monitors endpoint heartbeats, and securely forwards validated data to the Mini-SIEM.

---

## Features

- Receive logs from multiple endpoints
- Verify HMAC-SHA256 signatures
- Prevent replay attacks
- Normalize logs into a common format
- Parse events from different log sources
- Monitor endpoint heartbeats
- Forward validated logs to the Mini-SIEM
- Modular parser architecture

---

## Architecture

```
Log Generator
      │
      ▼
+----------------+
|   SIEM Agent   |
+----------------+
│ Verify HMAC    │
│ Replay Check   │
│ Normalize Logs │
│ Parse Events   │
│ Heartbeats     │
└──────┬─────────┘
       │
       ▼
Mini-SIEM
```

---

## Project Structure

```
siem-agent/
│
├── database/
├── monitor/
├── normalization/
├── pipeline/
├── security/
├── services/
├── docs/
├── receiver.py
├── sender.py
├── main.py
└── config.py
```

---

## Documentation

| File | Description |
|------|-------------|
| installation.md | Installation and configuration |
| architecture.md | Internal architecture |
| normalization.md | Log normalization process |
| replay-protection.md | Replay attack prevention |
| heartbeat-monitor.md | Heartbeat monitoring |
| security.md | Authentication and integrity |

---

## Running

```bash
python main.py
```

The SIEM Agent starts listening for incoming log messages from the Log Generator.

---

## Processing Pipeline

```
Receive Log
      │
      ▼
Verify Signature
      │
      ▼
Replay Protection
      │
      ▼
Normalize
      │
      ▼
Parse
      │
      ▼
Forward to Mini-SIEM
```

---

## Security

The SIEM Agent authenticates every message using HMAC-SHA256 and rejects invalid or replayed messages before forwarding them.

---

## Related Components

- **Log Generator** – Generates endpoint logs.
- **SIEM Agent** – Validates and processes logs.
- **Mini-SIEM** – Performs detection, alerting, and visualization.

---

## License

MIT License.