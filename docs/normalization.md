# Log Normalization

## Overview

Log normalization converts logs from different sources into a common format before they are forwarded to the Mini-SIEM. This allows the detection engine to process events consistently, regardless of their origin.

---

## Why Normalize?

Different systems produce logs in different formats. Normalization ensures that:

- Events have a consistent structure.
- Detection rules work across all log sources.
- New log sources can be added with minimal changes.

---

## Supported Sources

| Source | Status |
|--------|--------|
| Linux | ✔ Supported |
| Windows | ✔ Supported |
| Apache | ✔ Supported |
| Firewall | ✔ Supported |
| MySQL | ✔ Supported |

---

## Normalization Process

```
Receive Log
      │
      ▼
Identify Source
      │
      ▼
Parse Event
      │
      ▼
Extract Fields
      │
      ▼
Create Standard Format
      │
      ▼
Forward to Mini-SIEM
```

---

## Standard Fields

Every normalized event contains the following fields.

| Field | Description |
|-------|-------------|
| `timestamp` | Event time |
| `hostname` | Source machine |
| `generator_id` | Log Generator identifier |
| `event_type` | Normalized event type |
| `message` | Original event message |
| `source_ip` | Source IP address (when available) |
| `severity` | Event severity |
| `signature` | HMAC signature |

---

## Example

### Incoming Log

```json
{
    "hostname": "windows-pc",
    "message": "Successful logon",
    "event_id": 4624
}
```

### Normalized Log

```json
{
    "hostname": "windows-pc",
    "event_type": "successful_login",
    "severity": "LOW",
    "message": "Successful logon"
}
```

---

## Parser Architecture

Each log source has its own parser.

```
normalization/
└── parsers/
    ├── linux.py
    ├── windows.py
    ├── apache.py
    ├── firewall.py
    └── mysql.py
```

This modular design makes it easy to support additional log sources.

---

## Summary

Normalization provides a common event format for all supported log sources, allowing the Mini-SIEM to analyze, correlate, and detect threats without needing source-specific logic.