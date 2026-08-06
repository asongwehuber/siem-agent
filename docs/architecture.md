# System Architecture

## Overview

The SIEM Agent acts as the secure gateway between the Log Generator and the Mini-SIEM. It validates incoming messages, processes them, and forwards trusted events for analysis.

---

## Architecture

```
                +----------------+
                | Log Generator  |
                +-------+--------+
                        |
                        | Logs & Heartbeats
                        |
                        ▼
              +----------------------+
              |      SIEM Agent      |
              +----------------------+
              | Verify HMAC          |
              | Replay Protection    |
              | Normalize Logs       |
              | Parse Events         |
              | Monitor Heartbeats   |
              +----------+-----------+
                         |
                         ▼
                 +---------------+
                 |   Mini-SIEM   |
                 +---------------+
```

---

## Processing Flow

Every incoming message follows the same pipeline.

```
Receive Message
        │
        ▼
Verify Signature
        │
        ▼
Replay Check
        │
        ▼
Normalize
        │
        ▼
Parse Event
        │
        ▼
Forward to Mini-SIEM
```

---

## Project Structure

| Directory | Purpose |
|----------|---------|
| `database/` | Replay protection and local storage |
| `monitor/` | Heartbeat monitoring |
| `normalization/` | Log normalization and parsing |
| `pipeline/` | Processing workflow |
| `security/` | HMAC verification |
| `services/` | Background services |

---

## Core Components

| Component | Responsibility |
|-----------|----------------|
| Receiver | Accepts incoming logs |
| Verifier | Validates HMAC signatures |
| Replay Protection | Detects duplicate messages |
| Normalizer | Standardizes log format |
| Parser | Identifies event types |
| Sender | Forwards validated logs |
| Heartbeat Monitor | Tracks endpoint availability |

---

## Design Principles

- Modular architecture
- Secure message processing
- Vendor-independent log format
- Easy integration with new log sources
- Fault isolation between components

---

## Integration

The SIEM Agent is the central processing layer of the project.

```
Log Generator
      │
      ▼
SIEM Agent
      │
      ▼
Mini-SIEM
```

---

## Summary

The SIEM Agent validates, processes, and forwards log data while ensuring message integrity, preventing replay attacks, and monitoring endpoint availability. Its modular architecture makes it easy to maintain and extend.