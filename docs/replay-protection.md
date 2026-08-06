# Replay Protection

## Overview

Replay protection prevents attackers from resending previously captured messages to the SIEM Agent. Every incoming message is checked to ensure it has not already been processed.

---

## Why It Matters

Without replay protection, an attacker could repeatedly submit a valid message to:

- Generate duplicate alerts
- Corrupt security data
- Overload the SIEM with repeated events

---

## How It Works

Every incoming message passes through the replay protection module before it is processed.

```
Receive Message
        │
        ▼
Extract Metadata
        │
        ▼
Check Replay Database
        │
        ▼
Already Processed?
     ┌───────┴────────┐
     │                │
    Yes              No
     │                │
 Reject Message   Continue Processing
```

---

## Validation

The SIEM Agent uses message metadata to determine whether a message has already been received.

Typical validation includes:

- Event ID
- Generator ID
- Timestamp

If the message is identified as a duplicate, it is rejected before normalization and forwarding.

---

## Benefits

- Prevents duplicate event processing
- Protects against replay attacks
- Improves data integrity
- Reduces false alerts

---

## Summary

Replay protection ensures that each event is processed only once, improving the reliability and security of the SIEM pipeline.