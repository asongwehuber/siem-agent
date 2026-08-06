# Heartbeat Monitoring

## Overview

The SIEM Agent monitors heartbeat messages from connected endpoints to determine whether they are online or offline. Each heartbeat updates the endpoint's last known activity time.

---

## Purpose

Heartbeat monitoring enables the SIEM Agent to:

- Track endpoint availability
- Detect offline machines
- Monitor communication health
- Support availability alerts

---

## Workflow

```
Heartbeat Received
        │
        ▼
Verify Signature
        │
        ▼
Update Last Seen Time
        │
        ▼
Store Endpoint Status
        │
        ▼
Continue Monitoring
```

If a heartbeat is not received within the configured timeout, the endpoint is marked as offline.

---

## Heartbeat Message

Heartbeat messages use the same secure JSON format as log events.

Example:

```json
{
    "hostname": "linux-server-01",
    "generator_id": "generator-01",
    "message": "heartbeat",
    "timestamp": "2026-07-31T10:15:00Z",
    "signature": "HMAC_SHA256_SIGNATURE"
}
```

---

## Endpoint Status

| Status | Description |
|--------|-------------|
| Online | Heartbeats are being received. |
| Offline | No heartbeat received within the timeout period. |

---

## Benefits

- Detects unavailable endpoints
- Improves network visibility
- Supports reliable monitoring
- Integrates seamlessly with the Log Generator

---

## Summary

Heartbeat monitoring enables the SIEM Agent to continuously track endpoint availability by processing periodic heartbeat messages from the Log Generator. This helps maintain an accurate view of endpoint health and communication status.