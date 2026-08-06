# Security

## Overview

The SIEM Agent protects the integrity of the SIEM pipeline by authenticating incoming messages, preventing replay attacks, and rejecting invalid data before it reaches the Mini-SIEM.

---

## Security Features

- HMAC-SHA256 signature verification
- Replay attack protection
- Message integrity validation
- Secure forwarding to the Mini-SIEM

---

## Authentication

Every log and heartbeat message received from the Log Generator includes an HMAC-SHA256 signature.

The SIEM Agent recalculates the signature using the shared secret and compares it with the received signature.

```
Receive Message
        │
        ▼
Calculate HMAC
        │
        ▼
Compare Signatures
        │
   ┌────┴────┐
   │         │
 Match    No Match
   │         │
 Accept   Reject
```

---

## Shared Secret

The Log Generator and the SIEM Agent must use the same secret key.

Example:

```env
SECRET_KEY=your-shared-secret
```

If the keys do not match, the message is rejected.

---

## Replay Protection

Before processing a message, the SIEM Agent checks whether it has already been received.

Duplicate messages are discarded to prevent replay attacks and duplicate event processing.

---

## Message Validation

Each incoming message is validated before processing.

Validation includes:

- Required fields
- HMAC signature
- Replay protection
- JSON format

Only valid messages continue through the processing pipeline.

---

## Best Practices

- Use a strong, randomly generated secret key.
- Never commit secrets to source control.
- Store secrets in environment variables.
- Use HTTPS when communicating across untrusted networks.
- Rotate shared secrets periodically.

---

## Summary

The SIEM Agent ensures that only authentic, untampered, and non-duplicate messages are processed. These security controls provide a reliable foundation for secure log collection within the SIEM Project.