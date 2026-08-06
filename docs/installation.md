# Installation Guide

## Requirements

| Requirement | Version |
|------------|---------|
| Python | 3.10+ |
| Operating System | Windows, Linux, or macOS |
| Network | Access to the Log Generator and Mini-SIEM |

---

## Clone the Repository

```bash
git clone <repository-url>
cd siem-agent
```

---

## Create a Virtual Environment

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### Windows

```cmd
python -m venv venv
venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configure Environment Variables

Copy the example environment file.

### Linux/macOS

```bash
cp .env.example .env
```

### Windows

```cmd
copy .env.example .env
```

Open the `.env` file and update it as shown below.

```env
# Secret shared with the Log Generator
SECRET_KEY=your-shared-secret

# SIEM Agent
AGENT_HOST=0.0.0.0
AGENT_PORT=6000

# Mini-SIEM Endpoints
SIEM_LOG_ENDPOINT=http://127.0.0.1:5000/submit-log
SIEM_HEARTBEAT_ENDPOINT=http://127.0.0.1:5000/submit-heartbeat
```

---

## Configuration

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Shared HMAC secret used to verify messages from the Log Generator. |
| `AGENT_HOST` | Host address on which the SIEM Agent listens for incoming connections. |
| `AGENT_PORT` | Port on which the SIEM Agent listens (default: `6000`). |
| `SIEM_LOG_ENDPOINT` | Mini-SIEM endpoint that receives validated log events. |
| `SIEM_HEARTBEAT_ENDPOINT` | Mini-SIEM endpoint that receives heartbeat messages. |

---

## Run the SIEM Agent

```bash
python main.py
```

When started, the SIEM Agent will:

- Listen for logs and heartbeat messages.
- Verify HMAC signatures.
- Detect replay attacks.
- Normalize and parse events.
- Forward validated data to the Mini-SIEM.

---

## Verify the Installation

The installation is successful if:

- The SIEM Agent starts without errors.
- Log messages are received from the Log Generator.
- Heartbeat messages are received.
- Invalid signatures are rejected.
- Validated data is forwarded to the Mini-SIEM.

---

## Common Issues

| Issue | Solution |
|------|----------|
| Invalid HMAC signature | Ensure both the Log Generator and SIEM Agent use the same `SECRET_KEY`. |
| Unable to connect to the Mini-SIEM | Verify the `SIEM_LOG_ENDPOINT` and `SIEM_HEARTBEAT_ENDPOINT` values and ensure the Mini-SIEM is running. |
| No logs received | Confirm the Log Generator is running and configured to send data to the correct SIEM Agent address and port (`AGENT_HOST:AGENT_PORT`). |

---

## Next Steps

- **architecture.md** – Learn about the SIEM Agent architecture.
- **normalization.md** – Understand the log normalization process.
- **replay-protection.md** – Learn how replay attacks are prevented.
- **heartbeat-monitor.md** – Understand endpoint heartbeat monitoring.
- **security.md** – Review the SIEM Agent security features.