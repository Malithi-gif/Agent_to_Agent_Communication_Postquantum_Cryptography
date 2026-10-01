# B1 Standard Secure A2A-Style Baseline

This version upgrades the original plain-HTTP baseline to:

- HTTPS/TLS for Planner, Flight, Calendar, and Payment services
- Bearer-token authentication on task/action endpoints
- Local certificate verification (no `verify=False`)
- The same travel workflow and risk labels
- Metrics saved to `metrics/results_standard_tls.csv`

Important terminology:

This is a **TLS + bearer-token authenticated A2A-style research baseline**.
A static bearer token is not a complete OAuth 2.0 deployment, and this code is
not an implementation of the full official A2A protocol specification.

## Run

### 1. Install packages

```bash
python -m pip install -r requirements.txt
```

### 2. Clear old measurements

```bash
python reset_results.py
```

### 3. Start all four services

```bash
python run_all.py
```

The script generates a local self-signed certificate on first run and starts:

- Planner:  https://127.0.0.1:8001
- Flight:   https://127.0.0.1:8002
- Calendar: https://127.0.0.1:8013
- Payment:  https://127.0.0.1:8004

### 4. In a second terminal

```bash
python test_task.py
```

### 5. Results

```text
metrics/results_standard_tls.csv
```

## Optional token override

Windows CMD:

```cmd
set A2A_BEARER_TOKEN=my-secret-token
```

PowerShell:

```powershell
$env:A2A_BEARER_TOKEN="my-secret-token"
```

Use the same environment variable in both terminals.

## Metric interpretation

`request_latency_ms` and `total_call_latency_ms` include TLS transport time.

The per-primitive fields (`keygen_ms`, `sign_ms`, etc.) remain `0` because
TLS cryptographic primitives are handled internally by the TLS/OpenSSL stack
and are not separately instrumented in this baseline.

`bytes_sent` is an application-level byte estimate:
JSON payload + Authorization header value/name. It does **not** include all
TLS record/handshake bytes. For a paper claiming total network traffic,
use packet capture or socket-level byte accounting consistently for all four
systems.
