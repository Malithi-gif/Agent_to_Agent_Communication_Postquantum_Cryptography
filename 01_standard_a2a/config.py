import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CERT_DIR = ROOT / "certs"
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"

AGENTS = {
    "planner":  {"url": "https://127.0.0.1:8001", "port": 8001},
    "flight":   {"url": "https://127.0.0.1:8002", "port": 8002},
    "calendar": {"url": "https://127.0.0.1:8013", "port": 8013},
    "payment":  {"url": "https://127.0.0.1:8004", "port": 8004},
}

MAX_BOOKING_PRICE = 500.0

# Research-prototype bearer token. You may override it before running:
# Windows CMD:
#   set A2A_BEARER_TOKEN=my-secret-token
# PowerShell:
#   $env:A2A_BEARER_TOKEN="my-secret-token"
ACCESS_TOKEN = os.getenv("A2A_BEARER_TOKEN", "a2a-research-token-2026")
