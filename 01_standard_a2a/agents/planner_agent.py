import json
import time
import uuid

import httpx
import psutil
from fastapi import Depends, FastAPI
from pydantic import BaseModel

from config import ACCESS_TOKEN, AGENTS, CERT_FILE, MAX_BOOKING_PRICE
from metrics.collector import append_metric, process_memory_mb
from security.auth import verify_bearer_token
from security.risk import classify_risk

app = FastAPI(title="Standard TLS + Bearer A2A Planner")

AUTH_HEADER = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
AUTH_BYTES = len("Authorization".encode()) + len(f"Bearer {ACCESS_TOKEN}".encode())


class TravelTask(BaseModel):
    origin: str = "ORD"
    destination: str = "JFK"
    date: str
    max_price: float = MAX_BOOKING_PRICE
    auto_book: bool = True


async def call_agent(task_id, destination, action, endpoint, payload):
    start_total = time.perf_counter()

    success = False
    response_bytes = 0
    request_ms = 0.0

    # Application bytes used for comparison with the other prototypes.
    # TLS record/handshake bytes are not included here.
    payload_bytes = len(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    request_bytes = payload_bytes + AUTH_BYTES

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            verify=str(CERT_FILE),
        ) as client:
            start_request = time.perf_counter()

            r = await client.post(
                AGENTS[destination]["url"] + endpoint,
                json=payload,
                headers=AUTH_HEADER,
            )

            request_ms = (time.perf_counter() - start_request) * 1000

            r.raise_for_status()
            response_bytes = len(r.content)
            success = True
            return r.json()

    finally:
        append_metric({
            "task_id": task_id,
            "source": "planner",
            "destination": destination,
            "action": action,
            "risk": classify_risk(action),

            "security_mode": "standard_tls_bearer",
            "transport_security": "TLS",
            "authentication": "BearerToken",

            # TLS cryptography is handled by Python/OpenSSL internally.
            # These fields intentionally remain uninstrumented.
            "kem_algorithm": "TLS-managed",
            "signature_algorithm": "TLS-managed",
            "keygen_ms": 0,
            "encap_or_exchange_ms": 0,
            "decap_or_exchange_ms": 0,
            "sign_ms": 0,
            "verify_ms": 0,
            "encrypt_ms": 0,
            "decrypt_ms": 0,

            "request_latency_ms": round(request_ms, 4),
            "total_call_latency_ms": round(
                (time.perf_counter() - start_total) * 1000, 4
            ),

            "bytes_sent": request_bytes,
            "bytes_received": response_bytes,
            "auth_bytes": AUTH_BYTES,

            "delegation_bytes": 0,
            "audit_enabled": False,

            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_mb": round(process_memory_mb(), 3),
            "success": success,
        })


@app.get("/health")
def health():
    return {"agent": "planner", "status": "ok", "tls": True}


@app.post("/task", dependencies=[Depends(verify_bearer_token)])
async def task(t: TravelTask):
    task_id = str(uuid.uuid4())

    flights = await call_agent(
        task_id,
        "flight",
        "search_flight",
        "/search",
        {
            "origin": t.origin,
            "destination": t.destination,
            "date": t.date,
        },
    )

    valid = [
        f for f in flights["flights"]
        if f["price"] <= t.max_price
    ]

    if not valid:
        return {
            "task_id": task_id,
            "status": "not_booked",
        }

    selected = min(valid, key=lambda x: x["price"])

    cal = await call_agent(
        task_id,
        "calendar",
        "check_calendar",
        "/check",
        {"date": t.date},
    )

    if not cal["available"]:
        return {
            "task_id": task_id,
            "status": "not_booked",
            "reason": "calendar",
        }

    if not t.auto_book:
        return {
            "task_id": task_id,
            "status": "ready_to_book",
            "flight": selected,
        }

    pay = await call_agent(
        task_id,
        "payment",
        "payment",
        "/pay",
        {
            "amount": selected["price"],
            "flight_id": selected["flight_id"],
        },
    )

    return {
        "task_id": task_id,
        "status": "booked",
        "flight": selected,
        "calendar": cal,
        "payment": pay,
    }
