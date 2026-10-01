import json
import time
import uuid

import httpx
import psutil
from fastapi import FastAPI
from pydantic import BaseModel

from config import AGENTS, MAX_BOOKING_PRICE
from metrics.collector import append_metric, process_memory_mb
from security.risk import classify_risk
from security.classical import seal_for_target, b64d


app = FastAPI(title="Classical Planner")


class TravelTask(BaseModel):
    origin: str = "ORD"
    destination: str = "JFK"
    date: str
    max_price: float = MAX_BOOKING_PRICE
    auto_book: bool = True


def decoded_size(value):
    """
    Return the raw byte size of a Base64-encoded value.

    If the value is missing or cannot be decoded,
    return 0 instead of breaking the experiment.
    """
    if not value:
        return 0

    try:
        return len(b64d(value))
    except Exception:
        return 0


async def call_agent(
    task_id,
    destination,
    action,
    endpoint,
    payload,
):
    total_start = time.perf_counter()

    success = False
    response_bytes = 0

    m = {
        "keygen_ms": 0,
        "encap_ms": 0,
        "decap_ms": 0,
        "sign_ms": 0,
        "verify_ms": 0,
        "encrypt_ms": 0,
        "decrypt_ms": 0,
        "request_ms": 0,
        "request_bytes": 0,

        # New size metrics
        "public_key_bytes": 0,
        "kem_ciphertext_bytes": 0,
        "signature_bytes": 0,
        "encrypted_payload_bytes": 0,
    }

    try:
        async with httpx.AsyncClient(
            timeout=20.0
        ) as client:

            # =================================================
            # Get target X25519 public key
            # =================================================

            key_r = await client.get(
                AGENTS[destination]["url"]
                + "/crypto/public"
            )

            key_r.raise_for_status()

            key_info = key_r.json()

            target_public_key = b64d(
                key_info["public_key"]
            )

            # Raw X25519 public key size
            m["public_key_bytes"] = len(
                target_public_key
            )

            # =================================================
            # Encrypt and sign request
            # =================================================

            envelope, c = seal_for_target(
                action,
                payload,
                target_public_key,
            )

            # =================================================
            # Crypto-object sizes
            # =================================================

            # X25519 is a Diffie-Hellman key exchange,
            # not a KEM, so there is no KEM ciphertext.
            m["kem_ciphertext_bytes"] = 0

            # Try the expected envelope field names.
            # These are raw sizes after Base64 decoding.
            m["signature_bytes"] = decoded_size(
                envelope.get("signature")
            )

            m["encrypted_payload_bytes"] = (
                decoded_size(
                    envelope.get("ciphertext")
                )
            )

            # If your classical.py uses short field names,
            # support those as fallbacks too.
            if m["signature_bytes"] == 0:
                m["signature_bytes"] = decoded_size(
                    envelope.get("sig")
                )

            if m["encrypted_payload_bytes"] == 0:
                m["encrypted_payload_bytes"] = (
                    decoded_size(
                        envelope.get("ct")
                    )
                )

            # =================================================
            # Serialized request size
            # =================================================

            request_bytes = len(
                json.dumps(
                    envelope,
                    separators=(",", ":"),
                ).encode("utf-8")
            )

            # =================================================
            # Send secure request
            # =================================================

            req_start = time.perf_counter()

            r = await client.post(
                AGENTS[destination]["url"]
                + endpoint,
                json=envelope,
            )

            request_ms = (
                time.perf_counter()
                - req_start
            ) * 1000

            r.raise_for_status()

            response_bytes = len(
                r.content
            )

            result = r.json()

            # =================================================
            # Server-side crypto measurements
            # =================================================

            server = result.pop(
                "crypto_metrics",
                {}
            )

            success = True

            m.update({
                "keygen_ms":
                    c.get("keygen_ms", 0),

                "encap_ms":
                    c.get("exchange_ms", 0),

                "decap_ms":
                    server.get(
                        "decap_or_exchange_ms",
                        0,
                    ),

                "sign_ms":
                    c.get("sign_ms", 0),

                "verify_ms":
                    server.get(
                        "verify_ms",
                        0,
                    ),

                "encrypt_ms":
                    c.get("encrypt_ms", 0),

                "decrypt_ms":
                    server.get(
                        "decrypt_ms",
                        0,
                    ),

                "request_ms":
                    request_ms,

                "request_bytes":
                    request_bytes,
            })

            return result

    finally:

        append_metric({
            "task_id":
                task_id,

            "source":
                "planner",

            "destination":
                destination,

            "action":
                action,

            "risk":
                classify_risk(action),

            "security_mode":
                "classical",

            "kem_algorithm":
                "X25519",

            "signature_algorithm":
                "Ed25519",

            # =================================================
            # Crypto timing
            # =================================================

            "keygen_ms":
                round(
                    m.get("keygen_ms", 0),
                    6,
                ),

            "encap_or_exchange_ms":
                round(
                    m.get("encap_ms", 0),
                    6,
                ),

            "decap_or_exchange_ms":
                round(
                    m.get("decap_ms", 0),
                    6,
                ),

            "sign_ms":
                round(
                    m.get("sign_ms", 0),
                    6,
                ),

            "verify_ms":
                round(
                    m.get("verify_ms", 0),
                    6,
                ),

            "encrypt_ms":
                round(
                    m.get("encrypt_ms", 0),
                    6,
                ),

            "decrypt_ms":
                round(
                    m.get("decrypt_ms", 0),
                    6,
                ),

            # =================================================
            # NEW crypto-object-size metrics
            # =================================================

            "public_key_bytes":
                m.get(
                    "public_key_bytes",
                    0,
                ),

            "kem_ciphertext_bytes":
                m.get(
                    "kem_ciphertext_bytes",
                    0,
                ),

            "signature_bytes":
                m.get(
                    "signature_bytes",
                    0,
                ),

            "encrypted_payload_bytes":
                m.get(
                    "encrypted_payload_bytes",
                    0,
                ),

            # =================================================
            # Request measurements
            # =================================================

            "request_latency_ms":
                round(
                    m.get("request_ms", 0),
                    4,
                ),

            "total_call_latency_ms":
                round(
                    (
                        time.perf_counter()
                        - total_start
                    )
                    * 1000,
                    4,
                ),

            "bytes_sent":
                m.get(
                    "request_bytes",
                    0,
                ),

            "bytes_received":
                response_bytes,

            "delegation_bytes":
                0,

            "audit_enabled":
                False,

            "cpu_percent":
                psutil.cpu_percent(
                    interval=None
                ),

            "memory_mb":
                round(
                    process_memory_mb(),
                    3,
                ),

            "success":
                success,
        })


@app.post("/task")
async def task(t: TravelTask):

    task_id = str(
        uuid.uuid4()
    )

    # =========================================================
    # LOW-risk flight search
    # =========================================================

    flights = await call_agent(
        task_id,
        "flight",
        "search_flight",
        "/search",
        {
            "origin":
                t.origin,

            "destination":
                t.destination,

            "date":
                t.date,
        },
    )

    valid = [
        f
        for f in flights["flights"]
        if f["price"] <= t.max_price
    ]

    if not valid:
        return {
            "task_id": task_id,
            "status": "not_booked",
        }

    selected = min(
        valid,
        key=lambda x: x["price"],
    )

    # =========================================================
    # MEDIUM-risk calendar request
    # =========================================================

    cal = await call_agent(
        task_id,
        "calendar",
        "check_calendar",
        "/check",
        {
            "date":
                t.date
        },
    )

    if not cal["available"]:
        return {
            "task_id": task_id,
            "status": "not_booked",
            "reason": "calendar",
        }

    if not t.auto_book:
        return {
            "task_id":
                task_id,

            "status":
                "ready_to_book",

            "flight":
                selected,
        }

    # =========================================================
    # CRITICAL-risk payment
    # =========================================================

    pay = await call_agent(
        task_id,
        "payment",
        "payment",
        "/pay",
        {
            "amount":
                selected["price"],

            "flight_id":
                selected["flight_id"],
        },
    )

    return {
        "task_id":
            task_id,

        "status":
            "booked",

        "flight":
            selected,

        "calendar":
            cal,

        "payment":
            pay,
    }